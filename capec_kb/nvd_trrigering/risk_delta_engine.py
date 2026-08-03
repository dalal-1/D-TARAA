from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent

from cve_heavens_mapper_v2 import CveSignal, map_cve_to_heavens_signal
from feasibility_updater import UpdatedFeasibilityRecord, update_feasibility_record  # v2.0.0
from risk_recomputer import UpdatedRiskRecord, recompute_risk
from dtara_orchestrator import DtaraResult

logger = logging.getLogger(__name__)


@dataclass
class ThreatRiskDelta:
    threat_id:                   str
    feasibility_id:              str
    feasibility_rating_baseline: str
    feasibility_rating_updated:  str
    feasibility_changed:         bool
    a_norm_max_baseline:         float
    a_norm_max_updated:          float
    risk_records:                list[UpdatedRiskRecord]
    paths_changed:               int
    paths_total:                 int
    updated_feasibility:         UpdatedFeasibilityRecord


@dataclass
class RiskDeltaResult:
    cve_id:              str
    affected_ecus:       list[str]
    affected_technology: str
    signal:              CveSignal
    threat_deltas:       list[ThreatRiskDelta]
    threats_total:       int
    threats_feasibility_changed: int
    threats_risk_escalated:      int
    max_risk_delta:      int
    timestamp:           str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _build_feasibility_index(feasibility_records: list[dict]) -> dict[str, dict]:
    """Index by the record's own threat scenario (see risk.py for rationale)."""
    index: dict[str, dict] = {}
    for r in feasibility_records:
        tid = r.get("threat_id", "")
        if not tid:
            continue
        covered = r.get("covered_threat_ids") or [tid]
        if len(covered) > 1:
            raise ValueError(
                f"Feasibility record {r.get('feasibility_id', '?')} covers "
                f"{len(covered)} threat scenarios (pre-v1.5.0 artefact). "
                f"Regenerate attack_feasibility.json before reassessment."
            )
        index[tid] = r
    return index


def _build_risk_index(risk_records: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for r in risk_records:
        tid = r["threat_id"]
        index.setdefault(tid, []).append(r)
    return index


def _build_path_index(attack_paths: list[dict]) -> dict[str, dict]:
    return {p["path_id"]: p for p in attack_paths}


def _resolve_affected_ecu(
    feasibility_record: dict,
    path_index:         dict[str, dict],
    impacted_ecu_set:   set[str],
) -> str:
    for pr in feasibility_record.get("per_path_ratings", []):
        path = path_index.get(pr["path_id"])
        if path:
            target = path.get("target_ecu", "")
            if target in impacted_ecu_set:
                return target
    return next(iter(impacted_ecu_set), "")


def run_risk_delta(
    dtara_result:        DtaraResult,
    cve_enriched:        dict,
    feasibility_records: list[dict],
    risk_records:        list[dict],
    attack_paths:        list[dict],
) -> RiskDeltaResult:
    signal = map_cve_to_heavens_signal(cve_enriched)
    logger.info("[delta] CVE signal: AV=%s AC=%s PR=%s UI=%s -> access_means=%d "
                "exposure_time=%d WoO=%d (SE/KoIC/Eq not revised: no CVSS base "
                "metric measures them)",
                signal.cvss_av, signal.cvss_ac, signal.cvss_pr, signal.cvss_ui,
                signal.access_means, signal.exposure_time, signal.woo_value)

    impacted_threat_ids  = {t["threat_id"] for t in dtara_result.impacted_threats}
    impacted_ecu_set     = set(dtara_result.impacted_ecus)
    matched_technologies = dtara_result.matched_technologies

    feasibility_index = _build_feasibility_index(feasibility_records)
    risk_index        = _build_risk_index(risk_records)
    path_index        = _build_path_index(attack_paths)

    threat_deltas: list[ThreatRiskDelta] = []

    for threat_id in sorted(impacted_threat_ids):
        feasibility_record = feasibility_index.get(threat_id)
        if feasibility_record is None:
            logger.warning("[delta] No feasibility record for threat %s — skipping", threat_id)
            continue

        affected_ecu = _resolve_affected_ecu(feasibility_record, path_index, impacted_ecu_set)

        updated_feasibility = update_feasibility_record(
            feasibility_record   = feasibility_record,
            signal               = signal,
            path_index           = path_index,
            affected_ecu         = affected_ecu,
            matched_technologies = matched_technologies,
        )

        threat_risk_records = risk_index.get(threat_id, [])
        updated_risk_records: list[UpdatedRiskRecord] = []
        for rr in threat_risk_records:
            updated_rr = recompute_risk(rr, updated_feasibility)
            updated_risk_records.append(updated_rr)

        paths_changed = sum(1 for p in updated_feasibility.updated_path_ratings if p.changed)

        threat_deltas.append(ThreatRiskDelta(
            threat_id                   = threat_id,
            feasibility_id              = updated_feasibility.feasibility_id,
            feasibility_rating_baseline = updated_feasibility.feasibility_rating_baseline,
            feasibility_rating_updated  = updated_feasibility.feasibility_rating_updated,
            feasibility_changed         = updated_feasibility.feasibility_changed,
            a_norm_max_baseline         = updated_feasibility.a_norm_max_baseline,
            a_norm_max_updated          = updated_feasibility.a_norm_max_updated,
            risk_records                = updated_risk_records,
            paths_changed               = paths_changed,
            paths_total                 = len(updated_feasibility.updated_path_ratings),
            updated_feasibility         = updated_feasibility,
        ))

    threats_feasibility_changed = sum(1 for td in threat_deltas if td.feasibility_changed)
    threats_risk_escalated      = sum(
        1 for td in threat_deltas if any(rr.risk_escalated for rr in td.risk_records)
    )
    max_risk_delta = max(
        (rr.risk_delta for td in threat_deltas for rr in td.risk_records),
        default=0,
    )

    return RiskDeltaResult(
        cve_id               = signal.cve_id,
        affected_ecus        = sorted(impacted_ecu_set),
        affected_technology  = ", ".join(matched_technologies),
        signal               = signal,
        threat_deltas        = threat_deltas,
        threats_total        = len(threat_deltas),
        threats_feasibility_changed = threats_feasibility_changed,
        threats_risk_escalated      = threats_risk_escalated,
        max_risk_delta       = max_risk_delta,
    )