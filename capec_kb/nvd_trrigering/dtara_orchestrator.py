from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from cve_enrichment import enrich_cve
from arch_matcher import match_cve_to_architecture, MATCH_THRESHOLD

logger = logging.getLogger(__name__)


@dataclass
class DtaraResult:
    cve_id: str
    impacted: bool
    reassessment_required: bool
    impacted_ecus: list[str] = field(default_factory=list)
    impacted_assets: list[dict] = field(default_factory=list)
    impacted_threats: list[dict] = field(default_factory=list)
    impacted_attack_paths: list[dict] = field(default_factory=list)
    impacted_attack_trees: list[dict] = field(default_factory=list)
    matched_technologies: list[str] = field(default_factory=list)
    cve_summary: dict = field(default_factory=dict)


def _enrich(cve_id: str, api_key: str | None) -> dict:
    enriched = enrich_cve(cve_id, api_key)
    if not enriched.get("found", False):
        raise ValueError(f"CVE {cve_id} not found in NVD")
    return enriched


def _match(enriched: dict, arch_path: Path, score_threshold: float) -> dict:
    return match_cve_to_architecture(enriched, arch_path, score_threshold)


def _trace_assets(
    ecu_ids: set[str],
    assets: list[dict],
) -> list[dict]:
    result = []
    for asset in assets:
        mapped = set(asset.get("mapped_ecus") or [])
        if mapped & ecu_ids:
            result.append({
                "asset_id": asset["asset_id"],
                "name": asset["name"],
                "matched_ecus": sorted(mapped & ecu_ids),
            })
    return sorted(result, key=lambda x: x["asset_id"])


def _trace_threats(
    asset_ids: set[str],
    ecu_ids: set[str],
    threats: list[dict],
) -> list[dict]:
    result = []
    for threat in threats:
        asset_match = threat.get("target_asset_id") in asset_ids
        ecu_match = bool(set(threat.get("mapped_ecus") or []) & ecu_ids)
        if asset_match and ecu_match:
            result.append({
                "threat_id": threat["threat_id"],
                "title": threat.get("title", ""),
                "target_asset_id": threat.get("target_asset_id"),
            })
    return sorted(result, key=lambda x: x["threat_id"])


def _trace_paths_and_trees(
    threat_ids: set[str],
    attack_paths: list[dict],
    attack_trees: list[dict],
) -> tuple[list[dict], list[dict]]:
    matched_paths = []
    for path in attack_paths:
        if path.get("threat_id") in threat_ids:
            matched_paths.append({
                "path_id": path["path_id"],
                "threat_id": path["threat_id"],
                "target_ecu": path.get("target_ecu"),
                "path_length": path.get("path_length"),
            })

    matched_trees = []
    for tree in attack_trees:
        covered = set(tree.get("covered_threat_ids") or [])
        if covered & threat_ids:
            matched_trees.append({
                "tree_id": tree["tree_id"],
                "damage_scenario_id": tree.get("damage_scenario_id"),
                "damage_scenario_title": tree.get("damage_scenario_title"),
                "matched_threat_ids": sorted(covered & threat_ids),
            })

    return (
        sorted(matched_paths, key=lambda x: x["path_id"]),
        sorted(matched_trees, key=lambda x: x["tree_id"]),
    )


def run_dtara(
    cve_id: str,
    arch_path: str | Path,
    assets: list[dict],
    threats: list[dict],
    attack_paths: list[dict],
    attack_trees: list[dict],
    api_key: str | None = None,
    score_threshold: float = MATCH_THRESHOLD,
) -> DtaraResult:
    arch_path = Path(arch_path)

    logger.info("[d-TARA] Stage 1 — CVE enrichment: %s", cve_id)
    enriched = _enrich(cve_id, api_key)

    cve_summary = {
        "cve_id": cve_id,
        "description": enriched.get("description", ""),
        "cvss_score": enriched.get("cvss", {}).get("baseScore"),
        "cvss_severity": enriched.get("cvss", {}).get("baseSeverity"),
        "published": enriched.get("published"),
        "products": enriched.get("products", []),
        "vendors": enriched.get("vendors", []),
    }

    logger.info("[d-TARA] Stage 2 — Architecture matching")
    match_result = _match(enriched, arch_path, score_threshold)

    if not match_result["impacted"]:
        logger.info("[d-TARA] No architecture impact detected. Pipeline halted.")
        return DtaraResult(
            cve_id=cve_id,
            impacted=False,
            reassessment_required=False,
            matched_technologies=[],
            cve_summary=cve_summary,
        )

    ecu_ids = set(match_result["impactedComponents"])
    matched_technologies = match_result.get("matchedTechnologies", [])
    logger.info("[d-TARA] Impacted ECUs: %s", sorted(ecu_ids))
    logger.info("[d-TARA] Matched technologies: %s", matched_technologies)

    logger.info("[d-TARA] Stage 3 — Asset tracing")
    impacted_assets = _trace_assets(ecu_ids, assets)
    asset_ids = {a["asset_id"] for a in impacted_assets}
    logger.info("[d-TARA] Impacted assets: %d", len(impacted_assets))

    logger.info("[d-TARA] Stage 4 — Threat scenario tracing")
    impacted_threats = _trace_threats(asset_ids, ecu_ids, threats)
    threat_ids = {t["threat_id"] for t in impacted_threats}
    logger.info("[d-TARA] Impacted threats: %d", len(impacted_threats))

    logger.info("[d-TARA] Stage 5 — Attack path and tree tracing")
    impacted_paths, impacted_trees = _trace_paths_and_trees(
        threat_ids, attack_paths, attack_trees
    )
    logger.info(
        "[d-TARA] Impacted paths: %d  Impacted trees: %d",
        len(impacted_paths),
        len(impacted_trees),
    )

    return DtaraResult(
        cve_id=cve_id,
        impacted=True,
        reassessment_required=True,
        impacted_ecus=sorted(ecu_ids),
        impacted_assets=impacted_assets,
        impacted_threats=impacted_threats,
        impacted_attack_paths=impacted_paths,
        impacted_attack_trees=impacted_trees,
        matched_technologies=matched_technologies,
        cve_summary=cve_summary,
    )