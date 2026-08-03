from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from collections import defaultdict

GENERATOR_VERSION = "1.0.0"

_IMPACT_THRESHOLDS: list[tuple[float, float, str]] = [
    (0.00,  0.01,  "Negligible"),
    (0.01,  0.05,  "Moderate"),
    (0.05,  0.45,  "Major"),
    (0.45,  1.001, "Severe"),
]

_SAFETY_LOG: dict[str, int] = {
    "S0": 0,
    "S1": 1,
    "S2": 10,
    "S3": 100,
}

_FINANCIAL_LOG: dict[str, int] = {
    "F0": 0,
    "F1": 1,
    "F2": 10,
    "F3": 100,
}

_OPERATIONAL_LOG: dict[str, int] = {
    "O0": 0,
    "O1": 1,
    "O2": 10,
    "O3": 100,
}

_PRIVACY_LOG: dict[str, int] = {
    "P0": 0,
    "P1": 1,
    "P2": 10,
    "P3": 100,
}

_DIMENSION_MAPS: dict[str, dict[str, int]] = {
    "safety":      _SAFETY_LOG,
    "financial":   _FINANCIAL_LOG,
    "operational": _OPERATIONAL_LOG,
    "privacy":     _PRIVACY_LOG,
}

_CONFIDENCE_ORDER: dict[str, int] = {
    "high": 4,
    "medium": 3,
    "low": 2,
    "minimal": 1,
    "fallback": 0,
}

# Poids par defaut des categories d'impact -- source unique de verite.
# HEAVENS 2.0 Eq. (6) utilise w_s = 10 dans son exemple travaille.
# UPDATE G6 deplace la partie prenante vers l'usager de la route, ce qui retire
# la justification de w_f = 10 (perte financiere OEM). D'ou w_f = 1.
# [RQ-05-06] : la ponderation releve de l'organisation. A declarer dans le papier.
DEFAULT_DIMENSION_WEIGHTS: dict[str, float] = {
    "safety": 10.0,
    "financial": 1.0,
    "operational": 1.0,
    "privacy": 1.0,
}

_IMPACT_COUNTER: int = 0

def _reset_counter() -> None:
    global _IMPACT_COUNTER
    _IMPACT_COUNTER = 0

def _next_id() -> str:
    global _IMPACT_COUNTER
    _IMPACT_COUNTER += 1
    return f"IR-{_IMPACT_COUNTER:03d}"

def _rate(i_nsum: float) -> str:
    for lo, hi, label in _IMPACT_THRESHOLDS:
        if lo <= i_nsum < hi:
            return label
    return "Severe"

def _min_confidence(*confs: str) -> str:
    return min(confs, key=lambda c: _CONFIDENCE_ORDER.get(c, 0))

def _decode_dimension(
    code: str,
    dimension: str,
    evidence: dict,
) -> tuple[int, str, str, str]:
    dim_map = _DIMENSION_MAPS[dimension]
    log_val = dim_map.get(code)
    if log_val is None:
        return 0, "fallback", "T4", "fallback"
    dim_evidence = evidence.get(f"{dimension}_impact" if dimension != "safety" else "safety_level", {})
    source = dim_evidence.get("derived_from", "unknown")
    tier = dim_evidence.get("evidence_tier", "T4")
    confidence = dim_evidence.get("confidence", "minimal")
    return log_val, source, tier, confidence

def _decode_safety(
    code: str,
    evidence: dict,
) -> tuple[int, str, str, str]:
    log_val = _SAFETY_LOG.get(code)
    if log_val is None:
        return 0, "fallback", "T4", "fallback"
    dim_evidence = evidence.get("safety_level", {})
    source = dim_evidence.get("derived_from", "unknown")
    tier = dim_evidence.get("evidence_tier", "T4")
    confidence = dim_evidence.get("confidence", "minimal")
    return log_val, source, tier, confidence

@dataclass
class DimensionDerivation:
    code: str
    log_value: int
    source: str
    evidence_tier: str
    confidence: str

@dataclass
class DSImpactRecord:
    impact_record_id: str
    damage_scenario_id: str
    sfop_category: str
    safety: DimensionDerivation
    financial: DimensionDerivation
    operational: DimensionDerivation
    privacy: DimensionDerivation
    I_nsum: float
    impact_rating: str
    overall_confidence: str
    heavens_controllability: str
    heavens_degradation_mode: str
    heavens_category: str
    rationale: str
    generator_version: str

@dataclass
class ThreatImpactRecord:
    threat_impact_id: str
    threat_id: str
    per_ds_ratings: list[DSImpactRecord]
    worst_ds_id: str
    I_nsum_max: float
    impact_rating: str
    overall_confidence: str
    generator_version: str

def compute_ds_impact(
    damage_scenario: dict,
    dimension_weights: Optional[dict[str, float]] = None,
) -> DSImpactRecord:
    if dimension_weights is None:
        dimension_weights = dict(DEFAULT_DIMENSION_WEIGHTS)

    evidence = damage_scenario.get("impact_evidence", {})

    safety_code = damage_scenario.get("safety_level", "S0")
    safety_log, safety_source, safety_tier, safety_conf = _decode_safety(safety_code, evidence)

    financial_code = damage_scenario.get("financial_impact", "F0")
    financial_log, financial_source, financial_tier, financial_conf = _decode_dimension(
        financial_code, "financial", evidence
    )

    operational_code = damage_scenario.get("operational_impact", "O0")
    operational_log, operational_source, operational_tier, operational_conf = _decode_dimension(
        operational_code, "operational", evidence
    )

    privacy_code = damage_scenario.get("privacy_impact", "P0")
    privacy_log, privacy_source, privacy_tier, privacy_conf = _decode_dimension(
        privacy_code, "privacy", evidence
    )

    w_s = dimension_weights.get("safety", 1.0)
    w_f = dimension_weights.get("financial", 1.0)
    w_o = dimension_weights.get("operational", 1.0)
    w_p = dimension_weights.get("privacy", 1.0)

    numerator = (
        w_s * safety_log
        + w_f * financial_log
        + w_o * operational_log
        + w_p * privacy_log
    )
    denominator = 100.0 * (w_s + w_f + w_o + w_p)
    i_nsum = numerator / denominator if denominator > 0 else 0.0

    rating = _rate(i_nsum)
    overall_conf = _min_confidence(safety_conf, financial_conf, operational_conf, privacy_conf)

    safety_d = DimensionDerivation(
        code=safety_code,
        log_value=safety_log,
        source=safety_source,
        evidence_tier=safety_tier,
        confidence=safety_conf,
    )
    financial_d = DimensionDerivation(
        code=financial_code,
        log_value=financial_log,
        source=financial_source,
        evidence_tier=financial_tier,
        confidence=financial_conf,
    )
    operational_d = DimensionDerivation(
        code=operational_code,
        log_value=operational_log,
        source=operational_source,
        evidence_tier=operational_tier,
        confidence=operational_conf,
    )
    privacy_d = DimensionDerivation(
        code=privacy_code,
        log_value=privacy_log,
        source=privacy_source,
        evidence_tier=privacy_tier,
        confidence=privacy_conf,
    )

    ds_id = damage_scenario.get("damage_id", "unknown")

    rationale = (
        f"DS={ds_id} SFOP={damage_scenario.get('sfop_category', '?')} "
        f"S={safety_code}({safety_log})[{safety_source}] "
        f"F={financial_code}({financial_log})[{financial_source}] "
        f"O={operational_code}({operational_log})[{operational_source}] "
        f"P={privacy_code}({privacy_log})[{privacy_source}] "
        f"I_nsum={i_nsum:.6f} rating={rating} confidence={overall_conf}"
    )

    return DSImpactRecord(
        impact_record_id=_next_id(),
        damage_scenario_id=ds_id,
        sfop_category=damage_scenario.get("sfop_category", ""),
        safety=safety_d,
        financial=financial_d,
        operational=operational_d,
        privacy=privacy_d,
        I_nsum=round(i_nsum, 6),
        impact_rating=rating,
        overall_confidence=overall_conf,
        heavens_controllability=damage_scenario.get("heavens_controllability", "C0"),
        heavens_degradation_mode=damage_scenario.get("heavens_degradation_mode", "safe_state_default"),
        heavens_category=damage_scenario.get("heavens_category", "O"),
        rationale=rationale,
        generator_version=GENERATOR_VERSION,
    )

def compute_threat_impact(
    threat_id: str,
    linked_damage_scenarios: list[dict],
    dimension_weights: Optional[dict[str, float]] = None,
) -> ThreatImpactRecord:
    if not linked_damage_scenarios:
        return ThreatImpactRecord(
            threat_impact_id=_next_id(),
            threat_id=threat_id,
            per_ds_ratings=[],
            worst_ds_id="",
            I_nsum_max=0.0,
            impact_rating="Negligible",
            overall_confidence="fallback",
            generator_version=GENERATOR_VERSION,
        )

    per_ds: list[DSImpactRecord] = [
        compute_ds_impact(ds, dimension_weights)
        for ds in linked_damage_scenarios
    ]

    worst = max(per_ds, key=lambda r: r.I_nsum)

    all_confs = [r.overall_confidence for r in per_ds]
    overall_conf = _min_confidence(*all_confs)

    return ThreatImpactRecord(
        threat_impact_id=_next_id(),
        threat_id=threat_id,
        per_ds_ratings=per_ds,
        worst_ds_id=worst.damage_scenario_id,
        I_nsum_max=round(worst.I_nsum, 6),
        impact_rating=worst.impact_rating,
        overall_confidence=overall_conf,
        generator_version=GENERATOR_VERSION,
    )

def _ds_record_to_dict(r: DSImpactRecord) -> dict:
    def _dim(d: DimensionDerivation) -> dict:
        return asdict(d)
    return {
        "impact_record_id":      r.impact_record_id,
        "damage_scenario_id":    r.damage_scenario_id,
        "sfop_category":         r.sfop_category,
        "safety":                _dim(r.safety),
        "financial":             _dim(r.financial),
        "operational":           _dim(r.operational),
        "privacy":               _dim(r.privacy),
        "I_nsum":                r.I_nsum,
        "impact_rating":         r.impact_rating,
        "overall_confidence":    r.overall_confidence,
        "heavens_controllability":   r.heavens_controllability,
        "heavens_degradation_mode":  r.heavens_degradation_mode,
        "heavens_category":          r.heavens_category,
        "rationale":             r.rationale,
        "generator_version":     r.generator_version,
    }

def threat_impact_to_dict(r: ThreatImpactRecord) -> dict:
    return {
        "threat_impact_id":   r.threat_impact_id,
        "threat_id":          r.threat_id,
        "per_ds_ratings":     [_ds_record_to_dict(d) for d in r.per_ds_ratings],
        "worst_ds_id":        r.worst_ds_id,
        "I_nsum_max":         r.I_nsum_max,
        "impact_rating":      r.impact_rating,
        "overall_confidence": r.overall_confidence,
        "generator_version":  r.generator_version,
    }

def build_ds_index(damage_scenarios: list[dict]) -> dict[str, dict]:
    return {ds["damage_id"]: ds for ds in damage_scenarios}

def build_ts_to_ds_map(
    threat_scenarios: list[dict],
    ds_index: dict[str, dict],
) -> dict[str, list[dict]]:
    ts_to_ds: dict[str, list[dict]] = defaultdict(list)
    for ts in threat_scenarios:
        ts_id = ts.get("threat_id", "")
        ds_ids = ts.get("damage_scenario_ids") or []
        if not ds_ids:
            ds_id = ts.get("damage_scenario_id")
            if ds_id:
                ds_ids = [ds_id]
        for ds_id in ds_ids:
            ds = ds_index.get(ds_id)
            if ds:
                ts_to_ds[ts_id].append(ds)
    return ts_to_ds

if __name__ == "__main__":
    import sys
    from collections import Counter

    ds_path  = sys.argv[1] if len(sys.argv) > 1 else "damage_scenarios.json"
    ts_path  = sys.argv[2] if len(sys.argv) > 2 else "threat_scenarios.json"
    out_path = sys.argv[3] if len(sys.argv) > 3 else "impact_ratings.json"

    with open(ds_path) as f:
        ds_raw = json.load(f)

    damage_scenarios: list[dict] = (
        ds_raw.get("scenarios", ds_raw)
        if isinstance(ds_raw, dict)
        else ds_raw
    )

    with open(ts_path) as f:
        ts_raw = json.load(f)

    threat_scenarios: list[dict] = (
        ts_raw.get("scenarios", ts_raw)
        if isinstance(ts_raw, dict)
        else ts_raw
    )

    _reset_counter()

    ds_index = build_ds_index(damage_scenarios)
    ts_to_ds = build_ts_to_ds_map(threat_scenarios, ds_index)

    results: list[dict] = []
    for ts in threat_scenarios:
        ts_id = ts.get("threat_id", "")
        linked_ds = ts_to_ds.get(ts_id, [])
        record = compute_threat_impact(ts_id, linked_ds)
        results.append(threat_impact_to_dict(record))

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    total = len(results)
    rating_dist = Counter(r["impact_rating"] for r in results)
    conf_dist   = Counter(r["overall_confidence"] for r in results)
    no_ds       = sum(1 for r in results if not r["per_ds_ratings"])

    print(f"[impact_engine v{GENERATOR_VERSION}] Generated {total} threat impact records → {out_path}")
    print(f"  Rating distribution:      {dict(rating_dist)}")
    print(f"  Confidence distribution:  {dict(conf_dist)}")
    print(f"  Records with no DS link:  {no_ds}/{total}")