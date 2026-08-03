from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from typing import Optional

GENERATOR_VERSION = "1.0.0"

_RISK_MATRIX: dict[tuple[str, str], int] = {
    ("Very Low",  "Negligible"): 1,
    ("Very Low",  "Moderate"):   1,
    ("Very Low",  "Major"):      2,
    ("Very Low",  "Severe"):     3,
    ("Low",       "Negligible"): 1,
    ("Low",       "Moderate"):   2,
    ("Low",       "Major"):      3,
    ("Low",       "Severe"):     4,
    ("Medium",    "Negligible"): 2,
    ("Medium",    "Moderate"):   3,
    ("Medium",    "Major"):      4,
    ("Medium",    "Severe"):     5,
    ("High",      "Negligible"): 2,
    ("High",      "Moderate"):   4,
    ("High",      "Major"):      5,
    ("High",      "Severe"):     5,
}

_RISK_LEVEL: dict[int, str] = {
    1: "Negligible",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
}

_VALID_IMPACT_RATINGS: frozenset[str] = frozenset({
    "Negligible", "Moderate", "Major", "Severe"
})

_VALID_FEASIBILITY_RATINGS: frozenset[str] = frozenset({
    "Very Low", "Low", "Medium", "High"
})

_CONFIDENCE_ORDER: dict[str, int] = {
    "high":     4,
    "medium":   3,
    "low":      2,
    "minimal":  1,
    "fallback": 0,
}

def _min_confidence(*confs: str) -> str:
    return min(confs, key=lambda c: _CONFIDENCE_ORDER.get(c, 0))

def _lookup_risk(af_rating: str, impact_rating: str) -> tuple[int, str]:
    risk_value = _RISK_MATRIX.get((af_rating, impact_rating))
    if risk_value is None:
        return 1, "Negligible"
    return risk_value, _RISK_LEVEL[risk_value]

@dataclass
class RiskRecord:
    risk_id: str
    threat_id: str
    damage_scenario_id: str
    impact_rating: str
    attack_feasibility_rating: str
    risk_value: int
    risk_level: str
    confidence: str
    traceability: dict
    provenance: dict
    generator_version: str

_RISK_COUNTER: int = 0

def _reset_counter() -> None:
    global _RISK_COUNTER
    _RISK_COUNTER = 0

def _next_id() -> str:
    global _RISK_COUNTER
    _RISK_COUNTER += 1
    return f"RK-{_RISK_COUNTER:03d}"

def _build_impact_index(impact_records: list[dict]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for record in impact_records:
        tid = record.get("threat_id", "")
        if tid:
            index[tid] = record
    return index

def _build_feasibility_index(feasibility_records: list[dict]) -> dict[str, dict]:
    """Index feasibility records by their OWN threat scenario.

    CORRECTED. The previous version fanned each record out over every entry in
    `covered_threat_ids`, so a threat scenario could receive the feasibility of a
    record whose worst attack path realised a DIFFERENT threat. This violates
    ISO/SAE 21434 [RQ-08-11] NOTE 2 (aggregate over the *corresponding* attack
    paths) and HEAVENS 2.0 sec. 4.2.2.

    attack_feasibility.py v1.5.0 emits one record per threat scenario, so the
    index is now a direct threat_id -> record map. A record carrying more than
    one covered_threat_id is a stale artefact and is rejected loudly.
    """
    index: dict[str, dict] = {}
    for record in feasibility_records:
        tid = record.get("threat_id", "")
        if not tid:
            continue
        covered = record.get("covered_threat_ids") or [tid]
        if len(covered) > 1:
            raise ValueError(
                f"Feasibility record {record.get('feasibility_id', '?')} covers "
                f"{len(covered)} threat scenarios. This file was produced by "
                f"attack_feasibility.py < v1.5.0 and its ratings are not valid "
                f"per-threat. Regenerate attack_feasibility.json before scoring risk."
            )
        if tid in index:
            raise ValueError(f"Duplicate feasibility record for threat {tid}.")
        index[tid] = record
    return index

def _build_ds_index(damage_scenarios: list[dict]) -> dict[str, dict]:
    return {ds["damage_id"]: ds for ds in damage_scenarios}

def _build_ts_index(threat_scenarios: list[dict]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for ts in threat_scenarios:
        tid = ts.get("threat_id", "")
        if tid:
            index[tid] = ts
    return index

def _build_tree_index(attack_trees: list[dict]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for tree in attack_trees:
        tid = tree.get("tree_id", "")
        if tid:
            index[tid] = tree
    return index

def _extract_per_ds_impact_ratings(impact_record: dict) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for ds_rating in impact_record.get("per_ds_ratings", []):
        ds_id = ds_rating.get("damage_scenario_id", "")
        if ds_id:
            result[ds_id] = ds_rating
    return result

def compute_risk_record(
    threat_id: str,
    damage_scenario_id: str,
    impact_rating: str,
    attack_feasibility_rating: str,
    impact_record: dict,
    feasibility_record: dict,
    ds_impact_detail: Optional[dict],
    ts_record: Optional[dict],
    ds_record: Optional[dict],
    tree_record: Optional[dict],
) -> RiskRecord:

    risk_value, risk_level = _lookup_risk(attack_feasibility_rating, impact_rating)

    impact_confidence = impact_record.get("overall_confidence", "fallback")
    feasibility_confidence = feasibility_record.get("overall_confidence", "fallback")
    combined_confidence = _min_confidence(impact_confidence, feasibility_confidence)

    traceability: dict = {
        "threat": {
            "threat_id": threat_id,
            "title": ts_record.get("title", "") if ts_record else "",
            "stride_categories": ts_record.get("stride_categories", []) if ts_record else [],
            "compromised_property": ts_record.get("compromised_property", "") if ts_record else "",
            "target_asset_id": ts_record.get("target_asset_id", "") if ts_record else "",
            "target_asset_name": ts_record.get("target_asset_name", "") if ts_record else "",
            "source_ontology_id": ts_record.get("source_ontology_id", "") if ts_record else "",
        },
        "damage": {
            "damage_scenario_id": damage_scenario_id,
            "sfop_category": ds_record.get("sfop_category", "") if ds_record else (
                ds_impact_detail.get("sfop_category", "") if ds_impact_detail else ""
            ),
            "heavens_category": ds_record.get("heavens_category", "") if ds_record else "",
            "heavens_controllability": ds_record.get("heavens_controllability", "") if ds_record else "",
            "heavens_degradation_mode": ds_record.get("heavens_degradation_mode", "") if ds_record else "",
        },
        "impact": {
            "threat_impact_id": impact_record.get("threat_impact_id", ""),
            "impact_record_id": ds_impact_detail.get("impact_record_id", "") if ds_impact_detail else "",
            "I_nsum": ds_impact_detail.get("I_nsum", None) if ds_impact_detail else None,
            "worst_ds_id": impact_record.get("worst_ds_id", ""),
            "impact_confidence": impact_confidence,
            "safety": ds_impact_detail.get("safety", {}) if ds_impact_detail else {},
            "financial": ds_impact_detail.get("financial", {}) if ds_impact_detail else {},
            "operational": ds_impact_detail.get("operational", {}) if ds_impact_detail else {},
            "privacy": ds_impact_detail.get("privacy", {}) if ds_impact_detail else {},
            "rationale": ds_impact_detail.get("rationale", "") if ds_impact_detail else "",
        },
        "feasibility": {
            "feasibility_id": feasibility_record.get("feasibility_id", ""),
            "tree_id": feasibility_record.get("tree_id", ""),
            "worst_path_id": feasibility_record.get("worst_path_id", ""),
            "A_norm_max": feasibility_record.get("A_norm_max", None),
            "feasibility_confidence": feasibility_confidence,
            "pre_screen_rating": feasibility_record.get("pre_screen_rating", ""),
            "per_path_ratings": feasibility_record.get("per_path_ratings", []),
        },
        "attack_tree": {
            "tree_id": tree_record.get("tree_id", "") if tree_record else feasibility_record.get("tree_id", ""),
            "covered_threat_ids": tree_record.get("covered_threat_ids", []) if tree_record else [],
            "heavens_controllability": tree_record.get("heavens_controllability", "") if tree_record else "",
            "heavens_degradation_mode": tree_record.get("heavens_degradation_mode", "") if tree_record else "",
        },
    }

    provenance: dict = {
        "risk_matrix": "HEAVENS 2.0 Table 8",
        "multiplicity_rule_impact": "HEAVENS 2.0 §4.2.5 — worst-case damage scenario (max I_nsum)",
        "multiplicity_rule_feasibility": "HEAVENS 2.0 §4.2.5 — worst-case attack path (max A_norm)",
        "confidence_aggregation": "min(impact_confidence, feasibility_confidence)",
        "impact_rating_used": impact_rating,
        "attack_feasibility_rating_used": attack_feasibility_rating,
        "impact_source": f"impact_record:{impact_record.get('threat_impact_id', '')}",
        "feasibility_source": f"feasibility_record:{feasibility_record.get('feasibility_id', '')}",
        "generator_version": GENERATOR_VERSION,
    }

    return RiskRecord(
        risk_id=_next_id(),
        threat_id=threat_id,
        damage_scenario_id=damage_scenario_id,
        impact_rating=impact_rating,
        attack_feasibility_rating=attack_feasibility_rating,
        risk_value=risk_value,
        risk_level=risk_level,
        confidence=combined_confidence,
        traceability=traceability,
        provenance=provenance,
        generator_version=GENERATOR_VERSION,
    )

def compute_risk(
    impact_records: list[dict],
    feasibility_records: list[dict],
    damage_scenarios: Optional[list[dict]] = None,
    threat_scenarios: Optional[list[dict]] = None,
    attack_trees: Optional[list[dict]] = None,
) -> list[RiskRecord]:

    impact_index = _build_impact_index(impact_records)
    feasibility_index = _build_feasibility_index(feasibility_records)

    ds_index = _build_ds_index(damage_scenarios) if damage_scenarios else {}
    ts_index = _build_ts_index(threat_scenarios) if threat_scenarios else {}
    tree_index = _build_tree_index(attack_trees) if attack_trees else {}

    all_threat_ids: set[str] = set(impact_index.keys()) | set(feasibility_index.keys())

    results: list[RiskRecord] = []

    for threat_id in sorted(all_threat_ids):
        impact_record = impact_index.get(threat_id)
        feasibility_record = feasibility_index.get(threat_id)

        if impact_record is None or feasibility_record is None:
            continue

        impact_rating = impact_record.get("impact_rating", "Negligible")
        af_rating = feasibility_record.get("attack_feasibility_rating", "Very Low")

        if impact_rating not in _VALID_IMPACT_RATINGS:
            impact_rating = "Negligible"
        if af_rating not in _VALID_FEASIBILITY_RATINGS:
            af_rating = "Very Low"

        worst_ds_id = impact_record.get("worst_ds_id", "")
        per_ds_map = _extract_per_ds_impact_ratings(impact_record)

        damage_scenario_ids: list[str] = list(per_ds_map.keys()) if per_ds_map else (
            [worst_ds_id] if worst_ds_id else ["unknown"]
        )

        if worst_ds_id and worst_ds_id in per_ds_map:
            ds_impact_detail = per_ds_map[worst_ds_id]
            ds_id = worst_ds_id
        elif per_ds_map:
            ds_id = max(per_ds_map.keys(), key=lambda k: per_ds_map[k].get("I_nsum", 0.0))
            ds_impact_detail = per_ds_map[ds_id]
        else:
            ds_id = "unknown"
            ds_impact_detail = None

        ts_record = ts_index.get(threat_id)
        ds_record = ds_index.get(ds_id)

        tree_id = feasibility_record.get("tree_id", "")
        tree_record = tree_index.get(tree_id)

        record = compute_risk_record(
            threat_id=threat_id,
            damage_scenario_id=ds_id,
            impact_rating=impact_rating,
            attack_feasibility_rating=af_rating,
            impact_record=impact_record,
            feasibility_record=feasibility_record,
            ds_impact_detail=ds_impact_detail,
            ts_record=ts_record,
            ds_record=ds_record,
            tree_record=tree_record,
        )
        results.append(record)

    return results

def risk_to_dict(r: RiskRecord) -> dict:
    return {
        "risk_id":                   r.risk_id,
        "threat_id":                 r.threat_id,
        "damage_scenario_id":        r.damage_scenario_id,
        "impact_rating":             r.impact_rating,
        "attack_feasibility_rating": r.attack_feasibility_rating,
        "risk_value":                r.risk_value,
        "risk_level":                r.risk_level,
        "confidence":                r.confidence,
        "traceability":              r.traceability,
        "provenance":                r.provenance,
        "generator_version":         r.generator_version,
    }

def _load_json_scenarios(path: str) -> list[dict]:
    with open(path) as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        return raw.get("scenarios", raw.get("records", []))
    return raw

if __name__ == "__main__":
    impact_path      = sys.argv[1] if len(sys.argv) > 1 else "impact_ratings.json"
    feasibility_path = sys.argv[2] if len(sys.argv) > 2 else "attack_feasibility.json"
    out_path         = sys.argv[3] if len(sys.argv) > 3 else "risk.json"
    ds_path          = sys.argv[4] if len(sys.argv) > 4 else None
    ts_path          = sys.argv[5] if len(sys.argv) > 5 else None
    trees_path       = sys.argv[6] if len(sys.argv) > 6 else None

    impact_records      = _load_json_scenarios(impact_path)
    feasibility_records = _load_json_scenarios(feasibility_path)

    damage_scenarios = _load_json_scenarios(ds_path)  if ds_path  and __import__("os").path.exists(ds_path)  else None
    threat_scenarios = _load_json_scenarios(ts_path)  if ts_path  and __import__("os").path.exists(ts_path)  else None
    attack_trees     = _load_json_scenarios(trees_path) if trees_path and __import__("os").path.exists(trees_path) else None

    _reset_counter()

    records = compute_risk(
        impact_records,
        feasibility_records,
        damage_scenarios,
        threat_scenarios,
        attack_trees,
    )

    output = [risk_to_dict(r) for r in records]

    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    total        = len(records)
    level_dist   = Counter(r.risk_level  for r in records)
    value_dist   = Counter(r.risk_value  for r in records)
    conf_dist    = Counter(r.confidence  for r in records)
    af_dist      = Counter(r.attack_feasibility_rating for r in records)
    impact_dist  = Counter(r.impact_rating for r in records)

    print(f"[risk_engine v{GENERATOR_VERSION}] Generated {total} risk records → {out_path}")
    print(f"  Risk level distribution:       {dict(level_dist)}")
    print(f"  Risk value distribution:       {dict(value_dist)}")
    print(f"  Confidence distribution:       {dict(conf_dist)}")
    print(f"  Attack feasibility dist:       {dict(af_dist)}")
    print(f"  Impact rating dist:            {dict(impact_dist)}")