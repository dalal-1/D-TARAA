from __future__ import annotations

from dataclasses import dataclass

from feasibility_updater import UpdatedFeasibilityRecord


RISK_MATRIX: dict[tuple[str, str], tuple[int, str]] = {
    ("Negligible", "Very Low"): (1, "Negligible"),
    ("Negligible", "Low"):      (1, "Negligible"),
    ("Negligible", "Medium"):   (2, "Low"),
    ("Negligible", "High"):     (2, "Low"),
    ("Moderate",   "Very Low"): (1, "Negligible"),
    ("Moderate",   "Low"):      (2, "Low"),
    ("Moderate",   "Medium"):   (3, "Medium"),
    ("Moderate",   "High"):     (4, "High"),
    ("Major",      "Very Low"): (2, "Low"),
    ("Major",      "Low"):      (3, "Medium"),
    ("Major",      "Medium"):   (4, "High"),
    ("Major",      "High"):     (5, "Critical"),
    ("Severe",     "Very Low"): (3, "Medium"),
    ("Severe",     "Low"):      (4, "High"),
    ("Severe",     "Medium"):   (5, "Critical"),
    ("Severe",     "High"):     (5, "Critical"),
}


@dataclass
class UpdatedRiskRecord:
    risk_id:                     str
    threat_id:                   str
    damage_scenario_id:          str
    impact_rating:               str
    feasibility_rating_baseline: str
    feasibility_rating_updated:  str
    risk_value_baseline:         int
    risk_value_updated:          int
    risk_level_baseline:         str
    risk_level_updated:          str
    risk_delta:                  int
    risk_escalated:              bool
    cve_id:                      str
    affected_ecu:                str
    affected_technology:         str
    provenance:                  dict


def recompute_risk(
    risk_record:         dict,
    updated_feasibility: UpdatedFeasibilityRecord,
) -> UpdatedRiskRecord:
    impact_rating               = risk_record["impact_rating"]
    feasibility_rating_baseline = risk_record["attack_feasibility_rating"]
    feasibility_rating_updated  = updated_feasibility.feasibility_rating_updated

    baseline_value, baseline_level = RISK_MATRIX.get(
        (impact_rating, feasibility_rating_baseline),
        (risk_record["risk_value"], risk_record["risk_level"]),
    )

    updated_value, updated_level = RISK_MATRIX.get(
        (impact_rating, feasibility_rating_updated),
        (baseline_value, baseline_level),
    )

    delta     = updated_value - baseline_value
    escalated = delta > 0

    provenance = {
        "risk_matrix_spec":          "HEAVENS 2.0 Table 8",
        "impact_rating":             impact_rating,
        "feasibility_baseline":      feasibility_rating_baseline,
        "feasibility_updated":       feasibility_rating_updated,
        "feasibility_changed":       updated_feasibility.feasibility_changed,
        "a_norm_max_baseline":       updated_feasibility.a_norm_max_baseline,
        "a_norm_max_updated":        updated_feasibility.a_norm_max_updated,
        "worst_path_id_updated":     updated_feasibility.worst_path_id_updated,
        "risk_matrix_lookup_baseline": f"({impact_rating}, {feasibility_rating_baseline}) -> {baseline_level} ({baseline_value})",
        "risk_matrix_lookup_updated":  f"({impact_rating}, {feasibility_rating_updated}) -> {updated_level} ({updated_value})",
        "cve_id":                    updated_feasibility.cve_id,
        "affected_ecu":              updated_feasibility.affected_ecu,
        "affected_technology":       updated_feasibility.affected_technology,
        "feasibility_source":        f"feasibility_record:{updated_feasibility.feasibility_id}",
    }

    return UpdatedRiskRecord(
        risk_id                     = risk_record["risk_id"],
        threat_id                   = risk_record["threat_id"],
        damage_scenario_id          = risk_record["damage_scenario_id"],
        impact_rating               = impact_rating,
        feasibility_rating_baseline = feasibility_rating_baseline,
        feasibility_rating_updated  = feasibility_rating_updated,
        risk_value_baseline         = baseline_value,
        risk_value_updated          = updated_value,
        risk_level_baseline         = baseline_level,
        risk_level_updated          = updated_level,
        risk_delta                  = delta,
        risk_escalated              = escalated,
        cve_id                      = updated_feasibility.cve_id,
        affected_ecu                = updated_feasibility.affected_ecu,
        affected_technology         = updated_feasibility.affected_technology,
        provenance                  = provenance,
    )