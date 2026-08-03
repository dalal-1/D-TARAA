from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from collections import defaultdict

GENERATOR_VERSION = "1.5.0"  # Fix1: exposure_time unknown=1; FixB: CAPEC→HEAVENS remapping;
#                              Fix C (v1.5.0): per-threat-scenario aggregation
#                              (ISO/SAE 21434 [RQ-08-11] NOTE 2, HEAVENS 2.0 sec. 4.2.2/4.2.5)

_RATING_THRESHOLDS: list[tuple[float, float, str]] = [
    (0.00, 0.30, "Very Low"),
    (0.30, 0.60, "Low"),
    (0.60, 0.80, "Medium"),
    (0.80, 1.01, "High"),
]

_ACTOR_CLASS_SE: dict[str, int] = {
    "nation_state":              0,
    "advanced_persistent_threat": 0,
    "organized_crime":           1,
    "security_researcher":       1,
    "script_kiddie":             2,
    "opportunistic":             2,
    "insider":                   3,
}

_PATH_TYPE_SE: dict[str, int] = {
    "lateral_movement":   0,
    "remote_wireless":    1,
    "physical_diagnostic": 2,
    "physical_hardware":  2,
}

_IDENTIFICATION_PURPOSE_KOIC: dict[str, int] = {
    "safety_critical_function":    0,
    "security_critical_function":  0,
    "access_control_relevant":     1,
    "operational_relevant":        2,
    "general_security_relevance":  2,
    "non_critical":                3,
}

_FALLBACK_PROFILE_EXPOSURE: dict[str, int] = {
    "always_on":          3,
    "network_connected":  3,
    "functional_on_demand": 2,
    "conditional":        1,
    "workshop_only":      0,
    "unknown":            1,   # Fix 1: absence d'info ≠ cas le plus restrictif (workshop_only)
}

_SAE_HIGH_AUTOMATION: frozenset[str] = frozenset({
    "SAE_L3_L5", "SAE_L4_L5", "SAE_L5", "SAE_L4", "SAE_L3",
})
_SAE_MED_AUTOMATION: frozenset[str] = frozenset({
    "SAE_L2", "SAE_L2_L3",
})

_WOO_TABLE: dict[tuple[int, int], int] = {
    (1, 0): 0, (1, 1): 0, (1, 2): 0, (1, 3): 0,
    (2, 0): 0, (2, 1): 0, (2, 2): 0, (2, 3): 1,
    (3, 0): 0, (3, 1): 0, (3, 2): 1, (3, 3): 2,
    (4, 0): 0, (4, 1): 1, (4, 2): 2, (4, 3): 2,
    (5, 0): 1, (5, 1): 2, (5, 2): 3, (5, 3): 3,
}

# ---------------------------------------------------------------------------
# Fix B — Remapping CAPEC enrichment scales → HEAVENS parameter scales (0–3)
#
# Le générateur capec_enrichment.json utilise des échelles propres qui diffèrent
# des plages attendues par _norm() (0–3 par paramètre, max A_sum=12).
#
# SE  : CAPEC {0,3,6} → HEAVENS {0,1,3}
#       Low skill (SE=6)  → facile → HEAVENS SE=3 (insider/opportuniste)
#       Med skill (SE=3)  → moyen → HEAVENS SE=1
#       High skill (SE=0) → difficile → HEAVENS SE=0 (nation_state)
#       Valeurs inconnues : clamp à 3 (conservateur côté attaquant)
_CAPEC_SE_REMAP: dict[int, int] = {0: 0, 3: 1, 6: 3}

# WoO : CAPEC {1,2,3,4} encode l'*accès requis*, pas la fenêtre temporelle HEAVENS
#       CAPEC WoO=1 (remote)   → fenêtre max → HEAVENS WoO=3
#       CAPEC WoO=2 (adjacent) → fenêtre large → HEAVENS WoO=2
#       CAPEC WoO=3 (local)    → fenêtre réduite → HEAVENS WoO=1
#       CAPEC WoO=4 (physical) → fenêtre quasi nulle → HEAVENS WoO=0
#       Inversion sémantique intentionnelle : accès facile = grande fenêtre
_CAPEC_WOO_REMAP: dict[int, int] = {1: 3, 2: 2, 3: 1, 4: 0}

# KoIC : CAPEC {1,2,3,6} — valeurs 1–3 déjà dans range HEAVENS.
#        KoIC=6 (4 CAPECs, "via insider") est un artefact d'échelle → clamp à 3.
# Eq   : CAPEC {0,1,3} — déjà dans range HEAVENS, aucun remapping nécessaire.

def _remap_capec_se(v: int) -> int:
    """Remappe un SE CAPEC (0/3/6) vers l'échelle HEAVENS (0–3)."""
    return _CAPEC_SE_REMAP.get(v, min(v, 3))

def _remap_capec_woo(v: int) -> int:
    """Remappe un WoO CAPEC (1–4 = access_means) vers la fenêtre HEAVENS (0–3)."""
    return _CAPEC_WOO_REMAP.get(v, min(max(v, 0), 3))

def _remap_capec_koic(v: int) -> int:
    """Clamp KoIC CAPEC à 3 (artefact KoIC=6 sur 4 CAPECs 'via insider')."""
    return min(v, 3)
# ---------------------------------------------------------------------------

def _norm(raw_sum: int, n_params: int = 4) -> float:
    return raw_sum / (3 * n_params)

def _rate(a_norm: float) -> str:
    for lo, hi, label in _RATING_THRESHOLDS:
        if lo <= a_norm < hi:
            return label
    return "High"

def _confidence_min(*confs: str) -> str:
    order = {"high": 3, "medium": 2, "low": 1, "fallback": 0}
    return min(confs, key=lambda c: order.get(c, 0))

def _extract_capec_param(capec_refs: list[dict], param: str, use_min: bool = False) -> tuple[Optional[int], list[str]]:
    values: list[int] = []
    sources: list[str] = []
    for ref in capec_refs:
        v = ref.get(param)
        if v is not None:
            try:
                values.append(int(v))
                cid = str(ref.get("capec_id", ""))
                if cid:
                    sources.append(cid)
            except (ValueError, TypeError):
                pass
    if values:
        return min(values), sources
    return None, []

@dataclass
class ParameterDerivation:
    value: int
    source: str
    confidence: str
    provenance: dict

@dataclass
class PathFeasibility:
    path_id: str
    threat_id: str
    path_type: str
    path_length: int
    SE: ParameterDerivation
    KoIC: ParameterDerivation
    WoO: ParameterDerivation
    Eq: ParameterDerivation
    A_sum: int
    A_norm: float
    rating: str

@dataclass
class FeasibilityRecord:
    feasibility_id: str
    threat_id: str
    damage_scenario_id: str
    tree_id: str
    target_asset_id: str
    target_asset_name: str
    covered_threat_ids: list[str]
    per_path_ratings: list[PathFeasibility]
    worst_path_id: str
    A_norm_max: float
    attack_feasibility_rating: str
    pre_screen_rating: str
    overall_confidence: str
    heavens_controllability: str
    heavens_category: str
    heavens_sae_automation_level: str
    heavens_degradation_mode: str
    heavens_fallback_profile_class: str
    heavens_identification_purpose: str
    rationale: str
    generator_version: str

_feasibility_counter: int = 0

def _reset_counter() -> None:
    global _feasibility_counter
    _feasibility_counter = 0

def _next_id() -> str:
    global _feasibility_counter
    _feasibility_counter += 1
    return f"AF-{_feasibility_counter:03d}"

def _derive_SE(
    capec_refs: list[dict],
    threat_actor_classes: list[str],
    path_type: str,
    path_steps: Optional[list[dict]] = None,
    capec_enrichment: Optional[dict] = None,
) -> ParameterDerivation:
    if path_steps and capec_enrichment:
        step_se_values: list[int] = []
        step_sources: list[str] = []
        for step in path_steps:
            cid = str(step.get("capec_id") or "")
            if cid and cid in capec_enrichment:
                se_val = capec_enrichment[cid].get("SE")
                if se_val is not None:
                    step_se_values.append(int(se_val))
                    step_sources.append(cid)
        if step_se_values:
            raw = min(step_se_values)
            remapped = _remap_capec_se(raw)
            return ParameterDerivation(
                value=remapped,
                source="capec_primary",
                confidence="high",
                provenance={
                    "capec_ids": step_sources,
                    "step_se_values": step_se_values,
                    "raw_min": raw,
                    "remapped": remapped,
                },
            )

    v, sources = _extract_capec_param(capec_refs, "SE")
    if v is not None:
        remapped = _remap_capec_se(v)
        return ParameterDerivation(
            value=remapped,
            source="capec_primary",
            confidence="high",
            provenance={"capec_ids": sources, "raw_min": v, "remapped": remapped},
        )
    if threat_actor_classes:
        values: list[int] = []
        matched: list[str] = []
        for actor in threat_actor_classes:
            actor_norm = actor.lower().replace(" ", "_").replace("-", "_")
            for key, val in _ACTOR_CLASS_SE.items():
                if key in actor_norm:
                    values.append(val)
                    matched.append(actor)
                    break
        if values:
            result = max(values)
            return ParameterDerivation(
                value=result,
                source="actor_class",
                confidence="medium",
                provenance={"actor_classes_matched": matched, "value": result},
            )
    ptype_norm = path_type.lower()
    for key, val in _PATH_TYPE_SE.items():
        if key in ptype_norm:
            return ParameterDerivation(
                value=val,
                source="path_type",
                confidence="medium",
                provenance={"path_type": path_type, "value": val},
            )
    return ParameterDerivation(
        value=1,
        source="fallback",
        confidence="fallback",
        provenance={"reason": "no_capec_no_actor_no_path_type_match"},
    )

def _derive_KoIC(
    capec_refs: list[dict],
    heavens_identification_purpose: str,
    heavens_category: str,
    path_steps: Optional[list[dict]] = None,
    capec_enrichment: Optional[dict] = None,
) -> ParameterDerivation:
    if path_steps and capec_enrichment:
        step_values: list[int] = []
        step_sources: list[str] = []
        for step in path_steps:
            cid = str(step.get("capec_id") or "")
            if cid and cid in capec_enrichment:
                val = capec_enrichment[cid].get("KoIC")
                if val is not None:
                    step_values.append(int(val))
                    step_sources.append(cid)
        if step_values:
            raw = min(step_values)
            final = _remap_capec_koic(raw)
            floor_applied = False
            if heavens_category == "S" and final < 1:
                final = 1
                floor_applied = True
            return ParameterDerivation(
                value=final,
                source="capec_primary",
                confidence="high",
                provenance={
                    "capec_ids": step_sources,
                    "step_koic_values": step_values,
                    "raw_min": raw,
                    "remapped": final,
                    "safety_floor_applied": floor_applied,
                },
            )

    v, sources = _extract_capec_param(capec_refs, "KoIC")
    if v is not None:
        floor_applied = False
        final = _remap_capec_koic(v)
        if heavens_category == "S" and final < 1:
            final = 1
            floor_applied = True
        return ParameterDerivation(
            value=final,
            source="capec_primary",
            confidence="high",
            provenance={
                "capec_ids": sources,
                "raw_min": v,
                "remapped": final,
                "safety_floor_applied": floor_applied,
            },
        )
    purpose_val = _IDENTIFICATION_PURPOSE_KOIC.get(heavens_identification_purpose)
    if purpose_val is not None:
        final = purpose_val
        floor_applied = False
        if heavens_category == "S" and final < 1:
            final = 1
            floor_applied = True
        return ParameterDerivation(
            value=final,
            source="identification_purpose",
            confidence="medium",
            provenance={
                "identification_purpose": heavens_identification_purpose,
                "derived_value": purpose_val,
                "safety_floor_applied": floor_applied,
                "heavens_category": heavens_category,
            },
        )
    final = 1
    if heavens_category == "S" and final < 1:
        final = 1
    return ParameterDerivation(
        value=final,
        source="fallback",
        confidence="fallback",
        provenance={
            "reason": "no_capec_no_purpose_match",
            "heavens_category": heavens_category,
        },
    )

def _derive_WoO(
    capec_refs: list[dict],
    is_directly_remote: bool,
    is_transitively_remote: bool,
    attack_surfaces: list[str],
    heavens_fallback_profile_class: str,
    heavens_sae_automation_level: str,
    path_steps: Optional[list[dict]] = None,
    capec_enrichment: Optional[dict] = None,
) -> ParameterDerivation:
    if path_steps and capec_enrichment:
        step_values: list[int] = []
        step_sources: list[str] = []
        for step in path_steps:
            cid = str(step.get("capec_id") or "")
            if cid and cid in capec_enrichment:
                val = capec_enrichment[cid].get("WoO")
                if val is not None:
                    step_values.append(int(val))
                    step_sources.append(cid)
        if step_values:
            raw = min(step_values)
            remapped = _remap_capec_woo(raw)
            return ParameterDerivation(
                value=remapped,
                source="capec_primary",
                confidence="high",
                provenance={
                    "capec_ids": step_sources,
                    "step_woo_values": step_values,
                    "raw_min": raw,
                    "remapped": remapped,
                },
            )

    v, sources = _extract_capec_param(capec_refs, "WoO")
    if v is not None:
        remapped = _remap_capec_woo(v)
        return ParameterDerivation(
            value=remapped,
            source="capec_primary",
            confidence="high",
            provenance={"capec_ids": sources, "raw_min": v, "remapped": remapped},
        )
    surfaces_set = {s.lower() for s in attack_surfaces}
    if is_directly_remote:
        access_means = 5
        am_source = "remote_2_anywhere"
    elif is_transitively_remote:
        access_means = 4
        am_source = "remote_1_proximity"
    elif "diagnostic_interface" in surfaces_set:
        access_means = 3
        am_source = "physical_3_no_disassembly"
    elif "physical_access" in surfaces_set:
        access_means = 2
        am_source = "physical_2_component_access"
    else:
        access_means = 1
        am_source = "physical_1_component_disassembly"

    exposure_time = _FALLBACK_PROFILE_EXPOSURE.get(
        heavens_fallback_profile_class.lower(), 0
    )
    et_source = f"fallback_profile_class:{heavens_fallback_profile_class}"

    sae_mod_applied = False
    sae_norm = heavens_sae_automation_level.upper().replace(" ", "_")
    if sae_norm in _SAE_HIGH_AUTOMATION:
        if exposure_time < 2:
            exposure_time = 2
            sae_mod_applied = True
    elif sae_norm in _SAE_MED_AUTOMATION:
        if exposure_time < 1:
            exposure_time = 1
            sae_mod_applied = True

    woo_val = _WOO_TABLE.get((access_means, exposure_time), 1)

    return ParameterDerivation(
        value=woo_val,
        source="reachability_derived",
        confidence="medium",
        provenance={
            "access_means_value": access_means,
            "access_means_source": am_source,
            "exposure_time_value": exposure_time,
            "exposure_time_source": et_source,
            "sae_modifier_applied": sae_mod_applied,
            "sae_level": heavens_sae_automation_level,
            "woo_table_result": woo_val,
        },
    )

def _derive_Eq(
    capec_refs: list[dict],
    path_type: str,
    attack_surfaces: list[str],
    heavens_sae_automation_level: str,
    path_steps: Optional[list[dict]] = None,
    capec_enrichment: Optional[dict] = None,
) -> ParameterDerivation:
    if path_steps and capec_enrichment:
        step_values: list[int] = []
        step_sources: list[str] = []
        for step in path_steps:
            cid = str(step.get("capec_id") or "")
            if cid and cid in capec_enrichment:
                val = capec_enrichment[cid].get("Eq")
                if val is not None:
                    step_values.append(int(val))
                    step_sources.append(cid)
        if step_values:
            return ParameterDerivation(
                value=min(step_values),
                source="capec_primary",
                confidence="high",
                provenance={
                    "capec_ids": step_sources,
                    "step_eq_values": step_values,
                },
            )

    v, sources = _extract_capec_param(capec_refs, "Eq")
    if v is not None:
        return ParameterDerivation(
            value=v,
            source="capec_primary",
            confidence="high",
            provenance={"capec_ids": sources, "raw_max": v},
        )
    surfaces_set = {s.lower() for s in attack_surfaces}
    ptype = path_type.lower()

    if "remote_wireless" in ptype and "wireless_interface" in surfaces_set:
        eq_val = 3
        eq_source = "remote_wireless_standard_tools"
    elif ("physical_diagnostic" in ptype or "diagnostic_interface" in surfaces_set):
        eq_val = 2
        eq_source = "diagnostic_specialized_tools"
    elif "physical_hardware" in ptype:
        eq_val = 1
        eq_source = "physical_hardware_bespoke"
    elif "lateral_movement" in ptype and "in_vehicle_network" in surfaces_set:
        eq_val = 2
        eq_source = "can_bus_specialized_tools"
    else:
        eq_val = 1
        eq_source = "default_bespoke"

    sae_mod_applied = False
    sae_norm = heavens_sae_automation_level.upper().replace(" ", "_")
    if sae_norm in _SAE_HIGH_AUTOMATION and eq_val < 2:
        eq_val = 2
        sae_mod_applied = True

    return ParameterDerivation(
        value=eq_val,
        source="path_surface",
        confidence="medium",
        provenance={
            "path_type": path_type,
            "surfaces": list(attack_surfaces),
            "derived_source": eq_source,
            "sae_modifier_applied": sae_mod_applied,
            "sae_level": heavens_sae_automation_level,
        },
    )

def compute_path_feasibility(
    path: dict,
    threat_scenario: dict,
    attack_tree: dict,
    capec_enrichment: Optional[dict] = None,
) -> PathFeasibility:
    capec_refs: list[dict] = threat_scenario.get("capec_refs", [])
    threat_actor_classes: list[str] = threat_scenario.get("threat_actor_classes", [])
    attack_surfaces: list[str] = (
        threat_scenario.get("attack_surface_classes", [])
        or attack_tree.get("unique_surfaces", [])
    )
    is_direct: bool = bool(threat_scenario.get("is_directly_remote_reachable", False))
    is_transitive: bool = bool(threat_scenario.get("is_transitively_remote_reachable", False))

    heavens_ident = (
        threat_scenario.get("heavens_identification_purpose")
        or attack_tree.get("heavens_identification_purpose", "general_security_relevance")
    )
    heavens_cat = (
        threat_scenario.get("heavens_category")
        or attack_tree.get("heavens_category", "O")
    )
    heavens_fallback = (
        threat_scenario.get("heavens_fallback_profile_class")
        or attack_tree.get("heavens_fallback_profile_class", "unknown")
    )
    heavens_sae = (
        threat_scenario.get("heavens_sae_automation_level")
        or attack_tree.get("heavens_sae_automation_level", "SAE_L0_L4")
    )

    path_length: int = path.get("path_length", len(path.get("steps", [])))
    path_type: str = path.get("path_type", "unknown")
    path_steps: list[dict] = path.get("steps", [])

    se_d = _derive_SE(
        capec_refs, threat_actor_classes, path_type,
        path_steps=path_steps, capec_enrichment=capec_enrichment,
    )
    koic_d = _derive_KoIC(
        capec_refs, heavens_ident, heavens_cat,
        path_steps=path_steps, capec_enrichment=capec_enrichment,
    )
    woo_d = _derive_WoO(
        capec_refs, is_direct, is_transitive,
        attack_surfaces, heavens_fallback, heavens_sae,
        path_steps=path_steps, capec_enrichment=capec_enrichment,
    )
    eq_d = _derive_Eq(
        capec_refs, path_type, attack_surfaces, heavens_sae,
        path_steps=path_steps, capec_enrichment=capec_enrichment,
    )

    a_sum = se_d.value + koic_d.value + woo_d.value + eq_d.value
    a_norm = _norm(a_sum)
    rating = _rate(a_norm)

    return PathFeasibility(
        path_id=path.get("path_id", "unknown"),
        threat_id=path.get("threat_id", threat_scenario.get("threat_id", "")),
        path_type=path_type,
        path_length=path_length,
        SE=se_d,
        KoIC=koic_d,
        WoO=woo_d,
        Eq=eq_d,
        A_sum=a_sum,
        A_norm=round(a_norm, 6),
        rating=rating,
    )

def compute_pre_screen(threat_scenario: dict) -> str:
    if threat_scenario.get("is_directly_remote_reachable"):
        return "High"
    if threat_scenario.get("is_transitively_remote_reachable"):
        return "Medium"
    return "Low"

def compute_feasibility_for_tree(
    attack_tree: dict,
    attack_paths: list[dict],
    threat_scenarios: dict[str, dict],
    capec_enrichment: Optional[dict] = None,
) -> list[FeasibilityRecord]:
    """Emit ONE feasibility record per threat scenario covered by the tree.

    CORRECTED (v1.5.0). The previous implementation emitted a single record per
    attack *tree*, took max(A_norm) over paths belonging to ALL covered threat
    scenarios, and copied that rating to every threat via `covered_threat_ids`.
    A spoofing threat could therefore inherit the feasibility of a path realising
    an information-disclosure threat.

    That violates:
      ISO/SAE 21434 [RQ-08-11] NOTE 2 - the threat scenario aggregates the
          feasibility of *the corresponding* attack paths.
      HEAVENS 2.0 sec. 4.2.2 - threat scenarios are the direct children of the
          damage-scenario root, so each leaf-to-root attack path belongs to
          exactly one threat scenario.
      HEAVENS 2.0 Fig. 3 / sec. 4.2.5 - one risk value per threat scenario.

    Returns a list (possibly empty). Callers must iterate.
    """
    tree_id: str = attack_tree.get("tree_id", "")
    ds_id: str = attack_tree.get("damage_scenario_id", "")
    covered_ts_ids: list[str] = attack_tree.get("covered_threat_ids", [])

    tree_paths = [p for p in attack_paths if p.get("threat_id") in covered_ts_ids]
    eligible = [p for p in tree_paths if p.get("report_eligible", True)]
    render_paths = eligible if eligible else tree_paths

    # Partition the paths by the threat scenario that owns them.
    paths_by_threat: dict[str, list[dict]] = {ts_id: [] for ts_id in covered_ts_ids}
    for path in render_paths:
        ts_id = path.get("threat_id", "")
        if ts_id in paths_by_threat:
            paths_by_threat[ts_id].append(path)

    records: list[FeasibilityRecord] = []

    for ts_id in covered_ts_ids:
        ts = threat_scenarios.get(ts_id, {})
        pre_screen = compute_pre_screen(ts)
        own_paths = paths_by_threat.get(ts_id, [])

        if not own_paths:
            records.append(FeasibilityRecord(
                feasibility_id=_next_id(),
                threat_id=ts_id,
                damage_scenario_id=ds_id,
                tree_id=tree_id,
                target_asset_id=ts.get("target_asset_id", ""),
                target_asset_name=ts.get("target_asset_name", ""),
                covered_threat_ids=[ts_id],
                per_path_ratings=[],
                worst_path_id="",
                A_norm_max=0.0,
                attack_feasibility_rating="Very Low",
                pre_screen_rating=pre_screen,
                overall_confidence="fallback",
                heavens_controllability=attack_tree.get("heavens_controllability", "C0"),
                heavens_category=attack_tree.get("heavens_category", "O"),
                heavens_sae_automation_level=attack_tree.get("heavens_sae_automation_level", "SAE_L0_L4"),
                heavens_degradation_mode=attack_tree.get("heavens_degradation_mode", "safe_state_default"),
                heavens_fallback_profile_class=attack_tree.get("heavens_fallback_profile_class", "unknown"),
                heavens_identification_purpose=attack_tree.get("heavens_identification_purpose", "general_security_relevance"),
                rationale=(
                    f"No eligible attack paths for threat {ts_id} in tree {tree_id}. "
                    f"Rating defaults to Very Low."
                ),
                generator_version=GENERATOR_VERSION,
            ))
            continue

        per_path: list[PathFeasibility] = []
        for path in own_paths:
            pf = compute_path_feasibility(path, ts, attack_tree, capec_enrichment=capec_enrichment)
            per_path.append(pf)

        worst = max(per_path, key=lambda pf: pf.A_norm)

        all_confs: list[str] = []
        for pf in per_path:
            all_confs.extend([
                pf.SE.confidence,
                pf.KoIC.confidence,
                pf.WoO.confidence,
                pf.Eq.confidence,
            ])
        overall_conf = _confidence_min(*all_confs) if all_confs else "fallback"

        records.append(FeasibilityRecord(
            feasibility_id=_next_id(),
            threat_id=ts_id,
            damage_scenario_id=ds_id,
            tree_id=tree_id,
            target_asset_id=ts.get("target_asset_id", ""),
            target_asset_name=ts.get("target_asset_name", ""),
            covered_threat_ids=[ts_id],
            per_path_ratings=per_path,
            worst_path_id=worst.path_id,
            A_norm_max=round(worst.A_norm, 6),
            attack_feasibility_rating=worst.rating,
            pre_screen_rating=pre_screen,
            overall_confidence=overall_conf,
            heavens_controllability=attack_tree.get("heavens_controllability", "C0"),
            heavens_category=attack_tree.get("heavens_category", "O"),
            heavens_sae_automation_level=attack_tree.get("heavens_sae_automation_level", "SAE_L0_L4"),
            heavens_degradation_mode=attack_tree.get("heavens_degradation_mode", "safe_state_default"),
            heavens_fallback_profile_class=attack_tree.get("heavens_fallback_profile_class", "unknown"),
            heavens_identification_purpose=attack_tree.get("heavens_identification_purpose", "general_security_relevance"),
            rationale=(
                f"Feasibility for threat {ts_id} computed from {len(per_path)} of its own "
                f"eligible attack path(s) in tree {tree_id}. "
                f"Aggregation: max A_norm over this threat's paths "
                f"(ISO/SAE 21434 [RQ-08-11] NOTE 2; HEAVENS 2.0 sec. 4.2.5). "
                f"Worst path: {worst.path_id} "
                f"(A_norm={worst.A_norm:.4f}, rating={worst.rating}). "
                f"SE={worst.SE.value}[{worst.SE.source}] "
                f"KoIC={worst.KoIC.value}[{worst.KoIC.source}] "
                f"WoO={worst.WoO.value}[{worst.WoO.source}] "
                f"Eq={worst.Eq.value}[{worst.Eq.source}]. "
                f"Overall confidence: {overall_conf}."
            ),
            generator_version=GENERATOR_VERSION,
        ))

    return records

def compute_feasibility_all_threats(
    attack_trees: list[dict],
    attack_paths: list[dict],
    threat_scenarios: dict[str, dict],
    capec_enrichment: Optional[dict] = None,
) -> list[FeasibilityRecord]:
    """Compute exactly ONE feasibility record per threat scenario.

    HEAVENS 2.0 Fig. 3 requires a single risk value per threat scenario, and a
    threat scenario may lead to several damage scenarios (hence appear in several
    attack trees). Aggregating per (tree, threat) pair would emit the same threat
    several times with different ratings. Aggregation is therefore performed over
    ALL attack paths owned by the threat, across every tree, per
    ISO/SAE 21434 [RQ-08-11] NOTE 2.

    The attack tree contributes only the HEAVENS attributes of the damage
    scenario; the first tree covering the threat is used for those.
    """
    primary_tree: dict[str, dict] = {}
    for tree in attack_trees:
        for ts_id in tree.get("covered_threat_ids", []):
            primary_tree.setdefault(ts_id, tree)

    paths_by_threat: dict[str, list[dict]] = {}
    for path in attack_paths:
        paths_by_threat.setdefault(path.get("threat_id", ""), []).append(path)

    records: list[FeasibilityRecord] = []

    for ts_id in sorted(primary_tree.keys()):
        tree = primary_tree[ts_id]
        own = paths_by_threat.get(ts_id, [])
        eligible = [p for p in own if p.get("report_eligible", True)]
        render_paths = eligible if eligible else own

        stub = dict(tree)
        stub["covered_threat_ids"] = [ts_id]
        subset = compute_feasibility_for_tree(
            stub, render_paths, threat_scenarios,
            capec_enrichment=capec_enrichment,
        )
        records.extend(subset)

    return records


def feasibility_to_dict(record: FeasibilityRecord) -> dict:
    def _param_to_dict(p: ParameterDerivation) -> dict:
        return asdict(p)

    def _path_to_dict(pf: PathFeasibility) -> dict:
        return {
            "path_id": pf.path_id,
            "threat_id": pf.threat_id,
            "path_type": pf.path_type,
            "path_length": pf.path_length,
            "SE": _param_to_dict(pf.SE),
            "KoIC": _param_to_dict(pf.KoIC),
            "WoO": _param_to_dict(pf.WoO),
            "Eq": _param_to_dict(pf.Eq),
            "A_sum": pf.A_sum,
            "A_norm": pf.A_norm,
            "rating": pf.rating,
        }

    return {
        "feasibility_id": record.feasibility_id,
        "threat_id": record.threat_id,
        "damage_scenario_id": record.damage_scenario_id,
        "tree_id": record.tree_id,
        "target_asset_id": record.target_asset_id,
        "target_asset_name": record.target_asset_name,
        "covered_threat_ids": record.covered_threat_ids,
        "per_path_ratings": [_path_to_dict(pf) for pf in record.per_path_ratings],
        "worst_path_id": record.worst_path_id,
        "A_norm_max": record.A_norm_max,
        "attack_feasibility_rating": record.attack_feasibility_rating,
        "pre_screen_rating": record.pre_screen_rating,
        "overall_confidence": record.overall_confidence,
        "heavens_controllability": record.heavens_controllability,
        "heavens_category": record.heavens_category,
        "heavens_sae_automation_level": record.heavens_sae_automation_level,
        "heavens_degradation_mode": record.heavens_degradation_mode,
        "heavens_fallback_profile_class": record.heavens_fallback_profile_class,
        "heavens_identification_purpose": record.heavens_identification_purpose,
        "rationale": record.rationale,
        "generator_version": record.generator_version,
    }

if __name__ == "__main__":
    import sys
    from collections import Counter

    trees_path    = sys.argv[1] if len(sys.argv) > 1 else "attack_trees.json"
    paths_path    = sys.argv[2] if len(sys.argv) > 2 else "attack_paths.json"
    ts_path       = sys.argv[3] if len(sys.argv) > 3 else "threat_scenarios.json"
    out_path      = sys.argv[4] if len(sys.argv) > 4 else "attack_feasibility.json"
    enrichment_path = sys.argv[5] if len(sys.argv) > 5 else "capec_enrichment.json"

    with open(trees_path) as f:
        attack_trees: list[dict] = json.load(f)
    with open(paths_path) as f:
        attack_paths: list[dict] = json.load(f)
    with open(ts_path) as f:
        ts_raw = json.load(f)
    with open(enrichment_path) as f:
        capec_enrichment_data: dict = json.load(f)

    ts_list: list[dict] = (
        ts_raw.get("scenarios", ts_raw)
        if isinstance(ts_raw, dict)
        else ts_raw
    )
    ts_index: dict[str, dict] = {ts["threat_id"]: ts for ts in ts_list}

    _reset_counter()

    # v1.5.0: exactly one feasibility record per threat scenario, aggregated over
    # all of that threat's own attack paths across every tree.
    records = compute_feasibility_all_threats(
        attack_trees, attack_paths, ts_index,
        capec_enrichment=capec_enrichment_data,
    )
    results: list[dict] = [feasibility_to_dict(r) for r in records]

    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    total = len(results)
    rating_dist = Counter(r["attack_feasibility_rating"] for r in results)
    conf_dist = Counter(r["overall_confidence"] for r in results)
    no_paths = sum(1 for r in results if not r["per_path_ratings"])
    capec_primary_et = sum(
        1 for r in results
        for pf in r["per_path_ratings"]
        if pf["SE"]["source"] == "capec_primary"
    )
    total_path_ratings = sum(len(r["per_path_ratings"]) for r in results)

    print(f"[attack_feasibility_engine v{GENERATOR_VERSION}] "
          f"Generated {total} feasibility records → {out_path}")
    print(f"  Rating distribution:          {dict(rating_dist)}")
    print(f"  Confidence distribution:      {dict(conf_dist)}")
    print(f"  Records with no paths:        {no_paths}/{total}")
    print(f"  Total path-level ratings:     {total_path_ratings}")
    print(f"  SE from CAPEC primary:        {capec_primary_et}/{total_path_ratings}")

    # Fix B instrumentation — per-param source and raw/remapped value distributions
    from collections import defaultdict
    param_sources: dict[str, Counter] = defaultdict(Counter)
    param_raw:     dict[str, Counter] = defaultdict(Counter)
    param_remapped: dict[str, Counter] = defaultdict(Counter)
    woo_source_dist: Counter = Counter()

    for r in results:
        for pf in r["per_path_ratings"]:
            for param in ("SE", "KoIC", "WoO", "Eq"):
                pdata = pf[param]
                param_sources[param][pdata["source"]] += 1
                param_remapped[param][pdata["value"]] += 1
                raw = pdata.get("provenance", {}).get("raw_min")
                if raw is not None:
                    param_raw[param][raw] += 1
            woo_source_dist[pf["WoO"]["source"]] += 1

    print()
    print("  --- Per-param diagnostics (path-level) ---")
    for param in ("SE", "KoIC", "WoO", "Eq"):
        sources_str  = dict(sorted(param_sources[param].items()))
        remapped_str = dict(sorted(param_remapped[param].items()))
        raw_str      = dict(sorted(param_raw[param].items())) if param_raw[param] else "n/a"
        print(f"  {param:<5} sources={sources_str}")
        print(f"        raw_min_values={raw_str}")
        print(f"        remapped_values={remapped_str}")
    print(f"  WoO branch breakdown: {dict(woo_source_dist)}")