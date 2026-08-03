from __future__ import annotations

import hashlib
import json
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

GENERATOR_VERSION = "1.1.0"

_CONSEQUENCE_SFOP_SIGNALS_VERSION = "1.0.0"
_CONSEQUENCE_SFOP_SIGNALS_PROVENANCE = (
    "UN Regulation No. 155 Annex 5 (threat categories); "
    "HEAVENS 2.0 §3 (harm categories); "
    "ISO/SAE 21434:2021 §15 (damage scenario taxonomy); "
    "expert elicitation (automotive functional domain mapping)"
)

_EVIDENCE_TIER: dict[str, str] = {
    "node.harm_severity":        "T1",
    "node.financial_severity":   "T1",
    "node.operational_severity": "T1",
    "node.privacy_severity":     "T1",
    "sfop_domain_map":           "T2",
    "controllability_heuristic": "T3",
    "hardcoded_fallback":        "T4",
}

_EVIDENCE_CONFIDENCE: dict[str, str] = {
    "T1": "high",
    "T2": "medium",
    "T3": "low",
    "T4": "minimal",
}


@dataclass
class DamageScenario:
    damage_id: str
    internal_hash: str
    title: str
    description: str
    affected_assets: list[str]
    asset_summary: list[dict]
    affected_ecus: list[str]
    source_ontology_ids: list[str]
    ontology_node_label: str
    functional_domain: str
    dual_domain: Optional[str]
    functional_consequences: list[str]
    damage_seeds: list[str]
    r155_refs: list[str]
    capec_ids: list[str]
    sfop_category: str
    sfop_classification_provenance: dict
    harm_category: str
    impact_evidence: dict
    safety_level: str
    financial_impact: str
    operational_impact: str
    privacy_impact: str
    heavens_category: str
    heavens_controllability: str
    heavens_controllability_propagated: bool
    heavens_identification_purpose: str
    heavens_degradation_mode: str
    heavens_fallback_profile_class: str
    heavens_sae_automation_level: str
    heavens_damage_digest: str


_HEAVENS_CATEGORY_TO_SFOP: dict[str, str] = {
    "S": "Safety",
    "O": "Operational",
    "P": "Privacy",
    "F": "Financial",
}

_CTRL_ORDER: dict[str, int] = {"C3": 3, "C2": 2, "C1": 1, "C0": 0}
_HCAT_ORDER: dict[str, int] = {"S": 2, "O": 1, "P": 0, "F": 0}

_CONSEQUENCE_SFOP_SIGNALS: list[tuple[str, list[str]]] = [
    ("Safety",      ["safety_function_unavailability", "unintended_braking", "unintended_steering",
                     "uncontrolled_torque_output", "false_airbag_deployment", "airbag_suppression_in_collision",
                     "thermal_runaway_enablement", "hv_system_compromise", "sensor_data_spoofing",
                     "false_object_injection", "sensor_blinding", "safety_decision_corruption"]),
    ("Privacy",     ["covert_surveillance", "biometric_data_exfiltration", "occupant_state_falsification",
                     "presence_detection_bypass", "privacy_violation"]),
    ("Operational", ["authenticated_network_access_enabling_lateral_movement", "routing_manipulation",
                     "cross_domain_lateral_movement", "unauthorized_vehicle_unlock", "immobilizer_bypass",
                     "relay_attack_enablement", "authentication_bypass", "unauthorized_privileged_access",
                     "charging_system_manipulation", "service_disruption"]),
    ("Financial",   ["financial_fraud", "unauthorized_charging_access"]),
]

_HARM_CATEGORY_BY_SFOP: dict[str, str] = {
    "Safety":      "physical_harm",
    "Privacy":     "privacy_violation",
    "Operational": "operational_disruption",
    "Financial":   "financial_loss",
}

_SFOP_TITLE_VERB: dict[str, str] = {
    "Safety":      "causing physical harm via",
    "Privacy":     "enabling privacy violation via",
    "Operational": "disrupting operation of",
    "Financial":   "enabling financial fraud via",
}

_IMPACT_FALLBACKS: dict[str, dict[str, str]] = {
    "Safety":      {"safety_level": "S2", "financial_impact": "F0", "operational_impact": "O1", "privacy_impact": "P0"},
    "Privacy":     {"safety_level": "S0", "financial_impact": "F0", "operational_impact": "O1", "privacy_impact": "P2"},
    "Operational": {"safety_level": "S0", "financial_impact": "F1", "operational_impact": "O2", "privacy_impact": "P0"},
    "Financial":   {"safety_level": "S0", "financial_impact": "F2", "operational_impact": "O1", "privacy_impact": "P0"},
}

_CTRL_SAFETY_UPLIFT: dict[str, str] = {
    "C3": "S2",
    "C2": "S2",
    "C1": "S1",
    "C0": "S0",
}


def _file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _damage_internal_hash(ontology_id: str, sfop: str, domain: str, dual_domain: Optional[str]) -> str:
    canonical = json.dumps(
        {
            "ontology_id": ontology_id,
            "sfop": sfop,
            "domain": domain,
            "dual_domain": dual_domain if dual_domain else "",
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


_ds_counter: int = 0


def _reset_ds_counter() -> None:
    global _ds_counter
    _ds_counter = 0


def _next_ds_id() -> str:
    global _ds_counter
    _ds_counter += 1
    return f"DS-{_ds_counter:02d}"


def _damage_heavens_digest(
    ontology_id: str,
    sfop: str,
    heavens_category: str,
    controllability: str,
    degradation_mode: str,
) -> str:
    payload = json.dumps(
        {
            "ontology_id": ontology_id,
            "sfop": sfop,
            "heavens_category": heavens_category,
            "controllability": controllability,
            "degradation_mode": degradation_mode,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _extract_heavens(node: dict) -> dict:
    hp       = node.get("heavens_properties", {})
    ip       = hp.get("identification_purpose", {})
    ctrl     = hp.get("controllability", {})
    fallback = hp.get("fallback_mechanism", {})
    degrad   = hp.get("degradation_mode", {})
    sae      = hp.get("sae_automation_level", {})
    return {
        "heavens_category":                  ip.get("heavens_category", "O"),
        "heavens_controllability":           ctrl.get("rating", "C0"),
        "heavens_controllability_propagated":bool(ctrl.get("propagated", False)),
        "heavens_identification_purpose":    ip.get("purpose", "general_security_relevance"),
        "heavens_degradation_mode":          degrad.get("mode", "safe_state_default"),
        "heavens_fallback_profile_class":    fallback.get("profile_class", "unknown"),
        "heavens_sae_automation_level":      sae.get("level", "SAE_L0_L4"),
    }


def _resolve_sfop_classes(node: dict, heavens_ev: dict) -> tuple[set[str], dict[str, list[str]]]:
    sfop_classes: set[str] = set()
    triggered_signals: dict[str, list[str]] = {}

    primary_from_heavens = _HEAVENS_CATEGORY_TO_SFOP.get(heavens_ev["heavens_category"])
    if primary_from_heavens:
        sfop_classes.add(primary_from_heavens)

    node_sfop = node.get("sfop_primary_category")
    if node_sfop and node_sfop in _HEAVENS_CATEGORY_TO_SFOP.values():
        sfop_classes.add(node_sfop)

    conseq_set = set(node.get("functional_consequences", []))
    for sfop_class, signals in _CONSEQUENCE_SFOP_SIGNALS:
        matched = sorted(conseq_set & set(signals))
        if matched:
            sfop_classes.add(sfop_class)
            triggered_signals[sfop_class] = matched

    if not sfop_classes:
        sfop_classes.add("Operational")

    return sfop_classes, triggered_signals


def _resolve_harm_category(sfop: str, heavens_category: str) -> str:
    return _HARM_CATEGORY_BY_SFOP.get(sfop, "operational_disruption")


def _annotate_impact_entry(value: str, derived_from: str, sfop_map_tier: str) -> dict:
    tier = _EVIDENCE_TIER.get(derived_from, "T4")
    confidence = _EVIDENCE_CONFIDENCE.get(tier, "minimal")
    entry: dict = {
        "value":        value,
        "derived_from": derived_from,
        "evidence_tier": tier,
        "confidence":   confidence,
    }
    if derived_from == "sfop_domain_map":
        entry["sfop_map_tier"] = sfop_map_tier
    return entry


def _resolve_impact(
    node: dict,
    sfop: str,
    heavens_ev: dict,
    sfop_map: dict,
    sfop_map_tier: str,
    sfop_map_version: str,
    domain: str,
    dual_domain: Optional[str],
) -> tuple[str, str, str, str, dict]:
    node_harm_severity: dict       = node.get("harm_severity")        or {}
    node_financial_severity: dict  = node.get("financial_severity")   or {}
    node_operational_severity: dict = node.get("operational_severity") or {}
    node_privacy_severity: dict    = node.get("privacy_severity")     or {}

    ctrl = heavens_ev["heavens_controllability"]
    hcat = heavens_ev["heavens_category"]

    _SFOP_HARM_KEY: dict[str, str] = {
        "Safety":      "physical_harm",
        "Operational": "operational_disruption",
        "Privacy":     "operational_disruption",
        "Financial":   "operational_disruption",
    }
    harm_key = _SFOP_HARM_KEY.get(sfop, "physical_harm")

    safety_level = None
    derivation_safety = None

    if node_harm_severity:
        safety_level = (
            node_harm_severity.get("physical_harm")
            or node_harm_severity.get("safety_impact")
            or next(iter(node_harm_severity.values()), None)
        )
        if safety_level:
            derivation_safety = "node.harm_severity"

    sfop_entry = sfop_map.get(domain) or sfop_map.get(dual_domain or "") or {}
    sfop_harm_map: dict = sfop_entry.get("harm_severity") or {}

    if safety_level is None and sfop_harm_map:
        safety_level = sfop_harm_map.get(harm_key)
        if safety_level:
            derivation_safety = "sfop_domain_map"

    if safety_level is None and hcat == "S" and sfop == "Safety" and ctrl in _CTRL_SAFETY_UPLIFT:
        safety_level = _CTRL_SAFETY_UPLIFT[ctrl]
        derivation_safety = "controllability_heuristic"

    if safety_level is None:
        safety_level = _IMPACT_FALLBACKS[sfop]["safety_level"]
        derivation_safety = "hardcoded_fallback"

    if node_financial_severity:
        financial_impact = (
            node_financial_severity.get(harm_key)
            or next(iter(node_financial_severity.values()), None)
        )
        fin_deriv = "node.financial_severity"
    else:
        fin_map = sfop_entry.get("financial_severity") or {}
        financial_impact = fin_map.get(harm_key) or _IMPACT_FALLBACKS[sfop]["financial_impact"]
        fin_deriv = "sfop_domain_map" if fin_map else "hardcoded_fallback"

    if node_operational_severity:
        operational_impact = (
            node_operational_severity.get(harm_key)
            or next(iter(node_operational_severity.values()), None)
        )
        ops_deriv = "node.operational_severity"
    else:
        ops_map = sfop_entry.get("operational_severity") or {}
        operational_impact = ops_map.get(harm_key) or _IMPACT_FALLBACKS[sfop]["operational_impact"]
        ops_deriv = "sfop_domain_map" if ops_map else "hardcoded_fallback"

    if node_privacy_severity:
        privacy_impact = (
            node_privacy_severity.get(harm_key)
            or next(iter(node_privacy_severity.values()), None)
        )
        prv_deriv = "node.privacy_severity"
    else:
        prv_map = sfop_entry.get("privacy_severity") or {}
        privacy_impact = prv_map.get(harm_key) or _IMPACT_FALLBACKS[sfop]["privacy_impact"]
        prv_deriv = "sfop_domain_map" if prv_map else "hardcoded_fallback"

    impact_evidence = {
        "sfop_map_version": sfop_map_version,
        "safety_level":       _annotate_impact_entry(safety_level,       derivation_safety, sfop_map_tier),
        "financial_impact":   _annotate_impact_entry(financial_impact,   fin_deriv,         sfop_map_tier),
        "operational_impact": _annotate_impact_entry(operational_impact, ops_deriv,         sfop_map_tier),
        "privacy_impact":     _annotate_impact_entry(privacy_impact,     prv_deriv,         sfop_map_tier),
    }

    return safety_level, financial_impact, operational_impact, privacy_impact, impact_evidence


def _build_title(node: dict, sfop: str, heavens_ev: dict) -> str:
    ecus   = node.get("mapped_ecus", [])
    domain = node["functional_domain"]
    identification_purpose = heavens_ev.get("heavens_identification_purpose", "")
    subject = "/".join(ecus[:2]) if ecus else domain
    verb = _SFOP_TITLE_VERB.get(sfop, "compromising")
    purpose_tag = f" [{identification_purpose}]" if identification_purpose and identification_purpose != "general_security_relevance" else ""
    return f"Adversarial {verb} {subject} ({domain}){purpose_tag}"


def _build_description(node: dict, sfop: str, seeds: list[str], heavens_ev: dict) -> str:
    domain       = node["functional_domain"]
    dual_domain  = node.get("dual_domain")
    ecus         = node.get("mapped_ecus", [])
    conseq       = node.get("functional_consequences", [])
    degradation  = heavens_ev.get("heavens_degradation_mode", "safe_state_default")
    sae_level    = heavens_ev.get("heavens_sae_automation_level", "SAE_L0_L4")
    fallback     = heavens_ev.get("heavens_fallback_profile_class", "unknown")

    ecu_str    = ", ".join(ecus) if ecus else domain
    domain_str = f"{domain} / {dual_domain}" if dual_domain else domain
    seed_str   = "; ".join(seeds) if seeds else f"compromise of {domain}"
    conseq_str = "; ".join(conseq) if conseq else "unspecified functional impact"

    return (
        f"[{sfop}] Adversary targets {domain_str} implemented on {ecu_str}. "
        f"Damage initiators: {seed_str}. "
        f"Functional consequences: {conseq_str}. "
        f"Degradation response: {degradation} (fallback: {fallback}). "
        f"Operational context: {sae_level}."
    )


def _extract_r155_refs(node: dict) -> list[str]:
    return [
        src for src in node.get("provenance", {}).get("source", [])
        if "R155" in src or "Annex" in src
    ]


def _extract_capec_ids(node: dict) -> list[str]:
    return [str(ref["capec_id"]) for ref in node.get("capec_cwe_refs", [])]


def _derive_affected_ecus(asset_ids: list[str], asset_by_id: dict[str, dict]) -> list[str]:
    ecus: list[str] = []
    for aid in asset_ids:
        asset = asset_by_id.get(aid)
        if asset:
            for ecu in asset.get("mapped_ecus", []):
                if ecu not in ecus:
                    ecus.append(ecu)
    return ecus


def _build_asset_summary(asset_ids: list[str], asset_by_id: dict[str, dict]) -> list[dict]:
    summary = []
    for aid in asset_ids:
        asset = asset_by_id.get(aid)
        if asset:
            summary.append({
                "asset_id":   asset.get("asset_id", aid),
                "asset_name": asset.get("asset_name") or asset.get("name", ""),
                "trust_zone": asset.get("trust_zone", ""),
                "asset_type": asset.get("asset_type") or asset.get("type", ""),
            })
    return summary


def _build_asset_index(assets_raw: list[dict]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for a in assets_raw:
        oids = a.get("source_ontology_ids") or []
        if not oids and "source_ontology_id" in a:
            oids = [a["source_ontology_id"]]
        for oid in oids:
            index.setdefault(oid, []).append(a["asset_id"])
    return index


def generate_damage_scenarios(
    ontology_path: str | Path,
    assets_path: str | Path,
    sfop_map: Optional[dict] = None,
    sfop_map_version: Optional[str] = None,
) -> tuple[list[DamageScenario], dict]:
    ontology_path = Path(ontology_path)
    assets_path   = Path(assets_path)

    with open(ontology_path) as f:
        ontology = json.load(f)
    with open(assets_path) as f:
        assets_raw = json.load(f)

    sfop_map_is_fallback = sfop_map is None
    if sfop_map is None:
        from ontology_taxonomy_sfop_addition import SFOP_DOMAIN_MAP
        sfop_map = SFOP_DOMAIN_MAP
        if sfop_map_version is None:
            try:
                import ontology_taxonomy_sfop_addition as _sfop_mod
                sfop_map_version = getattr(_sfop_mod, "__version__", "unversioned")
            except Exception:
                sfop_map_version = "unversioned"

    sfop_map_tier    = "fallback_approximation" if sfop_map_is_fallback else "caller_supplied"
    sfop_map_version = sfop_map_version or "caller_supplied"

    generation_provenance = {
        "generator_version":                     GENERATOR_VERSION,
        "generated_at":                          datetime.now(timezone.utc).isoformat(),
        "consequence_sfop_signals_version":       _CONSEQUENCE_SFOP_SIGNALS_VERSION,
        "consequence_sfop_signals_provenance":    _CONSEQUENCE_SFOP_SIGNALS_PROVENANCE,
        "sfop_map_tier":                          sfop_map_tier,
        "sfop_map_version":                       sfop_map_version,
        "ontology_file": {
            "path":   str(ontology_path),
            "sha256": _file_sha256(ontology_path),
        },
        "assets_file": {
            "path":   str(assets_path),
            "sha256": _file_sha256(assets_path),
        },
    }

    asset_by_id: dict[str, dict]      = {a["asset_id"]: a for a in assets_raw}
    asset_index: dict[str, list[str]] = _build_asset_index(assets_raw)

    nodes: list[dict]               = sorted(ontology["nodes"], key=lambda n: n["ontology_id"])
    scenarios: list[DamageScenario] = []
    seen_hashes: set[str]           = set()
    collision_count: int            = 0
    _reset_ds_counter()

    for node in nodes:
        oid         = node["ontology_id"]
        domain      = node["functional_domain"]
        dual_domain = node.get("dual_domain")
        seeds       = node.get("damage_scenario_seeds", [])
        conseq      = node.get("functional_consequences", [])
        r155        = _extract_r155_refs(node)
        capecs      = _extract_capec_ids(node)
        node_label  = node.get("label") or node.get("name") or node.get("title") or oid

        heavens_ev               = _extract_heavens(node)
        sfop_classes, triggered  = _resolve_sfop_classes(node, heavens_ev)

        affected_asset_ids = asset_index.get(oid, [])
        affected_ecus      = _derive_affected_ecus(affected_asset_ids, asset_by_id)
        asset_summary      = _build_asset_summary(affected_asset_ids, asset_by_id)

        for sfop in sorted(sfop_classes):
            internal_hash = _damage_internal_hash(oid, sfop, domain, dual_domain)
            if internal_hash in seen_hashes:
                collision_count += 1
                warnings.warn(
                    f"Duplicate damage scenario skipped "
                    f"(ontology_id={oid}, sfop={sfop}, domain={domain})",
                    stacklevel=2,
                )
                continue
            seen_hashes.add(internal_hash)
            damage_id = _next_ds_id()

            harm_category = _resolve_harm_category(sfop, heavens_ev["heavens_category"])

            safety_level, financial_impact, operational_impact, privacy_impact, impact_evidence = _resolve_impact(
                node, sfop, heavens_ev, sfop_map, sfop_map_tier, sfop_map_version, domain, dual_domain
            )

            sfop_classification_provenance = {
                "heavens_category_source": heavens_ev["heavens_category"],
                "node_sfop_primary_category": node.get("sfop_primary_category"),
                "consequence_signals_triggered": triggered.get(sfop, []),
                "consequence_sfop_signals_version": _CONSEQUENCE_SFOP_SIGNALS_VERSION,
            }

            heavens_damage_digest = _damage_heavens_digest(
                oid,
                sfop,
                heavens_ev["heavens_category"],
                heavens_ev["heavens_controllability"],
                heavens_ev["heavens_degradation_mode"],
            )

            scenario = DamageScenario(
                damage_id=damage_id,
                internal_hash=internal_hash,
                title=_build_title(node, sfop, heavens_ev),
                description=_build_description(node, sfop, seeds, heavens_ev),
                affected_assets=affected_asset_ids,
                asset_summary=asset_summary,
                affected_ecus=affected_ecus,
                source_ontology_ids=[oid],
                ontology_node_label=node_label,
                functional_domain=domain,
                dual_domain=dual_domain,
                functional_consequences=conseq,
                damage_seeds=seeds,
                r155_refs=r155,
                capec_ids=capecs,
                sfop_category=sfop,
                sfop_classification_provenance=sfop_classification_provenance,
                harm_category=harm_category,
                impact_evidence=impact_evidence,
                safety_level=safety_level,
                financial_impact=financial_impact,
                operational_impact=operational_impact,
                privacy_impact=privacy_impact,
                heavens_category=heavens_ev["heavens_category"],
                heavens_controllability=heavens_ev["heavens_controllability"],
                heavens_controllability_propagated=heavens_ev["heavens_controllability_propagated"],
                heavens_identification_purpose=heavens_ev["heavens_identification_purpose"],
                heavens_degradation_mode=heavens_ev["heavens_degradation_mode"],
                heavens_fallback_profile_class=heavens_ev["heavens_fallback_profile_class"],
                heavens_sae_automation_level=heavens_ev["heavens_sae_automation_level"],
                heavens_damage_digest=heavens_damage_digest,
            )
            scenarios.append(scenario)

    generation_provenance["collision_count"] = collision_count
    return scenarios, generation_provenance


def scenarios_to_output(scenarios: list[DamageScenario], generation_provenance: dict) -> dict:
    return {
        "generation_provenance": generation_provenance,
        "scenarios": [asdict(s) for s in scenarios],
    }


if __name__ == "__main__":
    import sys
    from collections import Counter

    onto   = sys.argv[1] if len(sys.argv) > 1 else "functional_automotive_ontology.json"
    assets = sys.argv[2] if len(sys.argv) > 2 else "assets.json"
    out    = sys.argv[3] if len(sys.argv) > 3 else "damage_scenarios.json"

    scenarios, provenance = generate_damage_scenarios(onto, assets)
    result = scenarios_to_output(scenarios, provenance)

    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[damage_scenario_generator] Generated {len(scenarios)} damage scenarios → {out}")

    ecu_coverage = sum(1 for s in scenarios if s.affected_ecus)
    print(f"  Scenarios with affected_ecus:      {ecu_coverage}/{len(scenarios)}")

    sfop_dist   = Counter(s.sfop_category            for s in scenarios)
    slvl_dist   = Counter(s.safety_level              for s in scenarios)
    ctrl_dist   = Counter(s.heavens_controllability   for s in scenarios)
    hcat_dist   = Counter(s.heavens_category          for s in scenarios)
    harm_dist   = Counter(s.harm_category             for s in scenarios)
    degrad_dist = Counter(s.heavens_degradation_mode  for s in scenarios)

    print(f"  SFOP distribution:                 {dict(sfop_dist)}")
    print(f"  Safety level distribution:         {dict(slvl_dist)}")
    print(f"  Controllability distribution:      {dict(ctrl_dist)}")
    print(f"  HEAVENS category distribution:     {dict(hcat_dist)}")
    print(f"  Harm category distribution:        {dict(harm_dist)}")
    print(f"  Degradation mode distribution:     {dict(degrad_dist)}")

    derivation_sources = Counter(
        s.impact_evidence.get("safety_level", {}).get("derived_from", "unknown")
        for s in scenarios
    )
    print(f"  Safety level derivation sources:   {dict(derivation_sources)}")

    tier_dist = Counter(
        s.impact_evidence.get("safety_level", {}).get("evidence_tier", "unknown")
        for s in scenarios
    )
    print(f"  Safety level evidence tier dist:   {dict(tier_dist)}")

    seeds_present = sum(1 for s in scenarios if s.damage_seeds)
    print(f"  Scenarios with damage seeds:       {seeds_present}/{len(scenarios)}")

    collision_count = provenance.get("collision_count", 0)
    if collision_count:
        print(f"  Duplicate ID collisions skipped:   {collision_count}")