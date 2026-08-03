from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
from typing import Optional


@dataclass
class Asset:
    asset_id: str
    internal_hash: str
    name: str
    qualified_name: str
    asset_type: str
    category: str                                                               
    ciaa_properties: dict
    cia_properties: list[str]                                                        
    authorization_properties: list[str]                                             
    source_ontology_ids: list[str]
    source_functional_domains: list[str]
    source_subdomains: list[str]
    mapped_ecus: list[str]
    mapped_interfaces: list[str]
    attack_surface_classes: list[str]
    r155_refs: list[str]
    capec_ids: list[str]
    harm_relevance: str

    heavens_category: str
    heavens_controllability: str
    heavens_controllability_propagated: bool
    heavens_identification_purpose: str
    heavens_fallback_profile_class: str
    heavens_degradation_mode: str
    heavens_sae_automation_level: str

    heavens_asset_digest: str

    heavens_ctrl_source_ontology_id: str
    heavens_hcat_source_ontology_id: str

    damage_scenario_seeds: list[str]
    rationale: str


_CIAA_PROPERTIES = frozenset({"Confidentiality", "Integrity", "Availability", "Authenticity"})
_AUTHORIZATION_PROPERTY = "Authorization"
_ALL_KNOWN_CIA = _CIAA_PROPERTIES | {_AUTHORIZATION_PROPERTY}


_CIA_TYPE_MAP: list[tuple[str, str, str]] = [

    ("Integrity",        "messages",               "data"),
    ("Integrity",        "routing_rules",           "parameter"),
    ("Integrity",        "firewall_policy",         "parameter"),
    ("Integrity",        "firmware",                "firmware"),
    ("Integrity",        "calibration",             "parameter"),
    ("Integrity",        "torque_commands",         "data"),
    ("Integrity",        "control_signals",         "data"),
    ("Integrity",        "sensor_data",             "data"),
    ("Integrity",        "deployment_logic",        "function"),
    ("Integrity",        "timing_signals",          "data"),
    ("Availability",     "service",                 "function"),
    ("Availability",     "bus",                     "function"),
    ("Authorization",    "cross_domain_sessions",   "session"),
    ("Authorization",    "policy_rules",            "parameter"),
    ("Authorization",    "uds_sessions",            "session"),
    ("Authorization",    "privileged_sessions",     "session"),
    ("Authenticity",     "messages",                "data"),
    ("Authenticity",     "firmware",                "firmware"),
    ("Authenticity",     "certificates",            "key"),
    ("Confidentiality",  "biometric_data",          "data"),
    ("Confidentiality",  "occupant_data",           "data"),
    ("Confidentiality",  "video_streams",           "data"),
    ("Confidentiality",  "radar_data",              "data"),
    ("Confidentiality",  "cryptographic_keys",      "key"),
    ("Confidentiality",  "security_credentials",    "key"),
]

_DEFAULT_TYPE_BY_CIA: dict[str, str] = {
    "Integrity":        "data",
    "Availability":     "function",
    "Authorization":    "session",
    "Authenticity":     "data",
    "Confidentiality":  "data",
}


_CATEGORY_BY_TYPE: dict[str, str] = {
    "data":      "data",
    "parameter": "parameter",
    "function":  "functional",
    "firmware":  "firmware",                     
    "key":       "key",                          
    "session":   "communication",
}


_HEAVENS_CATEGORY_TO_HARM: dict[str, str] = {
    "S": "safety",
    "O": "operational",
    "P": "privacy",
    "F": "financial",
}

_DOMAIN_HARM_FALLBACK: dict[str, str] = {
    "NETWORK_GATEWAYING":        "operational",
    "AUTOMATED_DRIVING_CONTROL": "safety",
    "PERCEPTION_AND_SENSING":    "safety",
    "VEHICLE_MOTION_CONTROL":    "safety",
    "OCCUPANT_SAFETY_SYSTEMS":   "safety",
    "POWERTRAIN_MANAGEMENT":     "safety",
    "VEHICLE_ACCESS_CONTROL":    "operational",
    "DIAGNOSTIC_AND_SERVICE":    "operational",
    "BIOMETRIC_MONITORING":      "privacy",
    "CHARGING_AND_ENERGY":       "operational",
}


_CTRL_ORDER:  dict[str, int] = {"C3": 3, "C2": 2, "C1": 1, "C0": 0}
_HCAT_ORDER:  dict[str, int] = {"S": 2, "O": 1, "P": 0}

_GENERIC_NAMES: frozenset[str] = frozenset({
    "messages", "service", "commands", "control_signals", "configuration",
    "data", "signals", "parameters", "frames", "packets",
})


def _asset_internal_hash(
    qualified_name: str,
    cia: str,
    domain: str,
    dual_domain: Optional[str],
) -> str:
    canonical = json.dumps(
        {
            "qualified_name": qualified_name,
            "cia": cia,
            "domain": domain,
            "dual_domain": dual_domain if dual_domain else "",
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


_ast_counter: int = 0


def _reset_ast_counter() -> None:
    global _ast_counter
    _ast_counter = 0


def _next_ast_id() -> str:
    global _ast_counter
    _ast_counter += 1
    return f"AST-{_ast_counter:02d}"


def _asset_heavens_digest(
    all_oids: list[str],
    all_domains: list[str],
    all_subdomains: list[str],
    ctrl_rating: str,
    heavens_category: str,
) -> str:
    payload = json.dumps(
        {
            "ontology_ids": sorted(all_oids),
            "domains":      sorted(all_domains),
            "subdomains":   sorted(all_subdomains),
            "controllability": ctrl_rating,
            "heavens_category": heavens_category,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _resolve_asset_type(cia: str, asset_keyword: str) -> str:
    for (c, k, t) in _CIA_TYPE_MAP:
        if c == cia and k in asset_keyword:
            return t
    return _DEFAULT_TYPE_BY_CIA.get(cia, "data")


def _build_ciaa_dict(ciaa_props: list[str]) -> dict:
    return {
        "confidentiality": "Confidentiality" in ciaa_props,
        "integrity":       "Integrity"       in ciaa_props,
        "availability":    "Availability"    in ciaa_props,
        "authenticity":    "Authenticity"    in ciaa_props,
    }


def _split_cia_properties(
    raw_cia_list: list[str],
    trigger_cia: str,
) -> tuple[list[str], list[str]]:
    """
    Partition a raw CIA list into:
      - ciaa_props: members of _CIAA_PROPERTIES  (Confidentiality / Integrity /
                    Availability / Authenticity)
      - auth_props: Authorization entries

    The trigger CIA is prepended to its appropriate list if not already present,
    ensuring the property that caused this asset to be enumerated is always
    represented.
    """
    ciaa_props: list[str] = []
    auth_props: list[str] = []

    for prop in raw_cia_list:
        if prop in _CIAA_PROPERTIES:
            if prop not in ciaa_props:
                ciaa_props.append(prop)
        elif prop == _AUTHORIZATION_PROPERTY:
            if prop not in auth_props:
                auth_props.append(prop)

    if trigger_cia in _CIAA_PROPERTIES and trigger_cia not in ciaa_props:
        ciaa_props = [trigger_cia] + ciaa_props
    elif trigger_cia == _AUTHORIZATION_PROPERTY and trigger_cia not in auth_props:
        auth_props = [trigger_cia] + auth_props

    return ciaa_props, auth_props


def _extract_r155_refs(node: dict) -> list[str]:
    refs = []
    for src in node.get("provenance", {}).get("source", []):
        if "R155" in src or "Annex" in src:
            refs.append(src)
    return refs


def _extract_capec_ids(node: dict) -> list[str]:
    return [str(ref["capec_id"]) for ref in node.get("capec_cwe_refs", [])]


def _primary_ecu_label(ecus: list[str], domain: str) -> str:
    if not ecus:
        return domain.replace("_", " ").title()
    if len(ecus) == 1:
        return ecus[0]
    return f"{ecus[0]}+{len(ecus)-1}"


def _qualify_name(raw_name: str, ecus: list[str], domain: str) -> str:
    if raw_name in _GENERIC_NAMES:
        label = _primary_ecu_label(ecus, domain)
        return f"{label}.{raw_name}"
    return raw_name


def _merge_key(
    cia: str,
    raw_name: str,
    domain: str,
    dual_domain: Optional[str],
) -> str:
    dual_part = dual_domain if dual_domain else "__none__"
    return f"{domain}::{dual_part}::{cia}::{raw_name}"


def _extract_heavens_evidence(node: dict) -> dict:
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
        "heavens_fallback_profile_class":    fallback.get("profile_class", "unknown"),
        "heavens_degradation_mode":          degrad.get("mode", "safe_state_default"),
        "heavens_sae_automation_level":      sae.get("level", "SAE_L0_L4"),
    }


def _merge_heavens_evidence(
    entries: list[tuple[dict, str, str, str]],
) -> dict:
    best_ctrl_rank  = -1
    best_hcat_rank  = -1
    best_ev: dict   = {}
    ctrl_source_oid = ""
    hcat_source_oid = ""

    for node, oid, _cia, _kw in entries:
        ev        = _extract_heavens_evidence(node)
        ctrl_rank = _CTRL_ORDER.get(ev["heavens_controllability"], 0)
        hcat_rank = _HCAT_ORDER.get(ev["heavens_category"], 0)

        if ctrl_rank > best_ctrl_rank:
            best_ctrl_rank  = ctrl_rank
            best_ev         = dict(ev)
            ctrl_source_oid = oid

        if hcat_rank > best_hcat_rank:
            best_hcat_rank  = hcat_rank
            best_ev["heavens_category"] = ev["heavens_category"]
            hcat_source_oid = oid

    if not best_ev:
        best_ev = {
            "heavens_category":                  "O",
            "heavens_controllability":           "C0",
            "heavens_controllability_propagated": False,
            "heavens_identification_purpose":    "general_security_relevance",
            "heavens_fallback_profile_class":    "unknown",
            "heavens_degradation_mode":          "safe_state_default",
            "heavens_sae_automation_level":      "SAE_L0_L4",
        }

    best_ev["heavens_ctrl_source_ontology_id"] = ctrl_source_oid
    best_ev["heavens_hcat_source_ontology_id"] = hcat_source_oid
    return best_ev


def _derive_harm_relevance(
    heavens_category: str,
    domain: str,
    dual_domain: Optional[str],
) -> str:
    primary = _HEAVENS_CATEGORY_TO_HARM.get(heavens_category)
    if primary:
        return primary
    return (
        _DOMAIN_HARM_FALLBACK.get(domain)
        or _DOMAIN_HARM_FALLBACK.get(dual_domain or "")
        or "operational"
    )


_INSTANCE_SUFFIX_RE = re.compile(r"\s*[\(\[][^\)\]]+[\)\]]\s*$")


def _normalise_seed(seed: str) -> str:
    normalised = _INSTANCE_SUFFIX_RE.sub("", seed)
    return " ".join(normalised.lower().split())


def _aggregate_damage_seeds(
    entries: list[tuple[dict, str, str, str]],
) -> list[str]:
    seen_normalised: dict[str, str] = {}                                     
    for node, _oid, _cia, _kw in entries:
        for seed in node.get("damage_scenario_seeds", []):
            norm = _normalise_seed(seed)
            if norm not in seen_normalised:
                seen_normalised[norm] = seed
    return list(seen_normalised.values())


def enumerate_assets(ontology_path: str | Path) -> list[Asset]:
    with open(ontology_path) as f:
        ontology = json.load(f)

    nodes: list[dict] = sorted(ontology["nodes"], key=lambda n: n["ontology_id"])

    merge_buckets: dict[str, list[tuple[dict, str, str, str]]] = defaultdict(list)

    for node in nodes:
        oid         = node["ontology_id"]
        domain      = node["functional_domain"]
        dual_domain = node.get("dual_domain")
        asset_target: dict[str, list[str]] = node.get("asset_target_properties", {})
        for cia, keywords in sorted(asset_target.items()):
            for kw in sorted(keywords):
                mk = _merge_key(cia, kw, domain, dual_domain)
                merge_buckets[mk].append((node, oid, cia, kw))

    assets: list[Asset] = []
    seen_hashes: set[str] = set()
    _reset_ast_counter()

    for mk, entries in sorted(merge_buckets.items()):
        first_node, _first_oid, cia, raw_kw = entries[0]

        all_oids       = list(dict.fromkeys(e[1]                      for e in entries))
        all_domains    = list(dict.fromkeys(e[0]["functional_domain"]  for e in entries))
        all_ecus:       list[str] = []
        all_interfaces: list[str] = []
        all_surfaces:   list[str] = []
        all_subdomains: list[str] = []
        all_r155:       list[str] = []
        all_capec:      list[str] = []

        for node, _oid, _, _ in entries:
            for ecu in node.get("mapped_ecus", []):
                if ecu not in all_ecus:        all_ecus.append(ecu)
            for iface in node.get("mapped_interfaces", []):
                if iface not in all_interfaces: all_interfaces.append(iface)
            for surf in node.get("attack_surface_classes", []):
                if surf not in all_surfaces:   all_surfaces.append(surf)
            for sd in node.get("subdomains", []):
                if sd not in all_subdomains:   all_subdomains.append(sd)
            for ref in _extract_r155_refs(node):
                if ref not in all_r155:        all_r155.append(ref)
            for cid in _extract_capec_ids(node):
                if cid not in all_capec:       all_capec.append(cid)

        domain      = first_node["functional_domain"]
        dual_domain = first_node.get("dual_domain") or None


        heavens_ev = _merge_heavens_evidence(entries)


        asset_digest = _asset_heavens_digest(
            all_oids,
            all_domains,
            all_subdomains,
            heavens_ev["heavens_controllability"],
            heavens_ev["heavens_category"],
        )


        harm = _derive_harm_relevance(
            heavens_ev["heavens_category"],
            domain,
            dual_domain,
        )


        cia_props_node = first_node.get("cybersecurity_properties", {})
        raw_cia_list   = (
            cia_props_node.get("primary", []) + cia_props_node.get("secondary", [])
        )
        ciaa_props, auth_props = _split_cia_properties(raw_cia_list, cia)

        asset_type     = _resolve_asset_type(cia, raw_kw)
        category       = _CATEGORY_BY_TYPE.get(asset_type, "data")
        qualified_name = _qualify_name(raw_kw, all_ecus, domain)
        merged         = len(entries) > 1


        damage_seeds = _aggregate_damage_seeds(entries)


        internal_hash = _asset_internal_hash(qualified_name, cia, domain, dual_domain)
        if internal_hash in seen_hashes:
            continue
        seen_hashes.add(internal_hash)
        asset_id = _next_ast_id()

        dual_note = f" [dual_domain={dual_domain}]" if dual_domain else ""
        rationale = (
            f"Derived from {', '.join(all_oids)} ({', '.join(all_domains)}) "
            f"asset_target_properties[{cia}]. "
            f"Subdomains: {all_subdomains}. "
            f"Harm relevance: {harm} "
            f"(heavens_category={heavens_ev['heavens_category']}, "
            f"source={heavens_ev['heavens_hcat_source_ontology_id']}). "
            f"Controllability={heavens_ev['heavens_controllability']} "
            f"(source={heavens_ev['heavens_ctrl_source_ontology_id']})."
            f"{dual_note}"
            + (" [merged]" if merged else "")
        )

        asset = Asset(
            asset_id=asset_id,
            internal_hash=internal_hash,
            name=raw_kw,
            qualified_name=qualified_name,
            asset_type=asset_type,
            category=category,
            ciaa_properties=_build_ciaa_dict(ciaa_props),
            cia_properties=ciaa_props,
            authorization_properties=auth_props,
            source_ontology_ids=all_oids,
            source_functional_domains=all_domains,
            source_subdomains=all_subdomains,
            mapped_ecus=all_ecus,
            mapped_interfaces=all_interfaces,
            attack_surface_classes=all_surfaces,
            r155_refs=all_r155,
            capec_ids=all_capec,
            harm_relevance=harm,
            heavens_category=heavens_ev["heavens_category"],
            heavens_controllability=heavens_ev["heavens_controllability"],
            heavens_controllability_propagated=heavens_ev["heavens_controllability_propagated"],
            heavens_identification_purpose=heavens_ev["heavens_identification_purpose"],
            heavens_fallback_profile_class=heavens_ev["heavens_fallback_profile_class"],
            heavens_degradation_mode=heavens_ev["heavens_degradation_mode"],
            heavens_sae_automation_level=heavens_ev["heavens_sae_automation_level"],
            heavens_asset_digest=asset_digest,
            heavens_ctrl_source_ontology_id=heavens_ev["heavens_ctrl_source_ontology_id"],
            heavens_hcat_source_ontology_id=heavens_ev["heavens_hcat_source_ontology_id"],
            damage_scenario_seeds=damage_seeds,
            rationale=rationale,
        )
        assets.append(asset)

    return assets


def assets_to_dict(assets: list[Asset]) -> list[dict]:
    return [asdict(a) for a in assets]


if __name__ == "__main__":
    import sys
    from collections import Counter

    onto = sys.argv[1] if len(sys.argv) > 1 else "functional_automotive_ontology.json"
    out  = sys.argv[2] if len(sys.argv) > 2 else "assets.json"

    assets = enumerate_assets(onto)
    result = assets_to_dict(assets)

    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[asset_enumerator] Enumerated {len(assets)} assets → {out}")

    types = Counter(a.asset_type for a in assets)
    for t, c in sorted(types.items()):
        print(f"  asset_type {t:20s}: {c}")

    cats = Counter(a.category for a in assets)
    for c, n in sorted(cats.items()):
        print(f"  category   {c:20s}: {n}")

    ciaa_counts = {
        k: sum(1 for a in assets if a.ciaa_properties.get(k))
        for k in ["confidentiality", "integrity", "availability", "authenticity"]
    }
    print(f"  CIAA coverage: {ciaa_counts}")

    auth_assets = sum(1 for a in assets if a.authorization_properties)
    print(f"  Assets with Authorization properties: {auth_assets}")

    hcat_counts = Counter(a.heavens_category for a in assets)
    print(f"  HEAVENS categories: {dict(hcat_counts)}")

    ctrl_counts = Counter(a.heavens_controllability for a in assets)
    print(f"  Controllability ratings: {dict(ctrl_counts)}")

    harm_counts = Counter(a.harm_relevance for a in assets)
    print(f"  Harm relevance: {dict(harm_counts)}")

    seeds_present = sum(1 for a in assets if a.damage_scenario_seeds)
    print(f"  Assets with damage seeds: {seeds_present}/{len(assets)}")

    fw_key = sum(1 for a in assets if a.category in ("firmware", "key"))
    print(f"  Firmware + key category assets: {fw_key}")