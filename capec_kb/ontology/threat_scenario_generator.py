from __future__ import annotations

import hashlib
import json
import warnings
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

GENERATOR_VERSION = "2.0.0"

_CONSEQUENCE_SFOP_SIGNALS_VERSION = "1.0.0"

_CIA_TO_CAPEC_SCOPES: dict[str, list[str]] = {
    "Confidentiality": ["Confidentiality"],
    "Integrity":       ["Integrity"],
    "Availability":    ["Availability"],
    "Authorization":   ["Authorization", "Access Control"],
    "Authenticity":    ["Authentication", "Non-Repudiation"],
}

_CIA_TO_PRIMARY_STRIDE: dict[str, str] = {
    "Authenticity":    "Spoofing",
    "Integrity":       "Tampering",
    "Confidentiality": "Information Disclosure",
    "Availability":    "DoS",
    "Authorization":   "Elevation of Privilege",
}

_STRIDE_TO_CIA: dict[str, str] = {
    "Spoofing":              "Authenticity",
    "Tampering":             "Integrity",
    "Repudiation":           "Authenticity",
    "Information Disclosure":"Confidentiality",
    "DoS":                   "Availability",
    "Elevation of Privilege":"Authorization",
}

_VALID_STRIDE: frozenset[str] = frozenset(_STRIDE_TO_CIA.keys())

_ATTACKER_PROFILE_TO_SURFACE: dict[str, str] = {
    "remote":   "remote_network",
    "local":    "wireless_interface",
    "physical": "physical_access",
}

_IFACE_TYPE_TO_SURFACE: dict[str, str] = {
    "diagnostic": "diagnostic_interface",
    "network":    "remote_network",
    "wireless":   "wireless_interface",
    "sensor":     "physical_access",
    "actuator":   "physical_access",
}

_PREFERRED_ABSTRACTIONS: frozenset[str] = frozenset({"Standard", "Detailed"})


_SURFACE_CAPEC_KEYWORDS: dict[str, list[str]] = {
    "remote_network":       ["network attack", "remote exploit", "remote access",
                             "man-in-the-middle", "eavesdrop", "intercept",
                             "tcp ", "udp ", "http", "dns ", "replay attack",
                             "packet injection", "network injection", "api abuse",
                             "remote code"],
    "wireless_interface":   ["wireless", "bluetooth", "wi-fi", "wifi",
                             "cellular", "radio frequency", "zigbee",
                             "jamming", "rf attack", "signal spoofing",
                             "wireless replay"],
    "diagnostic_interface": ["diagnostic", "obd-ii", "obd2", "uart", "jtag",
                             "debug port", "firmware update", "bootloader",
                             "flash memory", "in-circuit"],
    "physical_access":      ["physical access", "hardware attack",
                             "side-channel", "fault injection", "power glitch",
                             "tamper", "cold boot", "hardware probe"],
    "in_vehicle_network":   ["can bus", "can frame", "lin bus", "flexray",
                             "automotive ethernet", "in-vehicle network",
                             "gateway bypass", "bus arbitration",
                             "obd port"],
}

_EVIDENCE_TIER: dict[str, str] = {
    "capec_consequences_scope_match": "T1",
    "capec_hierarchy_parent":         "T2",
    "capec_name_keyword_match":       "T3",
    "no_capec_evidence":              "T4",
}

_EVIDENCE_CONFIDENCE: dict[str, str] = {
    "T1": "high",
    "T2": "medium",
    "T3": "low",
    "T4": "minimal",
}

_REMOTE_ATTACKER_PROFILES: frozenset[str] = frozenset({"remote", "local"})

@dataclass
class ThreatScenario:
    threat_id: str
    internal_hash: str
    title: str
    description: str
    target_asset_id: str
    target_asset_name: str
    target_asset_qualified_name: str
    target_asset_trust_zone: str
    target_asset_type: str
    compromised_property: str
    attack_action: str
    source_ontology_id: str
    ontology_node_label: str
    functional_domain: str
    damage_scenario_ids: list[str]
    stride_categories: list[str]
    capec_refs: list[dict]
    capec_selection_evidence: str
    capec_selection_tier: str
    capec_selection_confidence: str
    r155_refs: list[str]
    threat_actor_classes: list[str]
    attack_surface_classes: list[str]
    entry_point_types: list[str]
    is_directly_remote_reachable: bool
    is_transitively_remote_reachable: bool
    remote_reachability_path: list[str]
    mapped_ecus: list[str]
    mapped_interfaces: list[str]
    heavens_category: str
    heavens_controllability: str
    heavens_controllability_propagated: bool
    heavens_identification_purpose: str
    heavens_degradation_mode: str
    heavens_fallback_profile_class: str
    heavens_sae_automation_level: str
    traceability: dict

def _file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def _threat_internal_hash(
    ontology_id: str,
    cia: str,
    asset_id: str,
) -> str:
    canonical = json.dumps(
        {"ontology_id": ontology_id, "cia": cia, "asset_id": asset_id},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


_ts_counter: int = 0


def _reset_ts_counter() -> None:
    global _ts_counter
    _ts_counter = 0


def _next_ts_id() -> str:
    global _ts_counter
    _ts_counter += 1
    return f"TS-{_ts_counter:02d}"

def _extract_heavens(node: dict) -> dict:
    hp      = node.get("heavens_properties", {})
    ip      = hp.get("identification_purpose", {})
    ctrl    = hp.get("controllability", {})
    fallbk  = hp.get("fallback_mechanism", {})
    degrad  = hp.get("degradation_mode", {})
    sae     = hp.get("sae_automation_level", {})
    return {
        "heavens_category":                   ip.get("heavens_category", "O"),
        "heavens_controllability":            ctrl.get("rating", "C0"),
        "heavens_controllability_propagated": bool(ctrl.get("propagated", False)),
        "heavens_identification_purpose":     ip.get("purpose", "general_security_relevance"),
        "heavens_degradation_mode":           degrad.get("mode", "safe_state_default"),
        "heavens_fallback_profile_class":     fallbk.get("profile_class", "unknown"),
        "heavens_sae_automation_level":       sae.get("level", "SAE_L0_L4"),
    }

def _build_capec_index_by_scope(
    capec_nodes: list[dict],
    capec_enrichment: dict[str, dict],
) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = defaultdict(list)
    for node in capec_nodes:
        if node.get("abstraction") not in _PREFERRED_ABSTRACTIONS:
            continue
        cid = str(node["capec_id"])
        node_scopes: set[str] = set()
        for c in node.get("consequences", []):
            node_scopes.update(c.get("scopes", []))
        if not node_scopes:
            continue
        enriched = _enrich_capec(cid, node, capec_enrichment)
        for scope in node_scopes:
            index[scope].append(enriched)
    return index

def _build_capec_lookup(
    capec_nodes: list[dict],
    capec_enrichment: dict[str, dict],
) -> dict[str, dict]:
    return {
        str(n["capec_id"]): _enrich_capec(str(n["capec_id"]), n, capec_enrichment)
        for n in capec_nodes
    }

def _enrich_capec(cid: str, node: dict, capec_enrichment: dict[str, dict]) -> dict:
    e = capec_enrichment.get(cid, {})
    return {
        "capec_id":        cid,
        "name":            node.get("name", ""),
        "abstraction":     node.get("abstraction", ""),
        "likelihood":      node.get("likelihood", ""),
        "severity":        node.get("severity", ""),
        "ET":              e.get("ET"),
        "SE":              e.get("SE"),
        "KoIC":            e.get("KoIC"),
        "WoO":             e.get("WoO"),
        "Eq":              e.get("Eq"),
        "derivation_trace":e.get("derivation_trace", {}),
        "capec_version":   e.get("capec_version", ""),
    }

def _surface_relevance_score(entry: dict, attack_surface_classes: list[str]) -> int:
    """Return count of surface-keyword hits in CAPEC name+description.

    Higher score → CAPEC is more relevant to the specific attack surfaces
    of this scenario, allowing selection to vary across scenarios even when
    CIA property is the same.
    """
    if not attack_surface_classes:
        return 0
    text = (entry.get("name", "") + " " + entry.get("description", "")).lower()

    score = 0
    for surface in attack_surface_classes:
        for kw in _SURFACE_CAPEC_KEYWORDS.get(surface, []):
            if kw in text:
                score += 1
    return score


def _select_capec_for_cia(
    cia: str,
    attack_surface_classes: list[str],
    capec_index_by_scope: dict[str, list[dict]],
    capec_lookup: dict[str, dict],
    capec_nodes: list[dict],
    max_results: int = 5,
) -> tuple[list[dict], str, str, str]:
    target_scopes = _CIA_TO_CAPEC_SCOPES.get(cia, [])
    candidates: dict[str, dict] = {}

    for scope in target_scopes:
        for entry in capec_index_by_scope.get(scope, []):
            cid = entry["capec_id"]
            if cid not in candidates:
                candidates[cid] = entry

    if candidates:
        ranked = sorted(
            candidates.values(),
            key=lambda e: (

                -_surface_relevance_score(e, attack_surface_classes),

                1 if e.get("abstraction") == "Standard" else 2,

                -(e.get("ET") or 0),
            ),
        )[:max_results]
        evidence = "capec_consequences_scope_match"
        tier = _EVIDENCE_TIER[evidence]
        confidence = _EVIDENCE_CONFIDENCE[tier]
        return ranked, evidence, tier, confidence

    parent_ids: set[str] = set()
    scope_set = set(target_scopes)
    for node in capec_nodes:
        for rel in node.get("relationships", []):
            if rel.get("nature") == "ChildOf":
                parent_id = str(rel.get("capec_id", ""))
                parent = capec_lookup.get(parent_id)
                if parent:
                    parent_node = next(
                        (n for n in capec_nodes if str(n["capec_id"]) == parent_id), {}
                    )
                    parent_scopes: set[str] = set()
                    for c in parent_node.get("consequences", []):
                        parent_scopes.update(c.get("scopes", []))
                    if parent_scopes & scope_set:
                        parent_ids.add(parent_id)

    if parent_ids:
        ranked = sorted(
            [capec_lookup[pid] for pid in parent_ids if pid in capec_lookup],
            key=lambda e: (
                -_surface_relevance_score(e, attack_surface_classes),
                -(e.get("ET") or 0),
            ),
        )[:max_results]
        evidence = "capec_hierarchy_parent"
        tier = _EVIDENCE_TIER[evidence]
        confidence = _EVIDENCE_CONFIDENCE[tier]
        return ranked, evidence, tier, confidence

    primary_stride = _CIA_TO_PRIMARY_STRIDE.get(cia, cia).lower()
    kw_matches: dict[str, dict] = {}
    for node in capec_nodes:
        if node.get("abstraction") not in _PREFERRED_ABSTRACTIONS:
            continue
        name_lower = node.get("name", "").lower()
        desc_lower = node.get("description", "").lower()
        if primary_stride in name_lower or primary_stride in desc_lower:
            cid = str(node["capec_id"])
            kw_matches[cid] = capec_lookup[cid]

    if kw_matches:
        ranked = sorted(
            kw_matches.values(),
            key=lambda e: (
                -_surface_relevance_score(e, attack_surface_classes),
                -(e.get("ET") or 0),
            ),
        )[:max_results]
        evidence = "capec_name_keyword_match"
        tier = _EVIDENCE_TIER[evidence]
        confidence = _EVIDENCE_CONFIDENCE[tier]
        return ranked, evidence, tier, confidence

    evidence = "no_capec_evidence"
    tier = _EVIDENCE_TIER[evidence]
    confidence = _EVIDENCE_CONFIDENCE[tier]
    return [], evidence, tier, confidence

def _derive_attack_surfaces_from_arch(
    ecus: list[str],
    interfaces: list[str],
    arch: dict,
) -> list[str]:
    ecu_set = {e.upper() for e in ecus}
    iface_set = {i.upper() for i in interfaces}
    surfaces: set[str] = set()

    iface_by_id = {i["id"].upper(): i for i in arch.get("external_interfaces", [])}

    for iface_id, iface in iface_by_id.items():
        if iface_id in iface_set:
            itype = iface.get("type", "")
            surface = _IFACE_TYPE_TO_SURFACE.get(itype)
            if surface:
                surfaces.add(surface)
            profile = iface.get("attacker_profile", "")
            surface2 = _ATTACKER_PROFILE_TO_SURFACE.get(profile)
            if surface2:
                surfaces.add(surface2)

    for flow in arch.get("data_flows", []):
        src = flow["source"].upper()
        dst = flow["destination"].upper()
        if src in ecu_set or dst in ecu_set or src in iface_set or dst in iface_set:
            for endpoint in (src, dst):
                iface = iface_by_id.get(endpoint)
                if iface:
                    itype = iface.get("type", "")
                    surface = _IFACE_TYPE_TO_SURFACE.get(itype)
                    if surface:
                        surfaces.add(surface)

    for bus in arch.get("communication_buses", []):
        members = {e.upper() for e in bus.get("connected_ecus", [])}
        if members & ecu_set:
            surfaces.add("in_vehicle_network")

    return sorted(surfaces)

def _compute_reachability(
    ecus: list[str],
    arch: dict,
) -> tuple[bool, bool, list[str]]:
    iface_map: dict[str, dict] = {i["id"]: i for i in arch.get("external_interfaces", [])}

    directly_exposed_ifaces: set[str] = {
        i["id"] for i in arch.get("external_interfaces", [])
        if i.get("exposed") and i.get("attacker_profile") in _REMOTE_ATTACKER_PROFILES
    }

    ecu_to_ifaces: dict[str, set[str]] = defaultdict(set)
    for flow in arch.get("data_flows", []):
        src = flow["source"]
        dst = flow["destination"]
        if src in iface_map and dst not in iface_map:
            ecu_to_ifaces[dst].add(src)
        if dst in iface_map and src not in iface_map:
            ecu_to_ifaces[src].add(dst)

    ecu_set = set(ecus)

    is_direct = any(
        iface in directly_exposed_ifaces
        for ecu in ecu_set
        for iface in ecu_to_ifaces.get(ecu, set())
    )

    if is_direct:
        hop_path = [
            iface
            for ecu in ecu_set
            for iface in ecu_to_ifaces.get(ecu, set())
            if iface in directly_exposed_ifaces
        ]
        return True, True, hop_path[:3]

    adj: dict[str, set[str]] = defaultdict(set)
    for flow in arch.get("data_flows", []):
        src, dst = flow["source"], flow["destination"]
        adj[src].add(dst)
        if flow.get("direction") == "bidirectional":
            adj[dst].add(src)
    for bus in arch.get("communication_buses", []):
        members = bus.get("connected_ecus", [])
        for a in members:
            for b in members:
                if a != b:
                    adj[a].add(b)

    for exposed_ecu in arch.get("ecus", []):
        eid = exposed_ecu["id"]
        direct_check = any(
            iface in directly_exposed_ifaces
            for iface in ecu_to_ifaces.get(eid, set())
        )
        if not direct_check:
            continue
        queue: deque[tuple[str, list[str]]] = deque([(eid, [eid])])
        visited: set[str] = {eid}
        while queue:
            node, path = queue.popleft()
            if node in ecu_set and node != eid:
                return False, True, path
            for nb in adj.get(node, set()):
                if nb not in visited:
                    visited.add(nb)
                    queue.append((nb, path + [nb]))

    return False, False, []

def _extract_r155_refs(node: dict, r155_threats: list[dict]) -> list[str]:
    provenance_refs: list[str] = node.get("provenance", {}).get("source", [])
    r155_ids: list[str] = []
    for src in provenance_refs:
        if "Threat" in src or "R155" in src:
            parts = src.split()
            for p in parts:
                if p and p[0].isdigit() and "." in p:
                    r155_ids.append(p)
    return r155_ids

def _build_asset_index(assets_raw: list[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = defaultdict(list)
    for a in assets_raw:
        oids = a.get("source_ontology_ids") or []
        if not oids and "source_ontology_id" in a:
            oids = [a["source_ontology_id"]]
        for oid in oids:
            index[oid].append(a)
    return index

def _resolve_asset(
    assets_for_node: list[dict],
    asset_kw: str,
) -> dict:
    for a in assets_for_node:
        if a.get("name") == asset_kw or a.get("asset_name") == asset_kw:
            return a
    for a in assets_for_node:
        name = (a.get("name") or a.get("asset_name") or "").lower()
        if asset_kw.lower() in name or name in asset_kw.lower():
            return a
    return {}

def _get_damage_ids_for_node(oid: str, damage_scenarios: list[dict]) -> list[str]:
    result = []
    for ds in damage_scenarios:
        oids = ds.get("source_ontology_ids") or []
        if not oids and ds.get("source_ontology_id"):
            oids = [ds["source_ontology_id"]]
        if oid in oids:
            result.append(ds["damage_id"])
    return result

def _build_title(cia: str, asset_name: str, ecus: list[str], domain: str) -> str:
    stride = _CIA_TO_PRIMARY_STRIDE.get(cia, cia)
    subject = "/".join(ecus[:2]) if ecus else domain
    return f"{stride} of {asset_name} on {subject} ({domain})"

def _build_description(
    cia: str,
    asset_name: str,
    ecus: list[str],
    domain: str,
    capec_refs: list[dict],
    heavens_ev: dict,
) -> str:
    stride = _CIA_TO_PRIMARY_STRIDE.get(cia, cia)
    subject = ", ".join(ecus[:2]) if ecus else domain
    capec_names = ", ".join(
        f"CAPEC-{c['capec_id']} ({c['name']})" for c in capec_refs[:2]
    ) if capec_refs else "no specific CAPEC pattern identified"
    ctrl = heavens_ev.get("heavens_controllability", "C0")
    sae  = heavens_ev.get("heavens_sae_automation_level", "SAE_L0_L4")
    return (
        f"[{stride}] An adversary compromises the {cia} property of {asset_name} "
        f"on {subject} within the {domain} functional domain. "
        f"Attack patterns: {capec_names}. "
        f"Vehicle context: {sae}, controllability {ctrl}."
    )

def _derive_attack_action(cia: str, asset_name: str, capec_refs: list[dict]) -> str:
    if capec_refs:
        top = capec_refs[0]
        name = top.get("name", "")
        if name:
            return f"executes {name} (CAPEC-{top['capec_id']}) to compromise {cia} of {asset_name}"
    stride = _CIA_TO_PRIMARY_STRIDE.get(cia, cia)
    return f"performs {stride.lower()} attack to compromise {cia} of {asset_name}"

def generate_threat_scenarios(
    ontology_path: str | Path,
    assets_path: str | Path,
    damage_scenarios_path: str | Path,
    r155_path: str | Path,
    capec_nodes_path: str | Path,
    capec_enrichment_path: str | Path,
    architecture_path: str | Path,
    parsed_threats_path: Optional[str | Path] = None,
) -> tuple[list[ThreatScenario], dict]:
    ontology_path         = Path(ontology_path)
    assets_path           = Path(assets_path)
    damage_scenarios_path = Path(damage_scenarios_path)
    r155_path             = Path(r155_path)
    capec_nodes_path      = Path(capec_nodes_path)
    capec_enrichment_path = Path(capec_enrichment_path)
    architecture_path     = Path(architecture_path)

    with open(ontology_path) as f:
        ontology = json.load(f)
    with open(assets_path) as f:
        assets_raw: list[dict] = json.load(f)
    with open(damage_scenarios_path) as f:
        raw_damage = json.load(f)
    with open(r155_path) as f:
        r155_raw = json.load(f)
    with open(capec_nodes_path, encoding="utf-8") as f:
        capec_nodes_raw: list[dict] = json.load(f)
    with open(capec_enrichment_path, encoding="utf-8") as f:
        capec_enrichment: dict[str, dict] = json.load(f)
    with open(architecture_path) as f:
        arch = json.load(f)

    damage_scenarios: list[dict] = (
        raw_damage.get("scenarios", [])
        if isinstance(raw_damage, dict)
        else raw_damage
    )

    r155_threats: list[dict] = r155_raw.get("threats", []) if isinstance(r155_raw, dict) else []

    capec_index_by_scope = _build_capec_index_by_scope(capec_nodes_raw, capec_enrichment)
    capec_lookup         = _build_capec_lookup(capec_nodes_raw, capec_enrichment)

    asset_index = _build_asset_index(assets_raw)

    generation_provenance: dict = {
        "generator_version":    GENERATOR_VERSION,
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "ontology_file":        {"path": str(ontology_path),         "sha256": _file_sha256(ontology_path)},
        "assets_file":          {"path": str(assets_path),           "sha256": _file_sha256(assets_path)},
        "damage_file":          {"path": str(damage_scenarios_path), "sha256": _file_sha256(damage_scenarios_path)},
        "capec_nodes_file":     {"path": str(capec_nodes_path),      "sha256": _file_sha256(capec_nodes_path)},
        "capec_enrichment_file":{"path": str(capec_enrichment_path), "sha256": _file_sha256(capec_enrichment_path)},
        "architecture_file":    {"path": str(architecture_path),     "sha256": _file_sha256(architecture_path)},
        "capec_selection_method": "evidence_driven_scope_match",
        "capec_index_version":  _CONSEQUENCE_SFOP_SIGNALS_VERSION,
    }

    nodes: list[dict]               = sorted(ontology["nodes"], key=lambda n: n["ontology_id"])
    scenarios: list[ThreatScenario] = []
    seen_hashes: set[str]           = set()
    collision_count: int            = 0
    _reset_ts_counter()

    for node in nodes:
        oid         = node["ontology_id"]
        domain      = node["functional_domain"]
        ecus        = node.get("mapped_ecus", [])
        interfaces  = node.get("mapped_interfaces", [])
        actors      = node.get("reachable_threat_actor_classes", [])
        entry       = node.get("entry_point", {})
        entry_types = entry.get("entry_point_types", [])
        node_label  = node.get("label") or node.get("name") or node.get("title") or oid

        heavens_ev = _extract_heavens(node)

        is_direct, is_transitive, reachability_path = _compute_reachability(ecus, arch)
        attack_surfaces = _derive_attack_surfaces_from_arch(ecus, interfaces, arch)
        if not attack_surfaces:
            attack_surfaces = node.get("attack_surface_classes", [])

        r155_ids   = _extract_r155_refs(node, r155_threats)
        damage_ids = _get_damage_ids_for_node(oid, damage_scenarios)

        assets_for_node = asset_index.get(oid, [])

        asset_target: dict[str, list[str]] = node.get("asset_target_properties", {})

        for cia, keywords in sorted(asset_target.items()):
            capec_refs, capec_evidence, capec_tier, capec_confidence = _select_capec_for_cia(
                cia,
                attack_surfaces,
                capec_index_by_scope,
                capec_lookup,
                capec_nodes_raw,
            )

            stride_cats = [_CIA_TO_PRIMARY_STRIDE[cia]] if cia in _CIA_TO_PRIMARY_STRIDE else []

            for asset_kw in sorted(keywords):
                asset_rec  = _resolve_asset(assets_for_node, asset_kw)
                asset_id   = asset_rec.get("asset_id", "ASSET-UNKNOWN")
                asset_qname= asset_rec.get("qualified_name") or asset_rec.get("asset_name") or asset_kw
                asset_tz   = asset_rec.get("trust_zone", "")
                asset_type = asset_rec.get("asset_type") or asset_rec.get("type", "")

                internal_hash = _threat_internal_hash(oid, cia, asset_id)

                if internal_hash in seen_hashes:
                    collision_count += 1
                    warnings.warn(
                        f"Duplicate threat scenario skipped "
                        f"(ontology_id={oid}, cia={cia}, asset_id={asset_id})",
                        stacklevel=2,
                    )
                    continue
                seen_hashes.add(internal_hash)
                threat_id = _next_ts_id()

                action = _derive_attack_action(cia, asset_kw, capec_refs)

                traceability: dict = {
                    "ontology_node":               oid,
                    "ontology_node_label":          node_label,
                    "ontology_version":             str(ontology.get("ontology_version", "?")),
                    "inference_method":             node.get("provenance", {}).get(
                                                       "inference_method", "weighted_evidence_convergence"
                                                   ),
                    "deterministic":                str(node.get("provenance", {}).get("deterministic", True)),
                    "asset_id":                     asset_id,
                    "asset_trust_zone":             asset_tz,
                    "cia_property":                 cia,
                    "capec_selection_method":       capec_evidence,
                    "capec_selection_tier":         capec_tier,
                    "capec_selection_confidence":   capec_confidence,
                    "capec_refs_count":             str(len(capec_refs)),
                    "r155_refs":                    "; ".join(r155_ids) if r155_ids else "none",
                    "damage_links":                 "; ".join(damage_ids) if damage_ids else "none",
                    "damage_ids_count":             str(len(damage_ids)),
                    "direct_remote":                str(is_direct),
                    "transitive_remote":            str(is_transitive),
                    "heavens_controllability":      heavens_ev["heavens_controllability"],
                    "heavens_category":             heavens_ev["heavens_category"],
                    "heavens_sae_automation_level": heavens_ev["heavens_sae_automation_level"],
                    "generator_version":            GENERATOR_VERSION,
                }

                ts = ThreatScenario(
                    threat_id=threat_id,
                    internal_hash=internal_hash,
                    title=_build_title(cia, asset_kw, ecus, domain),
                    description=_build_description(cia, asset_kw, ecus, domain, capec_refs, heavens_ev),
                    target_asset_id=asset_id,
                    target_asset_name=asset_kw,
                    target_asset_qualified_name=asset_qname,
                    target_asset_trust_zone=asset_tz,
                    target_asset_type=asset_type,
                    compromised_property=cia,
                    attack_action=action,
                    source_ontology_id=oid,
                    ontology_node_label=node_label,
                    functional_domain=domain,
                    damage_scenario_ids=damage_ids,
                    stride_categories=stride_cats,
                    capec_refs=capec_refs,
                    capec_selection_evidence=capec_evidence,
                    capec_selection_tier=capec_tier,
                    capec_selection_confidence=capec_confidence,
                    r155_refs=r155_ids,
                    threat_actor_classes=actors,
                    attack_surface_classes=attack_surfaces,
                    entry_point_types=entry_types,
                    is_directly_remote_reachable=is_direct,
                    is_transitively_remote_reachable=is_transitive,
                    remote_reachability_path=reachability_path,
                    mapped_ecus=ecus,
                    mapped_interfaces=interfaces,
                    heavens_category=heavens_ev["heavens_category"],
                    heavens_controllability=heavens_ev["heavens_controllability"],
                    heavens_controllability_propagated=heavens_ev["heavens_controllability_propagated"],
                    heavens_identification_purpose=heavens_ev["heavens_identification_purpose"],
                    heavens_degradation_mode=heavens_ev["heavens_degradation_mode"],
                    heavens_fallback_profile_class=heavens_ev["heavens_fallback_profile_class"],
                    heavens_sae_automation_level=heavens_ev["heavens_sae_automation_level"],
                    traceability=traceability,
                )
                scenarios.append(ts)

    generation_provenance["collision_count"]     = collision_count
    generation_provenance["total_scenarios"]     = len(scenarios)

    return scenarios, generation_provenance

def scenarios_to_output(scenarios: list[ThreatScenario], generation_provenance: dict) -> dict:
    return {
        "generation_provenance": generation_provenance,
        "scenarios": [asdict(s) for s in scenarios],
    }

if __name__ == "__main__":
    import sys
    from collections import Counter

    onto   = sys.argv[1] if len(sys.argv) > 1 else "functional_automotive_ontology.json"
    assets = sys.argv[2] if len(sys.argv) > 2 else "assets.json"
    damage = sys.argv[3] if len(sys.argv) > 3 else "damage_scenarios.json"
    r155   = sys.argv[4] if len(sys.argv) > 4 else "r155_raw.json"
    capec  = sys.argv[5] if len(sys.argv) > 5 else "capec_nodes.json"
    enrich = sys.argv[6] if len(sys.argv) > 6 else "capec_enrichment.json"
    arch   = sys.argv[7] if len(sys.argv) > 7 else "architecture.json"
    out    = sys.argv[8] if len(sys.argv) > 8 else "threat_scenarios.json"

    scenarios, provenance = generate_threat_scenarios(
        onto, assets, damage, r155, capec, enrich, arch
    )
    result = scenarios_to_output(scenarios, provenance)

    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[threat_scenario_generator v{GENERATOR_VERSION}] Generated {len(scenarios)} threat scenarios → {out}")

    cia_dist   = Counter(s.compromised_property           for s in scenarios)
    tier_dist  = Counter(s.capec_selection_tier           for s in scenarios)
    ctrl_dist  = Counter(s.heavens_controllability        for s in scenarios)
    hcat_dist  = Counter(s.heavens_category               for s in scenarios)
    direct_r   = sum(1 for s in scenarios if s.is_directly_remote_reachable)
    transitive = sum(1 for s in scenarios if s.is_transitively_remote_reachable)
    no_damage  = sum(1 for s in scenarios if not s.damage_scenario_ids)
    no_asset   = sum(1 for s in scenarios if s.target_asset_id == "ASSET-UNKNOWN")
    no_capec   = sum(1 for s in scenarios if not s.capec_refs)
    collisions = provenance.get("collision_count", 0)

    print(f"  CIA distribution:                  {dict(cia_dist)}")
    print(f"  CAPEC selection tier distribution: {dict(tier_dist)}")
    print(f"  HEAVENS controllability dist:      {dict(ctrl_dist)}")
    print(f"  HEAVENS category distribution:     {dict(hcat_dist)}")
    print(f"  Directly remote reachable:         {direct_r}")
    print(f"  Transitively remote reachable:     {transitive}")
    print(f"  Scenarios with no damage link:     {no_damage}")
    print(f"  Scenarios with ASSET-UNKNOWN:      {no_asset}")
    print(f"  Scenarios with no CAPEC refs:      {no_capec}")
    if collisions:
        print(f"  Duplicate ID collisions skipped:   {collisions}")