from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    from r155_mitigation_builder import build_mitigation_index as _build_mitigation_index_from_builder
    _USE_BUILDER = True
except ImportError:
    _USE_BUILDER = False


@dataclass
class CybersecurityGoal:
    goal_id: str
    damage_scenario_id: str
    source_ontology_id: str
    functional_domain: str
    ciaa_property: str
    safety_level: str
    sfop_category: str
    harm_description: str
    goal_statement: str
    cybersecurity_requirements: list[str]
    r155_mitigations: list[dict]
    threat_actor_classes: list[str]
    entry_point_types: list[str]
    r155_refs: list[str]
    linked_ts_ids: list[str]
    mapped_ecus: list[str]
    derivation: dict


_CIAA_VERB: dict[str, str] = {
    "Integrity":       "maintain the integrity of",
    "Availability":    "ensure the availability of",
    "Confidentiality": "protect the confidentiality of",
    "Authenticity":    "ensure the authenticity of",
    "Authorization":   "enforce authorisation controls for",
}

_DOMAIN_OBJECTIVE: dict[str, str] = {
    "NETWORK_GATEWAYING": (
        "prevent unauthorised cross-domain traffic manipulation that could enable "
        "lateral movement to safety-critical ECUs and compromise vehicle safety"
    ),
    "PERCEPTION_AND_SENSING": (
        "prevent sensor data corruption, spoofing, or blinding that could impair "
        "ADAS situational awareness and cause collision or loss of vehicle control"
    ),
    "VEHICLE_MOTION_CONTROL": (
        "prevent unauthorised commands from overriding braking, steering, or traction "
        "control, thereby causing loss of vehicle control and physical harm"
    ),
    "POWERTRAIN_MANAGEMENT": (
        "prevent unauthorised manipulation of powertrain or HV battery parameters "
        "that could cause unintended vehicle motion, thermal runaway, or fire"
    ),
    "OCCUPANT_SAFETY_SYSTEMS": (
        "prevent false activation or suppression of airbag and restraint systems "
        "that could directly endanger vehicle occupants"
    ),
    "VEHICLE_ACCESS_CONTROL": (
        "prevent unauthorised access to vehicle functions and resources that bypasses "
        "authentication and authorisation controls"
    ),
    "AUTOMATED_DRIVING_CONTROL": (
        "prevent unauthorised manipulation of automated driving commands that could "
        "cause loss of vehicle control or collision"
    ),
    "DIAGNOSTIC_AND_SERVICE": (
        "prevent exploitation of diagnostic interfaces to gain unauthorised access "
        "to ECU programming, configuration, or safety-critical parameters"
    ),
    "CHARGING_AND_ENERGY": (
        "prevent manipulation of charging parameters or HV energy management that "
        "could cause thermal damage, fire, or loss of vehicle mobility"
    ),
    "BIOMETRIC_MONITORING": (
        "prevent unauthorised access to or disclosure of occupant biometric data "
        "in violation of privacy rights and GDPR obligations"
    ),
}

_REQUIREMENTS: dict[str, dict[str, list[str]]] = {
    "Integrity": {
        "DEFAULT": [
            "Implement message authentication codes (MAC/CMAC) for all safety-critical "
            "CAN messages to prevent injection and tampering (R155 M10, M15)",
            "Apply access control techniques to prevent unauthorised parameter modification "
            "(R155 M7)",
        ],
        "NETWORK_GATEWAYING": [
            "Implement MAC/CMAC for all cross-domain messages traversing the gateway ECU "
            "(R155 M10)",
            "Enforce firewall policy integrity with cryptographic protection against "
            "unauthorised rule modification (R155 M7, M6)",
        ],
        "VEHICLE_MOTION_CONTROL": [
            "Implement message authentication for all brake, steering, and traction "
            "control CAN frames (R155 M10)",
            "Apply input validation and plausibility checks on all safety-critical "
            "actuator commands (R155 M7)",
        ],
        "POWERTRAIN_MANAGEMENT": [
            "Implement authenticated CAN messages for all HV battery management and "
            "inverter control commands (R155 M10)",
            "Apply range and plausibility checks on charging voltage, power, and "
            "temperature parameters (R155 M7)",
        ],
        "OCCUPANT_SAFETY_SYSTEMS": [
            "Implement message authentication for all airbag deployment commands and "
            "restraint control signals (R155 M10)",
            "Apply redundant sensor cross-validation to prevent false deployment or "
            "suppression (R155 M6)",
        ],
        "PERCEPTION_AND_SENSING": [
            "Implement sensor data integrity validation and cross-sensor plausibility "
            "checks (R155 M6, M7)",
            "Apply anomaly detection to identify sensor spoofing or injected false "
            "objects (R155 M15)",
        ],
    },
    "Availability": {
        "DEFAULT": [
            "Implement DoS detection and rate-limiting on the in-vehicle network to "
            "prevent bus flooding (R155 M13)",
            "Apply watchdog mechanisms and safe-state fallback for all safety-critical "
            "ECUs (R155 M13)",
        ],
        "VEHICLE_MOTION_CONTROL": [
            "Implement CAN bus load monitoring and rate-limiting to prevent denial of "
            "service on safety-critical control messages (R155 M13)",
            "Apply hardware watchdog timers with fail-safe degradation modes on all "
            "motion control ECUs",
        ],
        "OCCUPANT_SAFETY_SYSTEMS": [
            "Implement redundant communication paths for restraint system activation "
            "signals (R155 M13)",
            "Apply power supply monitoring and fail-operational design for airbag "
            "controllers",
        ],
        "POWERTRAIN_MANAGEMENT": [
            "Implement rate-limiting on inverter and battery management command messages "
            "to prevent DoS-induced shutdown (R155 M13)",
            "Apply safe-state logic for HV battery management in case of communication "
            "loss",
        ],
    },
    "Authenticity": {
        "DEFAULT": [
            "Implement sender authentication for all cross-domain ECU messages using "
            "hardware-backed cryptographic keys (R155 M10)",
            "Use Hardware Security Modules (HSM) for secure key storage and "
            "cryptographic operations (R155 M11)",
        ],
        "NETWORK_GATEWAYING": [
            "Deploy HSM-backed message authentication on all ECUs connected to the "
            "gateway to prevent source spoofing (R155 M10, M11)",
            "Implement certificate-based ECU identity verification for cross-domain "
            "sessions (R155 M10)",
        ],
        "VEHICLE_ACCESS_CONTROL": [
            "Implement certificate-based mutual authentication for remote access "
            "functions (remote key, immobiliser) (R155 M20)",
            "Use hardware-backed key storage for all vehicle access credentials "
            "(R155 M11)",
        ],
    },
    "Confidentiality": {
        "DEFAULT": [
            "Encrypt all sensitive data transmitted between ECUs and backend servers "
            "using TLS 1.3 or equivalent (R155 M12)",
            "Restrict diagnostic data access to authorised sessions with "
            "role-based access control (R155 M8)",
        ],
        "BIOMETRIC_MONITORING": [
            "Encrypt all biometric and occupant data at rest and in transit with "
            "approved cryptographic algorithms (R155 M12, M24)",
            "Implement data minimisation and purpose limitation in compliance with "
            "GDPR and R155 §1.3 (R155 M8)",
        ],
        "PERCEPTION_AND_SENSING": [
            "Restrict access to raw sensor feeds and interior camera streams to "
            "authorised ADAS processing ECUs only (R155 M8)",
            "Encrypt interior sensor data streams to prevent eavesdropping "
            "(R155 M12)",
        ],
    },
    "Authorization": {
        "DEFAULT": [
            "Enforce role-based access control and least-privilege principle for all "
            "ECU functions (R155 M9, M18)",
            "Implement UDS session authentication (security access seed/key) for all "
            "ECU programming and calibration operations (R155 M22)",
        ],
        "NETWORK_GATEWAYING": [
            "Enforce strict allow-list based routing policy — deny all cross-domain "
            "messages not explicitly authorised (R155 M9)",
            "Implement gateway-level session authorisation before forwarding "
            "safety-critical commands (R155 M9)",
        ],
        "VEHICLE_ACCESS_CONTROL": [
            "Implement multi-factor authentication for privileged diagnostic sessions "
            "and remote access (R155 M9, M20)",
            "Enforce time-limited, audited access for service technician operations "
            "(R155 M18, M19)",
        ],
    },
}

_MITIGATION_CIAA: dict[str, list[str]] = {
    "M4":  ["Confidentiality"],
    "M5":  ["Confidentiality"],
    "M6":  ["Integrity"],
    "M7":  ["Integrity", "Availability"],
    "M8":  ["Authorization", "Confidentiality"],
    "M9":  ["Authorization"],
    "M10": ["Integrity", "Authenticity"],
    "M11": ["Confidentiality", "Integrity"],
    "M12": ["Confidentiality"],
    "M13": ["Availability"],
    "M14": ["Integrity"],
    "M15": ["Integrity", "Authenticity"],
    "M16": ["Integrity", "Availability"],
    "M18": ["Authorization"],
    "M19": ["Authorization"],
    "M20": ["Authenticity", "Authorization"],
    "M21": ["Integrity"],
    "M22": ["Authorization"],
    "M23": ["Integrity", "Availability"],
    "M24": ["Confidentiality"],
}

_MITIGATION_R155_REF: dict[str, str] = {
    "M1":  "R155 Annex 5 Part A §1.1",
    "M2":  "R155 Annex 5 Part A §1.2",
    "M3":  "R155 Annex 5 Part A §2.1",
    "M4":  "R155 Annex 5 Part A §3.2",
    "M5":  "R155 Annex 5 Part A §3.5",
    "M6":  "R155 Annex 5 Part B §5.1",
    "M7":  "R155 Annex 5 Part B §5.2-5.5",
    "M8":  "R155 Annex 5 Part B §7.2-7.3",
    "M9":  "R155 Annex 5 Part B §9.1",
    "M10": "R155 Annex 5 Part B §4.1-6.3",
    "M11": "R155 Annex 5 Part B §4.2",
    "M12": "R155 Annex 5 Part B §7.1",
    "M13": "R155 Annex 5 Part B §8.1-8.2",
    "M14": "R155 Annex 5 Part B §10.1",
    "M15": "R155 Annex 5 Part B §11.1",
    "M16": "R155 Annex 5 Part B §12.1-12.3",
    "M18": "R155 Annex 5 Part B §15.1",
    "M19": "R155 Annex 5 Part B §15.2",
    "M20": "R155 Annex 5 Part B §16.1-16.2",
    "M21": "R155 Annex 5 Part B §16.3-17.1",
    "M22": "R155 Annex 5 Part B §18.1-18.3",
    "M23": "R155 Annex 5 Part B §26.1-29.2",
    "M24": "R155 Annex 5 Part C §30.1-31.1",
}

from ontology_taxonomy_sfop_addition import HEAVENS_SAFETY_DESCRIPTIONS as _S_LEVEL_HARM

_goal_counter: int = 0


def _reset_counter() -> None:
    global _goal_counter
    _goal_counter = 0


def _goal_id() -> str:
    global _goal_counter
    _goal_counter += 1
    return f"CG-{_goal_counter:03d}"


def _build_mitigation_index(r155_raw: dict) -> dict[str, list[dict]]:
    if _USE_BUILDER:
        return _build_mitigation_index_from_builder(r155_raw)
    index: dict[str, list[dict]] = {}
    for m in r155_raw.get("mitigations", []):
        entry = {
            "mitigation_id":    m.get("mitigation_id", ""),
            "description":      m.get("description", ""),
            "scope":            m.get("scope", "vehicle"),
            "cyber_properties": m.get("cyber_properties", []),
            "r155_ref":         m.get("r155_ref", ""),
        }
        for ref in m.get("protects_against", []):
            index.setdefault(str(ref), []).append(entry)
    return index


def _enrich_mitigation(m: dict) -> dict:
    mid = m.get("mitigation_id", "")
    r155_ref = m.get("r155_ref") or _MITIGATION_R155_REF.get(mid, "")
    cyber_properties = m.get("cyber_properties") or _MITIGATION_CIAA.get(mid, [])
    return {
        "mitigation_id":    mid,
        "description":      m.get("description", ""),
        "scope":            m.get("scope", "vehicle"),
        "cyber_properties": cyber_properties,
        "r155_ref":         r155_ref,
    }


def _get_requirements(ciaa: str, domain: str) -> list[str]:
    prop_map = _REQUIREMENTS.get(ciaa, {})
    return prop_map.get(domain) or prop_map.get("DEFAULT") or [
        f"Apply appropriate security controls to protect {ciaa.lower()} of "
        f"{domain.replace('_', ' ').lower()} assets (R155 Annex 5 Part B)"
    ]


def _build_goal_statement(domain: str, ciaa: str) -> str:
    verb = _CIAA_VERB.get(ciaa, f"protect the {ciaa.lower()} of")
    domain_display = domain.replace("_", " ").title()
    objective = _DOMAIN_OBJECTIVE.get(
        domain,
        f"prevent security compromise of {domain.replace('_', ' ').lower()} functions"
    )
    return (
        f"The {domain_display} function(s) shall {verb} "
        f"all safety-critical parameters and commands in order to {objective}."
    )


def _derive_mapped_ecus(ds_id: str, damage_scenarios: list[dict]) -> list[str]:
    for ds in damage_scenarios:
        if ds.get("damage_id") == ds_id:
            return ds.get("affected_ecus", [])
    return []


def generate_cybersecurity_goals(
    ontology_path: str | Path,
    damage_scenarios_path: str | Path,
    threat_scenarios_path: str | Path,
    r155_path: str | Path,
) -> list[CybersecurityGoal]:
    _reset_counter()

    with open(ontology_path) as f:
        ontology = json.load(f)
    with open(damage_scenarios_path) as f:
        damage_scenarios: list[dict] = json.load(f)
    with open(threat_scenarios_path) as f:
        threat_scenarios: list[dict] = json.load(f)
    with open(r155_path) as f:
        r155_raw: dict = json.load(f)

    onto_map: dict[str, dict] = {n["ontology_id"]: n for n in ontology["nodes"]}
    mit_index = _build_mitigation_index(r155_raw)

    ts_by_ds: dict[str, list[dict]] = {}
    for ts in threat_scenarios:
        for did in ts.get("damage_scenario_ids", []):
            ts_by_ds.setdefault(did, []).append(ts)

    goals: list[CybersecurityGoal] = []
    seen: set[tuple[str, str]] = set()

    for ds in sorted(damage_scenarios, key=lambda d: d["damage_id"]):
        ds_id     = ds["damage_id"]
        onto_id   = ds.get("source_ontology_id", "")
        domain    = ds.get("functional_domain", "")
        r155_refs = ds.get("r155_refs", [])
        onto_node = onto_map.get(onto_id, {})

        primary_props: list[str] = (
            onto_node.get("cybersecurity_properties", {}).get("primary", [])
        )
        primary_props = [p for p in primary_props if p in _CIAA_VERB]
        if not primary_props:
            primary_props = ["Integrity"]

        ts_for_ds = ts_by_ds.get(ds_id, [])
        actor_classes: set[str] = set()
        entry_points: set[str] = set()
        for ts in ts_for_ds:
            actor_classes.update(ts.get("threat_actor_classes", []))
            entry_points.update(ts.get("entry_point_types", []))

        sfop = ds.get("sfop_category", "Operational")
        safety_level = ds.get("safety_level", "S1")
        harm_desc = _S_LEVEL_HARM.get(safety_level, _S_LEVEL_HARM["S1"])

        mapped_ecus = _derive_mapped_ecus(ds_id, damage_scenarios)

        ds_mitigations_raw: list[dict] = []
        seen_mit_ids: set[str] = set()
        for ref in r155_refs:
            clean_ref = ref.replace("R155 Annex 5 Threat ", "").strip()
            for m in mit_index.get(clean_ref, []):
                if m["mitigation_id"] not in seen_mit_ids:
                    seen_mit_ids.add(m["mitigation_id"])
                    ds_mitigations_raw.append(m)

        ds_mitigations = [_enrich_mitigation(m) for m in ds_mitigations_raw]

        for ciaa in sorted(primary_props):
            dedup_key = (ds_id, ciaa)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            goal = CybersecurityGoal(
                goal_id               = _goal_id(),
                damage_scenario_id    = ds_id,
                source_ontology_id    = onto_id,
                functional_domain     = domain,
                ciaa_property         = ciaa,
                safety_level          = safety_level,
                sfop_category         = sfop,
                harm_description      = harm_desc,
                goal_statement        = _build_goal_statement(domain, ciaa),
                cybersecurity_requirements = _get_requirements(ciaa, domain),
                r155_mitigations      = ds_mitigations,
                threat_actor_classes  = sorted(actor_classes),
                entry_point_types     = sorted(entry_points),
                r155_refs             = r155_refs,
                linked_ts_ids         = [ts["threat_id"] for ts in ts_for_ds],
                mapped_ecus           = mapped_ecus,
                derivation = {
                    "method":                        "deterministic_ontology_ciaa_domain_mapping",
                    "ontology_version":              str(ontology.get("ontology_version", "?")),
                    "llm_used":                      False,
                    "source_ds":                     ds_id,
                    "source_ciaa_prop":              ciaa,
                    "source_domain":                 domain,
                    "sfop_category":                 sfop,
                    "safety_level":                  safety_level,
                    "r155_mitigations_resolved":     len(ds_mitigations),
                    "mapped_ecus_count":             len(mapped_ecus),
                },
            )
            goals.append(goal)

    return goals


def goals_to_dict(goals: list[CybersecurityGoal]) -> list[dict]:
    return [asdict(g) for g in goals]


def inject_goal_ids(
    goals_path: str | Path,
    ts_path:    str | Path,
) -> None:
    with open(goals_path) as f:
        goals: list[dict] = json.load(f)
    with open(ts_path) as f:
        ts_list: list[dict] = json.load(f)

    ts_to_goals: dict[str, list[str]] = {}
    for g in goals:
        for ts_id in g.get("linked_ts_ids", []):
            ts_to_goals.setdefault(ts_id, []).append(g["goal_id"])

    for ts in ts_list:
        ts["cybersecurity_goal_ids"] = ts_to_goals.get(ts["threat_id"], [])

    with open(ts_path, "w") as f:
        json.dump(ts_list, f, indent=2)


if __name__ == "__main__":
    import sys
    from collections import Counter
    onto   = sys.argv[1] if len(sys.argv) > 1 else "functional_automotive_ontology.json"
    ds     = sys.argv[2] if len(sys.argv) > 2 else "damage_scenarios.json"
    ts     = sys.argv[3] if len(sys.argv) > 3 else "threat_scenarios.json"
    r155   = sys.argv[4] if len(sys.argv) > 4 else "r155_raw.json"
    out    = sys.argv[5] if len(sys.argv) > 5 else "cybersecurity_goals.json"

    goals = generate_cybersecurity_goals(onto, ds, ts, r155)
    result = goals_to_dict(goals)
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[cybersecurity_goal_generator] Generated {len(goals)} goals → {out}")
    ciaa_dist  = Counter(g.ciaa_property for g in goals)
    sfop_dist  = Counter(g.sfop_category for g in goals)
    s_dist     = Counter(g.safety_level for g in goals)
    for k, v in sorted(ciaa_dist.items()):
        print(f"     {k:25s}: {v}")
    print(f"  SFOP  : {dict(sfop_dist)}")
    print(f"  Levels: {dict(s_dist)}")
    ecu_covered = sum(1 for g in goals if g.mapped_ecus)
    print(f"  Goals with mapped_ecus: {ecu_covered}/{len(goals)}")
    mit_ref_ok = sum(1 for g in goals for m in g.r155_mitigations if m.get("r155_ref"))
    mit_total  = sum(len(g.r155_mitigations) for g in goals)
    print(f"  Mitigations with r155_ref: {mit_ref_ok}/{mit_total}")
    inject_goal_ids(out, ts)
    print(f"  cybersecurity_goal_ids injected into {ts}")