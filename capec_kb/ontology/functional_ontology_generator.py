import json
import sys
import os
import hashlib
import importlib.util
from pathlib import Path
from collections import defaultdict

_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from inference_engine import infer_functional_domain
from consequence_inference import infer_consequences

def _import_capec_mapper():
    _spec = importlib.util.spec_from_file_location(
        "capec_mapper", _here / "capec_mapper.py"
    )
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    return _mod

_capec_mapper = _import_capec_mapper()
build_capec_refs = _capec_mapper.build_capec_refs
load_capec_index = _capec_mapper.load_capec_index

from ontology_taxonomy import (
    CYBERSECURITY_DOMAIN_MAP,
    R155_THREAT_MAP,
    REFERENCE_STANDARDS,
    ASSET_TARGET_PROPERTIES_MAP,
    ATTACK_SURFACE_ACTOR_MAP,
    ENTRY_POINT_SURFACE_TYPES,
    EXTERNALLY_REACHABLE_SURFACES,
    TRANSITIVE_REMOTE_ATTACKER_SURFACES,
    NETWORK_EXPOSED_INTERFACE_TYPES,
    SFOP_DOMAIN_MAP,
)

OCCUPANT_SENSING_R155 = ["R155 Annex 5 Threat 8.1"]

_DUAL_DOMAIN_RULES = {
    "NETWORK_GATEWAYING": "AUTOMATED_DRIVING_CONTROL",
}

_INSTANCE_DIFFERENTIATORS = {
    "energy_conversion": {
        "front": "front drive unit",
        "rear": "rear drive unit",
    },
    "occupant_sensing": {
        "camera": "interior camera",
        "radar": "interior radar",
    },
    "lateral_control": {
        "controller": "steering actuator",
        "angle": "steering angle sensor",
    },
}

_CONTROLLABILITY_RULES = [
    (
        {"unintended_braking", "loss_of_deceleration_control", "unintended_steering",
         "uncontrolled_lateral_motion", "false_airbag_deployment", "airbag_suppression_in_collision",
         "seatbelt_pretensioner_attack", "uncontrolled_torque_output", "thermal_runaway_enablement",
         "hv_system_compromise"},
        "C3",
        "Consequence set includes direct uncontrolled physical actuation; driver has no effective override path",
    ),
    (
        {"sensor_data_spoofing", "false_object_injection", "sensor_blinding",
         "occupant_state_falsification", "presence_detection_bypass", "safety_decision_corruption",
         "routing_manipulation", "cross_domain_lateral_movement"},
        "C2",
        "Consequence corrupts inputs to safety-critical decision logic; driver situational awareness partially retained but degraded",
    ),
    (
        {"unauthorized_vehicle_unlock", "immobilizer_bypass", "relay_attack_enablement",
         "authentication_bypass", "authenticated_network_access_enabling_lateral_movement",
         "charging_system_manipulation", "unauthorized_privileged_access"},
        "C1",
        "Consequence affects access control or secondary systems; driver physical safety not immediately threatened",
    ),
]

_CONTROLLABILITY_ORDER = {"C3": 3, "C2": 2, "C1": 1, "C0": 0}

_FALLBACK_PROFILES = {
    "sensor_to_actuator": {
        "profile_class": "hardware_interrupt_based",
        "typical_mechanism": "dedicated_hardware_comparator_or_equivalent",
        "profile_rationale": "Sensor-to-actuator role typically relies on a hardware-level interrupt path independent of the software stack to ensure actuation cannot be suppressed by software compromise alone",
        "evidence_source": "actuator_sensor_role:sensor_to_actuator",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-5:2018 Clause 9 (hardware safety requirements)",
    },
    "bus_bridge": {
        "profile_class": "watchdog_timeout_based",
        "typical_mechanism": "message_timeout_watchdog_with_safe_state_routing",
        "profile_rationale": "Bus bridge role typically implements a message-timeout watchdog that triggers ECU reset and reverts to a last-known-good or deny-all routing state on timeout",
        "evidence_source": "data_flow_role:bus_bridge",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-6:2018 Clause 9 (software architectural design)",
    },
    "wireless_to_network_bridge": {
        "profile_class": "authentication_lockout_based",
        "typical_mechanism": "progressive_lockout_on_authentication_failure",
        "profile_rationale": "Wireless-to-network bridge role typically implements progressive lockout after repeated authentication failures, reverting to a passive or deny-all mode",
        "evidence_source": "data_flow_role:wireless_to_network_bridge",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO/SAE 21434:2021 Clause 10 (cybersecurity controls)",
    },
    "sensor_producer": {
        "profile_class": "plausibility_monitoring_based",
        "typical_mechanism": "cross_sensor_plausibility_check_with_safe_value_substitution",
        "profile_rationale": "Sensor producer role typically has a consumer-side plausibility monitor that discards implausible values and substitutes safe-state defaults",
        "evidence_source": "data_flow_role:sensor_producer",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-6:2018 Clause 9 (plausibility checks)",
    },
    "occupant_sensor_producer": {
        "profile_class": "plausibility_monitoring_based",
        "typical_mechanism": "cross_sensor_plausibility_check_with_safe_value_substitution",
        "profile_rationale": "Occupant sensor producer role typically has a consumer-side plausibility monitor that discards implausible values and substitutes safe-state defaults",
        "evidence_source": "data_flow_role:occupant_sensor_producer",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-6:2018 Clause 9 (plausibility checks)",
    },
    "actuator_producer": {
        "profile_class": "output_limiter_based",
        "typical_mechanism": "hardware_output_limiter_independent_of_software_stack",
        "profile_rationale": "Actuator producer role typically includes a hardware-enforced output limit stage (e.g. torque limiter, current clamp) that constrains uncontrolled output magnitude independently of the software command path",
        "evidence_source": "data_flow_role:actuator_producer",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-5:2018 Clause 9 (hardware safety requirements)",
    },
    "control_producer": {
        "profile_class": "hardware_cutoff_based",
        "typical_mechanism": "hardware_thermal_or_overcurrent_protection_independent_of_software",
        "profile_rationale": "Control producer role typically includes hardware-level thermal or overcurrent protection that can interrupt the control path independently of software state",
        "evidence_source": "data_flow_role:control_producer",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-5:2018 Clause 9 (hardware safety requirements)",
    },
    "pure_consumer": {
        "profile_class": "interlock_based",
        "typical_mechanism": "hardware_interlock_or_enable_line_independent_of_software",
        "profile_rationale": "Pure consumer role typically depends on a hardware interlock or enable line that prevents activation regardless of software command if the interlock condition is not met",
        "evidence_source": "data_flow_role:pure_consumer",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-5:2018 Clause 9 (hardware safety requirements)",
    },
    "diagnostic_node": {
        "profile_class": "session_timeout_based",
        "typical_mechanism": "uds_session_timeout_with_return_to_normal_mode",
        "profile_rationale": "Diagnostic node role implements UDS session timeout (ISO 14229-1 S3 timer); on timeout the ECU terminates the diagnostic session and returns to normal operating mode, isolating the diagnostic attack surface",
        "evidence_source": "data_flow_role:diagnostic_node",
        "profile_confidence": "standard_derived",
        "standard_ref": "ISO 14229-1:2020 Clause 7.4.2 (S3 server timer)",
    },
    "network_bridge": {
        "profile_class": "watchdog_timeout_based",
        "typical_mechanism": "message_timeout_watchdog_with_safe_state_routing",
        "profile_rationale": "Network bridge role typically implements a message-timeout watchdog that triggers reset and reverts to a safe routing state on timeout",
        "evidence_source": "data_flow_role:network_bridge",
        "profile_confidence": "role_typical",
        "standard_ref": "ISO 26262-6:2018 Clause 9 (software architectural design)",
    },
    "unknown": {
        "profile_class": "generic_watchdog_based",
        "typical_mechanism": "generic_watchdog_timeout_with_safe_state_default",
        "profile_rationale": "No specific role matched; generic watchdog timeout with safe-state default applied as a conservative fallback profile",
        "evidence_source": "data_flow_role:unknown",
        "profile_confidence": "default_fallback",
        "standard_ref": "ISO 26262-6:2018 Clause 9 (software architectural design)",
    },
}

_DEGRADATION_RULES = {
    "VEHICLE_MOTION_CONTROL": {
        "mode": "reduced_authority_control",
        "description": "Vehicle defaults to minimum steering/braking authority; speed limited to crawl mode via powertrain interlock",
        "iso26262_asil": "ASIL-D",
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "mode": "passive_safe_state",
        "description": "Restraint system enters passive armed state; no commands accepted until power cycle and self-test pass",
        "iso26262_asil": "ASIL-D",
    },
    "PERCEPTION_AND_SENSING": {
        "mode": "sensor_fusion_exclusion",
        "description": "Compromised sensor stream excluded from fusion; ADAS falls back to remaining sensors with reduced envelope",
        "iso26262_asil": "ASIL-B",
    },
    "NETWORK_GATEWAYING": {
        "mode": "default_deny_routing",
        "description": "Gateway reverts to deny-all routing policy; only safety-critical CAN frames from pre-approved IDs pass",
        "iso26262_asil": "ASIL-B",
    },
    "POWERTRAIN_MANAGEMENT": {
        "mode": "limp_home",
        "description": "Powertrain limited to limp-home torque envelope; HV contactor kept closed only if thermal limits are nominal",
        "iso26262_asil": "ASIL-C",
    },
    "VEHICLE_ACCESS_CONTROL": {
        "mode": "passive_immobiliser",
        "description": "Vehicle reverts to passive immobiliser; keyless entry disabled, physical key required",
        "iso26262_asil": "QM",
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "mode": "driver_takeover_request",
        "description": "Autopilot disengages and issues audible/visual takeover request; controls handed to driver",
        "iso26262_asil": "ASIL-D",
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "mode": "session_termination",
        "description": "Diagnostic session closed; ECU returns to normal operating mode",
        "iso26262_asil": "QM",
    },
    "BIOMETRIC_MONITORING": {
        "mode": "data_suppression",
        "description": "Biometric data stream suspended; occupant monitoring disabled until re-authentication",
        "iso26262_asil": "QM",
    },
    "CHARGING_AND_ENERGY": {
        "mode": "charge_session_abort",
        "description": "Charging session aborted; HV interlock re-verified before any new session is permitted",
        "iso26262_asil": "ASIL-B",
    },
}

_IDENTIFICATION_PURPOSE_RULES = {
    "VEHICLE_MOTION_CONTROL": {
        "purpose": "safety_critical_actuator_integrity",
        "heavens_category": "S",
        "description": "Node controls physical vehicle motion; identified to assess attack feasibility against safety-critical actuation chains",
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "purpose": "safety_critical_passive_safety",
        "heavens_category": "S",
        "description": "Node controls pyrotechnic and restraint actuators; identified to assess false-activation and suppression attack paths",
    },
    "PERCEPTION_AND_SENSING": {
        "purpose": "safety_relevant_sensor_integrity",
        "heavens_category": "S",
        "description": "Node supplies sensor data to safety decision logic; identified to assess spoofing and blinding attack impact on ADAS",
    },
    "NETWORK_GATEWAYING": {
        "purpose": "security_boundary_enforcement",
        "heavens_category": "O",
        "description": "Node enforces cross-domain isolation; identified to assess lateral movement enablement and routing manipulation",
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "purpose": "safety_critical_control_logic",
        "heavens_category": "S",
        "description": "Node executes automated driving control logic; identified to assess command injection and decision corruption",
    },
    "POWERTRAIN_MANAGEMENT": {
        "purpose": "safety_relevant_energy_management",
        "heavens_category": "S",
        "description": "Node manages high-voltage energy conversion and storage; identified to assess thermal runaway and torque manipulation",
    },
    "VEHICLE_ACCESS_CONTROL": {
        "purpose": "operational_access_gating",
        "heavens_category": "O",
        "description": "Node controls vehicle physical access and network authentication; identified to assess theft and lateral movement enablement",
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "purpose": "operational_diagnostic_surface",
        "heavens_category": "O",
        "description": "Node exposes diagnostic interface; identified to assess privileged session exploitation",
    },
    "BIOMETRIC_MONITORING": {
        "purpose": "privacy_data_source",
        "heavens_category": "P",
        "description": "Node captures biometric and presence data; identified to assess covert surveillance and data exfiltration",
    },
    "CHARGING_AND_ENERGY": {
        "purpose": "safety_relevant_energy_transfer",
        "heavens_category": "S",
        "description": "Node manages external energy transfer; identified to assess HV connector and interlock manipulation",
    },
}

_SUBDOMAIN_IDENTIFICATION_OVERRIDES = {
    "presence_detection": {
        "purpose": "safety_relevant_occupant_detection",
        "heavens_category": "S",
        "description": "Subdomain presence_detection can influence restraint system activation decisions; reclassified from Privacy to Safety to capture false-presence and suppression attack impact",
        "override_rationale": "Subdomain override: presence_detection feeds occupant classification which gates airbag deployment — Safety impact supersedes domain-level Privacy classification",
    },
    "occupant_sensing": {
        "purpose": "safety_relevant_occupant_sensing",
        "heavens_category": "S",
        "description": "Subdomain occupant_sensing supplies occupant state data to safety decision logic; reclassified to Safety to capture falsification attack impact on restraint systems",
        "override_rationale": "Subdomain override: occupant_sensing data is consumed by OCCUPANT_SAFETY_SYSTEMS domain nodes",
    },
}

_HEAVENS_CATEGORY_ORDER = {"S": 2, "O": 1, "P": 0}

_SAE_AUTOMATION_RULES = [
    (
        {"AUTOMATED_DRIVING_CONTROL", "PERCEPTION_AND_SENSING"},
        {"sensor_producer", "occupant_sensor_producer", "actuator_producer", "control_producer",
         "bus_bridge", "sensor_consumer"},
        "SAE_L3_L4",
        "Node participates in automated driving control or sensor fusion loop active during SAE L3/L4 operation",
    ),
    (
        {"VEHICLE_MOTION_CONTROL", "OCCUPANT_SAFETY_SYSTEMS", "POWERTRAIN_MANAGEMENT",
         "NETWORK_GATEWAYING"},
        {"bus_bridge", "actuator_producer", "sensor_to_actuator", "control_producer"},
        "SAE_L2_L4",
        "Node executes safety-critical actuation or gatewaying functions active from SAE L2 through L4",
    ),
    (
        {"VEHICLE_ACCESS_CONTROL", "DIAGNOSTIC_AND_SERVICE"},
        None,
        "SAE_L0_L4",
        "Node operates independently of automation level; active across full SAE L0–L4 range",
    ),
    (
        {"BIOMETRIC_MONITORING", "CHARGING_AND_ENERGY"},
        None,
        "SAE_L0_L4",
        "Node operates independently of automation level; active across full SAE L0–L4 range",
    ),
]


def _derive_controllability(consequences, domain, dual_domain):
    conseq_set = set(consequences)
    for trigger_set, rating, rationale in _CONTROLLABILITY_RULES:
        if conseq_set & trigger_set:
            return {
                "rating": rating,
                "rationale": rationale,
                "derivation_source": "functional_consequences + domain",
                "iso26262_ref": "ISO 26262-3:2018 Clause 6.4.3",
                "propagated": False,
            }
    return {
        "rating": "C0",
        "rationale": "No consequence in node set maps to a controllability trigger; impact limited to non-safety domains",
        "derivation_source": "functional_consequences + domain",
        "iso26262_ref": "ISO 26262-3:2018 Clause 6.4.3",
        "propagated": False,
    }


def _derive_fallback_mechanism(data_flow_role, actuator_sensor_role, domain):
    role = data_flow_role if data_flow_role != "unknown" else actuator_sensor_role
    entry = _FALLBACK_PROFILES.get(role) or _FALLBACK_PROFILES.get(data_flow_role) or _FALLBACK_PROFILES["unknown"]
    return {
        "profile_class": entry["profile_class"],
        "typical_mechanism": entry["typical_mechanism"],
        "profile_rationale": entry["profile_rationale"],
        "evidence_source": entry["evidence_source"],
        "profile_confidence": entry["profile_confidence"],
        "standard_ref": entry["standard_ref"],
        "derivation_method": "data_flow_role + actuator_sensor_role -> fallback_profile_table",
        "architecture_validation": "not_verified_against_architecture",
    }


def _derive_degradation_mode(domain, dual_domain, consequences):
    entry = _DEGRADATION_RULES.get(domain) or _DEGRADATION_RULES.get(dual_domain)
    if not entry:
        entry = {
            "mode": "safe_state_default",
            "description": "ECU transitions to vendor-defined safe state; no domain-specific degradation policy mapped",
            "iso26262_asil": "QM",
        }
    has_safety_unavailability = "safety_function_unavailability" in consequences
    return {
        "mode": entry["mode"],
        "description": entry["description"],
        "iso26262_asil": entry["iso26262_asil"],
        "safety_function_loss_applicable": has_safety_unavailability,
        "derivation_source": "functional_domain -> degradation_table",
    }


def _derive_identification_purpose(domain, dual_domain, subdomains):
    subdomain_override = None
    for sd in (subdomains or []):
        if sd in _SUBDOMAIN_IDENTIFICATION_OVERRIDES:
            subdomain_override = _SUBDOMAIN_IDENTIFICATION_OVERRIDES[sd]
            break

    base_entry = (
        _IDENTIFICATION_PURPOSE_RULES.get(domain)
        or _IDENTIFICATION_PURPOSE_RULES.get(dual_domain)
    )
    if not base_entry:
        base_entry = {
            "purpose": "general_security_relevance",
            "heavens_category": "O",
            "description": "Node identified as cybersecurity-relevant based on ontology inference; no domain-specific purpose rule matched",
        }

    if subdomain_override is not None:
        base_rank = _HEAVENS_CATEGORY_ORDER.get(base_entry["heavens_category"], 0)
        override_rank = _HEAVENS_CATEGORY_ORDER.get(subdomain_override["heavens_category"], 0)
        if override_rank > base_rank:
            return {
                "purpose": subdomain_override["purpose"],
                "heavens_category": subdomain_override["heavens_category"],
                "description": subdomain_override["description"],
                "subdomains_applied": subdomains,
                "derivation_source": "subdomain_override -> identification_purpose_table",
                "subdomain_override_applied": True,
                "override_rationale": subdomain_override["override_rationale"],
                "base_domain_category": base_entry["heavens_category"],
            }

    return {
        "purpose": base_entry["purpose"],
        "heavens_category": base_entry["heavens_category"],
        "description": base_entry["description"],
        "subdomains_applied": subdomains,
        "derivation_source": "functional_domain -> identification_purpose_table",
        "subdomain_override_applied": False,
    }


def _derive_sae_automation_level(domain, dual_domain, data_flow_role):
    domains = {domain}
    if dual_domain:
        domains.add(dual_domain)
    for domain_set, role_set, level, rationale in _SAE_AUTOMATION_RULES:
        if domains & domain_set:
            if role_set is None or data_flow_role in role_set:
                return {
                    "level": level,
                    "rationale": rationale,
                    "derivation_source": "functional_domain + data_flow_role -> sae_table",
                    "sae_j3016_ref": "SAE J3016_202104",
                }
    return {
        "level": "SAE_L0_L4",
        "rationale": "No automation-level restriction matched; node treated as active across all levels",
        "derivation_source": "functional_domain + data_flow_role -> sae_table",
        "sae_j3016_ref": "SAE J3016_202104",
    }


def _derive_heavens_properties(node, architecture):
    domain = node["functional_domain"]
    dual_domain = node.get("dual_domain")
    subdomains = node.get("subdomains", [])
    consequences = node.get("functional_consequences", [])

    ie = node.get("inference_evidence", {})
    data_flow_role = ie.get("data_flow_role", {}).get("role", "unknown") if ie.get("data_flow_role") else "unknown"
    actuator_sensor_role = ie.get("actuator_sensor_role", {}).get("role", "unknown") if ie.get("actuator_sensor_role") else "unknown"

    controllability = _derive_controllability(consequences, domain, dual_domain)
    fallback_mechanism = _derive_fallback_mechanism(data_flow_role, actuator_sensor_role, domain)
    degradation_mode = _derive_degradation_mode(domain, dual_domain, consequences)
    identification_purpose = _derive_identification_purpose(domain, dual_domain, subdomains)
    sae_automation_level = _derive_sae_automation_level(domain, dual_domain, data_flow_role)

    input_digest = hashlib.sha256(
        json.dumps({
            "domain": domain,
            "dual_domain": dual_domain,
            "subdomains": subdomains,
            "consequences": consequences,
            "data_flow_role": data_flow_role,
            "actuator_sensor_role": actuator_sensor_role,
        }, sort_keys=True).encode()
    ).hexdigest()[:12]

    return {
        "controllability": controllability,
        "fallback_mechanism": fallback_mechanism,
        "degradation_mode": degradation_mode,
        "identification_purpose": identification_purpose,
        "sae_automation_level": sae_automation_level,
        "derivation_version": "heavens_v2_derivation_v1.1",
        "derivation_digest": input_digest,
    }


def _propagate_heavens_properties(merged_nodes):
    node_index = {node["ontology_id"]: node for node in merged_nodes}
    ecu_to_ontology = {}
    for node in merged_nodes:
        for ecu_id in node.get("mapped_ecus", []):
            ecu_to_ontology[ecu_id] = node["ontology_id"]

    def _get_downstream_ontology_ids(node):
        downstream = set()
        topo = node.get("topology", {})
        for ecu_id in topo.get("connected_ecus", []):
            oid = ecu_to_ontology.get(ecu_id)
            if oid and oid != node["ontology_id"]:
                downstream.add(oid)
        for crossing in topo.get("trust_boundary_crossings", []):
            dst_ecu = crossing.get("dst_ecu")
            oid = ecu_to_ontology.get(dst_ecu)
            if oid and oid != node["ontology_id"]:
                downstream.add(oid)
        return downstream

    for node in merged_nodes:
        hp = node.get("heavens_properties", {})
        local_ctrl_rating = hp.get("controllability", {}).get("rating", "C0")
        local_ctrl_rank = _CONTROLLABILITY_ORDER.get(local_ctrl_rating, 0)
        local_hcat = hp.get("identification_purpose", {}).get("heavens_category", "O")
        local_hcat_rank = _HEAVENS_CATEGORY_ORDER.get(local_hcat, 0)

        max_ctrl_rank = local_ctrl_rank
        max_ctrl_rating = local_ctrl_rating
        max_hcat_rank = local_hcat_rank
        max_hcat = local_hcat
        propagation_sources_ctrl = []
        propagation_sources_hcat = []

        downstream_ids = _get_downstream_ontology_ids(node)
        for ds_oid in downstream_ids:
            ds_node = node_index.get(ds_oid)
            if not ds_node:
                continue
            ds_hp = ds_node.get("heavens_properties", {})
            ds_ctrl = ds_hp.get("controllability", {}).get("rating", "C0")
            ds_ctrl_rank = _CONTROLLABILITY_ORDER.get(ds_ctrl, 0)
            ds_hcat = ds_hp.get("identification_purpose", {}).get("heavens_category", "O")
            ds_hcat_rank = _HEAVENS_CATEGORY_ORDER.get(ds_hcat, 0)

            if ds_ctrl_rank > max_ctrl_rank:
                max_ctrl_rank = ds_ctrl_rank
                max_ctrl_rating = ds_ctrl
                propagation_sources_ctrl = [ds_oid]
            elif ds_ctrl_rank == max_ctrl_rank and ds_oid not in propagation_sources_ctrl and ds_ctrl_rank > local_ctrl_rank:
                propagation_sources_ctrl.append(ds_oid)

            if ds_hcat_rank > max_hcat_rank:
                max_hcat_rank = ds_hcat_rank
                max_hcat = ds_hcat
                propagation_sources_hcat = [ds_oid]
            elif ds_hcat_rank == max_hcat_rank and ds_oid not in propagation_sources_hcat and ds_hcat_rank > local_hcat_rank:
                propagation_sources_hcat.append(ds_oid)

        ctrl_block = hp.get("controllability", {})
        if max_ctrl_rank > local_ctrl_rank:
            ctrl_block = dict(ctrl_block)
            ctrl_block["rating"] = max_ctrl_rating
            ctrl_block["propagated"] = True
            ctrl_block["propagated_from"] = propagation_sources_ctrl
            ctrl_block["local_rating"] = local_ctrl_rating
            ctrl_block["propagation_rationale"] = (
                "Downstream node(s) carry higher controllability rating; "
                "this enabling node inherits maximum downstream controllability per HEAVENS impact propagation"
            )
            hp = dict(hp)
            hp["controllability"] = ctrl_block

        node["heavens_properties"] = hp

    return merged_nodes


def load_architecture(path):
    with open(path, "r") as f:
        return json.load(f)


def build_topology_index(architecture):
    index = {
        "ecu_to_zone": {},
        "zone_to_trust": {},
        "ecu_to_buses": defaultdict(list),
        "ecu_to_outflows": defaultdict(list),
        "ecu_to_inflows": defaultdict(list),
        "interface_map": {},
        "bus_map": {},
    }

    for zone in architecture["trust_zones"]:
        index["zone_to_trust"][zone["id"]] = zone["trust_level"]

    for ecu in architecture["ecus"]:
        index["ecu_to_zone"][ecu["id"]] = ecu["trust_zone"]

    for bus in architecture["communication_buses"]:
        index["bus_map"][bus["id"]] = bus
        for ecu_id in bus["connected_ecus"]:
            index["ecu_to_buses"][ecu_id].append(bus["id"])

    for flow in architecture["data_flows"]:
        index["ecu_to_outflows"][flow["source"]].append(flow)
        index["ecu_to_inflows"][flow["destination"]].append(flow)

    for iface in architecture["external_interfaces"]:
        index["interface_map"][iface["id"]] = iface

    return index


def collect_mapped_interfaces(ecu_id, architecture):
    interface_ids = {i["id"] for i in architecture["external_interfaces"]}
    mapped = set()
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id and flow["destination"] in interface_ids:
            mapped.add(flow["destination"])
        if flow["destination"] == ecu_id and flow["source"] in interface_ids:
            mapped.add(flow["source"])
    return sorted(mapped)


def _get_ecu_trust_level(ecu_id, architecture):
    ecu = next((e for e in architecture["ecus"] if e["id"] == ecu_id), None)
    if not ecu:
        return 0
    zone = next((z for z in architecture["trust_zones"] if z["id"] == ecu["trust_zone"]), None)
    return zone["trust_level"] if zone else 0


def _get_ecu_buses(ecu_id, architecture):
    return frozenset(
        bus["id"]
        for bus in architecture["communication_buses"]
        if ecu_id in bus["connected_ecus"]
    )


def _get_ecu_interface_classes(ecu_id, architecture):
    adjacent = set()
    interface_ids = {i["id"] for i in architecture["external_interfaces"]}
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id and flow["destination"] in interface_ids:
            adjacent.add(flow["destination"])
        if flow["destination"] == ecu_id and flow["source"] in interface_ids:
            adjacent.add(flow["source"])
    classes = set()
    for iface_id in adjacent:
        iface = next((i for i in architecture["external_interfaces"] if i["id"] == iface_id), None)
        if iface:
            classes.add(iface.get("type", "unknown"))
    return frozenset(classes)


def _get_flow_role(ecu_id, architecture, node):
    return node["inference_evidence"].get("data_flow_role", {}).get("role", "unknown")


def _compute_merge_key(ecu_id, node, architecture):
    trust_level = _get_ecu_trust_level(ecu_id, architecture)
    buses = _get_ecu_buses(ecu_id, architecture)
    interface_classes = _get_ecu_interface_classes(ecu_id, architecture)
    flow_role = _get_flow_role(ecu_id, architecture, node)
    attack_surfaces = frozenset(node["attack_surface_classes"])
    subdomains = frozenset(node["subdomains"])

    return (
        node["functional_domain"],
        subdomains,
        attack_surfaces,
        flow_role,
        trust_level,
        interface_classes,
    )


def _derive_asset_target_properties(functional_domain, subdomains):
    if subdomains:
        subdomain = subdomains[0]
        key = f"{functional_domain}_{subdomain}"
        if key in ASSET_TARGET_PROPERTIES_MAP:
            return ASSET_TARGET_PROPERTIES_MAP[key]
    return ASSET_TARGET_PROPERTIES_MAP.get(functional_domain, {})


def _has_exposed_network_interface(ecu_id, architecture):
    interface_ids = {i["id"] for i in architecture["external_interfaces"]}
    for flow in architecture["data_flows"]:
        candidate = None
        if flow["source"] == ecu_id and flow["destination"] in interface_ids:
            candidate = flow["destination"]
        elif flow["destination"] == ecu_id and flow["source"] in interface_ids:
            candidate = flow["source"]
        if candidate:
            iface = next((i for i in architecture["external_interfaces"] if i["id"] == candidate), None)
            if iface and iface.get("type") in NETWORK_EXPOSED_INTERFACE_TYPES and iface.get("exposed", False):
                return True
    return False


def _is_transitively_remote_reachable(ecu_id, attack_surface_classes, architecture):
    if any(s in TRANSITIVE_REMOTE_ATTACKER_SURFACES for s in attack_surface_classes):
        return True
    if _has_exposed_network_interface(ecu_id, architecture):
        return True
    return False


def _derive_reachable_threat_actor_classes(attack_surface_classes, ecu_id=None, architecture=None):
    actors = []
    for surface in attack_surface_classes:
        for actor in ATTACK_SURFACE_ACTOR_MAP.get(surface, []):
            if actor not in actors:
                actors.append(actor)

    if ecu_id and architecture:
        if _is_transitively_remote_reachable(ecu_id, attack_surface_classes, architecture):
            if "remote_attacker" not in actors:
                actors.append("remote_attacker")

    return actors


def _augment_attack_surfaces_for_network_exposure(ecu_id, attack_surfaces, architecture):
    surfaces = list(attack_surfaces)
    if _has_exposed_network_interface(ecu_id, architecture):
        if "remote_network" not in surfaces:
            surfaces.append("remote_network")
    return surfaces


def _derive_entry_point(attack_surface_classes, zone_id, ecu_id=None, architecture=None):
    externally_reachable = bool(set(attack_surface_classes) & EXTERNALLY_REACHABLE_SURFACES)
    physical_only = "physical_access" in attack_surface_classes and not externally_reachable
    is_entry_point = externally_reachable or physical_only

    entry_point_types = []
    for surface in attack_surface_classes:
        ep_type = ENTRY_POINT_SURFACE_TYPES.get(surface)
        if ep_type and ep_type not in entry_point_types:
            entry_point_types.append(ep_type)

    derivation_parts = []
    for surface in attack_surface_classes:
        if surface in EXTERNALLY_REACHABLE_SURFACES or surface == "physical_access":
            derivation_parts.append(f"attack_surface:{surface}")
    if zone_id:
        derivation_parts.append(f"trust_zone:{zone_id}")

    transitive_remote = False
    if ecu_id and architecture:
        transitive_remote = _is_transitively_remote_reachable(ecu_id, attack_surface_classes, architecture)
        if transitive_remote and "remote_ip" not in entry_point_types:
            entry_point_types.append("remote_ip")
            if "transitive_network_exposure" not in derivation_parts:
                derivation_parts.append("transitive_network_exposure")

    return {
        "is_entry_point": is_entry_point,
        "entry_point_types": entry_point_types,
        "externally_reachable": externally_reachable,
        "transitive_remote_reachable": transitive_remote,
        "reachability_derivation": " + ".join(derivation_parts) if derivation_parts else "none",
    }


def _infer_dual_domain(functional_domain, subdomains, confidence, evidence_record):
    base_dual = _DUAL_DOMAIN_RULES.get(functional_domain)
    if base_dual:
        return base_dual
    return None


def _differentiate_damage_seeds(damage_seeds, ecu_id, subdomains):
    if not damage_seeds:
        return damage_seeds

    tokens = set(ecu_id.lower().replace("_", " ").split())
    differentiator = None

    for subdomain in (subdomains or []):
        inst_map = _INSTANCE_DIFFERENTIATORS.get(subdomain, {})
        for key, label in inst_map.items():
            if key in tokens:
                differentiator = label
                break
        if differentiator:
            break

    if not differentiator:
        return damage_seeds

    result = []
    for seed in damage_seeds:
        if differentiator.lower() not in seed.lower():
            if "from " in seed:
                parts = seed.split("from ", 1)
                seed = parts[0] + f"from {differentiator} " + parts[1]
            else:
                seed = seed + f" ({differentiator})"
        result.append(seed)
    return result


def _collect_protocols_for_ecu(ecu_id, architecture):
    protocols_seen = []
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id or flow["destination"] == ecu_id:
            transport = flow["protocol"].get("transport", "NONE")
            application = flow["protocol"].get("application", "NONE")
            proto_str = f"{transport}/{application}"
            if proto_str not in protocols_seen:
                protocols_seen.append(proto_str)
    return protocols_seen


def _normalise_capec_ref_fields(capec_cwe_refs):
    for ref in capec_cwe_refs:
        if not ref.get("severity") or (isinstance(ref.get("severity"), str) and ref["severity"].strip() == ""):
            ref["severity"] = "Unknown"
        if not ref.get("likelihood") or (isinstance(ref.get("likelihood"), str) and ref["likelihood"].strip() == ""):
            ref["likelihood"] = "Unknown"
    return capec_cwe_refs


def _augment_r155_for_subdomains(subdomains, r155_sources):
    augmented = list(r155_sources)
    if "occupant_sensing" in subdomains:
        for entry in OCCUPANT_SENSING_R155:
            if entry not in augmented:
                augmented.append(entry)
    return augmented


_SFOP_ASIL_PHYSICAL_HARM = {
    "ASIL-D": "S3",
    "ASIL-C": "S3",
    "ASIL-B": "S2",
    "ASIL-A": "S1",
    "QM":     "S0",
}

_SFOP_DEGRADATION_OPERATIONAL = {
    "reduced_authority_control":  "complete",
    "passive_safe_state":         "complete",
    "driver_takeover_request":    "complete",
    "sensor_fusion_exclusion":    "partial",
    "limp_home":                  "partial",
    "default_deny_routing":       "partial",
    "charge_session_abort":       "partial",
    "passive_immobiliser":        "minor",
    "session_termination":        "minor",
    "data_suppression":           "minor",
    "safe_state_default":         "minor",
}

_SFOP_HEAVENS_PRIMARY_CATEGORY = {
    "S": "Safety",
    "O": "Operational",
    "P": "Privacy",
    "F": "Financial",
}

_SFOP_CONSEQUENCE_SIGNALS = {
    "physical_harm_keywords": {
        "unintended_braking", "loss_of_deceleration_control", "unintended_steering",
        "uncontrolled_lateral_motion", "false_airbag_deployment",
        "airbag_suppression_in_collision", "seatbelt_pretensioner_attack",
        "uncontrolled_torque_output", "thermal_runaway_enablement",
        "hv_system_compromise",
    },
    "financial_keywords": {
        "charging_system_manipulation", "immobilizer_bypass",
        "relay_attack_enablement", "unauthorized_vehicle_unlock",
        "authentication_bypass",
    },
    "privacy_keywords": {
        "occupant_state_falsification", "presence_detection_bypass",
        "biometric",
    },
    "operational_keywords": {
        "routing_manipulation", "cross_domain_lateral_movement",
        "sensor_data_spoofing", "false_object_injection",
        "sensor_blinding", "safety_decision_corruption",
        "safety_function_unavailability", "unauthorized_privileged_access",
    },
}

_SFOP_FINANCIAL_CONSEQUENCE_MAP = {
    "charging_system_manipulation": "repair_or_recall",
    "thermal_runaway_enablement":   "repair_or_recall",
    "hv_system_compromise":         "repair_or_recall",
    "immobilizer_bypass":           "theft_or_fraud",
    "relay_attack_enablement":      "theft_or_fraud",
    "unauthorized_vehicle_unlock":  "theft_or_fraud",
    "authentication_bypass":        "theft_or_fraud",
}

_SFOP_S_LEVEL_FROM_HARM = {
    True:  "S3",
    False: "S0",
}

_SFOP_F_LEVEL_MAP = {
    "repair_or_recall": "F3",
    "theft_or_fraud":   "F3",
    "service_cost":     "F2",
    None:               "F1",
}

_SFOP_O_LEVEL_MAP = {
    "complete": "O3",
    "partial":  "O2",
    "minor":    "O1",
    None:       "O1",
}

_SFOP_P_LEVEL_MAP = {
    True:  "P3",
    False: "P0",
}


def _build_sfop_evidence(degradation_mode, asil, heavens_category, identification_purpose, consequences):
    conseq_set = set(consequences) if consequences else set()

    physical_harm_possible = bool(
        conseq_set & _SFOP_CONSEQUENCE_SIGNALS["physical_harm_keywords"]
    )
    loss_of_vehicle_control = physical_harm_possible and asil in ("ASIL-D", "ASIL-C")
    fallback_available = degradation_mode not in (
        "reduced_authority_control", "passive_safe_state", "driver_takeover_request"
    )
    operational_disruption = _SFOP_DEGRADATION_OPERATIONAL.get(degradation_mode)
    privacy_relevant = heavens_category == "P"
    privacy_data_exposed = bool(
        conseq_set & _SFOP_CONSEQUENCE_SIGNALS["privacy_keywords"]
    )
    financial_consequence = next(
        (_SFOP_FINANCIAL_CONSEQUENCE_MAP[c] for c in conseq_set if c in _SFOP_FINANCIAL_CONSEQUENCE_MAP),
        None,
    )

    return {
        "physical_harm_possible":   physical_harm_possible,
        "loss_of_vehicle_control":  loss_of_vehicle_control,
        "fallback_available":       fallback_available,
        "operational_disruption":   operational_disruption,
        "privacy_relevant":         privacy_relevant,
        "privacy_data_exposed":     privacy_data_exposed,
        "financial_consequence":    financial_consequence,
        "asil_source":              asil,
        "heavens_category_source":  heavens_category,
        "identification_purpose":   identification_purpose,
        "degradation_mode_source":  degradation_mode,
    }


def _sfop_levels_from_evidence(evidence):
    asil = evidence["asil_source"]
    hcat = evidence["heavens_category_source"]
    op   = evidence["operational_disruption"]

    if evidence["loss_of_vehicle_control"] and not evidence["fallback_available"]:
        s_level = "S3"
    elif evidence["physical_harm_possible"]:
        s_level = _SFOP_ASIL_PHYSICAL_HARM.get(asil, "S1")
    else:
        s_level = "S0"

    f_level = _SFOP_F_LEVEL_MAP.get(evidence["financial_consequence"], "F1")

    o_level = _SFOP_O_LEVEL_MAP.get(op, "O1")

    if evidence["privacy_data_exposed"]:
        p_level = "P3"
    elif evidence["privacy_relevant"]:
        p_level = "P2"
    else:
        p_level = "P0"

    return s_level, f_level, o_level, p_level


def _sfop_primary_category_from_evidence(evidence):
    hcat = evidence["heavens_category_source"]
    mapped = _SFOP_HEAVENS_PRIMARY_CATEGORY.get(hcat)
    if mapped:
        return mapped
    if evidence["physical_harm_possible"]:
        return "Safety"
    if evidence["privacy_data_exposed"]:
        return "Privacy"
    return "Operational"


def _derive_sfop_metadata(functional_domain, dual_domain, consequences,
                          degradation_mode=None, asil=None,
                          heavens_category=None, identification_purpose=None):
    if degradation_mode is not None and asil is not None and heavens_category is not None:
        evidence = _build_sfop_evidence(
            degradation_mode, asil, heavens_category,
            identification_purpose or "", consequences,
        )
        s_level, f_level, o_level, p_level = _sfop_levels_from_evidence(evidence)
        sfop_primary_category = _sfop_primary_category_from_evidence(evidence)
        harm_severity = {
            "physical_harm":         s_level,
            "operational_disruption": o_level,
        }
        financial_severity = {
            "physical_harm":         f_level,
            "operational_disruption": f_level,
        }
        operational_severity = {
            "physical_harm":         o_level,
            "operational_disruption": o_level,
        }
        privacy_severity = {
            "physical_harm":         p_level,
            "operational_disruption": p_level,
        }
        return sfop_primary_category, harm_severity, financial_severity, operational_severity, privacy_severity, evidence

    domain_entry = SFOP_DOMAIN_MAP.get(functional_domain) or SFOP_DOMAIN_MAP.get(dual_domain) or {}
    sfop_primary_category = domain_entry.get("sfop_primary_category", "Operational")
    harm_severity = dict(domain_entry.get("harm_severity", {}))
    financial_severity = dict(domain_entry.get("financial_severity", {}))
    operational_severity = dict(domain_entry.get("operational_severity", {}))
    privacy_severity = dict(domain_entry.get("privacy_severity", {}))

    conseq_str = " ".join(consequences).lower() if consequences else ""
    if not harm_severity:
        if any(k in conseq_str for k in ["safety", "harm", "crash", "fire", "thermal", "injury", "death"]):
            harm_severity.setdefault("physical_harm", "S3")
            harm_severity.setdefault("operational_disruption", "S2")
        elif any(k in conseq_str for k in ["privacy", "biometric", "disclosure", "personal"]):
            harm_severity.setdefault("physical_harm", "S0")
            harm_severity.setdefault("operational_disruption", "S1")
        else:
            harm_severity.setdefault("physical_harm", "S1")
            harm_severity.setdefault("operational_disruption", "S1")

    return sfop_primary_category, harm_severity, financial_severity, operational_severity, privacy_severity, None


def generate_ontology_node(ecu_id, ontology_id_counter, architecture, capec_index):
    inference = infer_functional_domain(ecu_id, architecture)

    domain = inference["functional_domain"]
    subdomains = inference["subdomains"]
    confidence = inference["confidence"]
    evidence_record = inference["evidence_record"]
    justification = inference["justification"]

    dual_domain = _infer_dual_domain(domain, subdomains, confidence, evidence_record)

    cyber_props = CYBERSECURITY_DOMAIN_MAP.get(domain, {
        "primary": ["Integrity"],
        "secondary": [],
        "derivation": "Default: integrity is the baseline cybersecurity property",
    })
    cyber_props = dict(cyber_props)
    cyber_props["primary"] = list(cyber_props.get("primary", []))
    cyber_props["secondary"] = list(cyber_props.get("secondary", []))

    consequences, damage_seeds, attack_surfaces = infer_consequences(
        domain, subdomains, cyber_props
    )

    attack_surfaces = _augment_attack_surfaces_for_network_exposure(ecu_id, attack_surfaces, architecture)

    damage_seeds = _differentiate_damage_seeds(damage_seeds, ecu_id, subdomains)

    r155_sources = R155_THREAT_MAP.get(domain, [])
    r155_sources = _augment_r155_for_subdomains(subdomains, r155_sources)
    sources = r155_sources + ["ISO/SAE 21434 Clause 8.3"]

    mapped_interfaces = collect_mapped_interfaces(ecu_id, architecture)

    ontology_id = f"FUNC-{ontology_id_counter:03d}"

    ecu = next((e for e in architecture["ecus"] if e["id"] == ecu_id), None)
    zone_id = ecu["trust_zone"] if ecu else None

    asset_target_properties = _derive_asset_target_properties(domain, subdomains)
    reachable_threat_actor_classes = _derive_reachable_threat_actor_classes(attack_surfaces, ecu_id, architecture)
    entry_point = _derive_entry_point(attack_surfaces, zone_id, ecu_id, architecture)

    protocols_seen = _collect_protocols_for_ecu(ecu_id, architecture)

    capec_cwe_refs = build_capec_refs(
        attack_surfaces, cyber_props, consequences, r155_sources, capec_index,
        subdomains=subdomains,
        protocols_seen=protocols_seen,
    )
    capec_cwe_refs = _normalise_capec_ref_fields(capec_cwe_refs)

    sfop_primary_category, harm_severity, financial_severity, operational_severity, privacy_severity, sfop_evidence = _derive_sfop_metadata(
        domain, dual_domain, consequences,
    )

    node = {
        "ontology_id": ontology_id,
        "functional_domain": domain,
        "subdomains": subdomains,
        "confidence": confidence,
        "dual_domain": dual_domain,
        "mapped_ecus": [ecu_id],
        "mapped_interfaces": mapped_interfaces,
        "sfop_primary_category": sfop_primary_category,
        "harm_severity": harm_severity,
        "financial_severity": financial_severity,
        "operational_severity": operational_severity,
        "privacy_severity": privacy_severity,
        "sfop_evidence": sfop_evidence,
        "inference_evidence": {
            "trust_zone_signal":    evidence_record.get("trust_zone_signal"),
            "data_flow_role":       evidence_record.get("data_flow_role"),
            "interface_proximity":  evidence_record.get("interface_proximity"),
            "protocol_signal":      evidence_record.get("protocol_signal"),
            "bus_membership":       evidence_record.get("bus_membership"),
            "lexical_tokens":       evidence_record.get("lexical_tokens"),
            "actuator_sensor_role": evidence_record.get("actuator_sensor_role"),
        },
        "cybersecurity_properties": {
            "primary":    cyber_props["primary"],
            "secondary":  cyber_props["secondary"],
            "derivation": cyber_props["derivation"],
        },
        "functional_consequences": consequences,
        "damage_scenario_seeds": damage_seeds,
        "attack_surface_classes": attack_surfaces,
        "asset_target_properties": asset_target_properties,
        "reachable_threat_actor_classes": reachable_threat_actor_classes,
        "entry_point": entry_point,
        "provenance": {
            "source":             sources,
            "reference_standards": REFERENCE_STANDARDS,
            "justification":      justification,
            "inference_method":   "weighted_evidence_convergence_v2",
            "deterministic":      True,
        },
        "capec_cwe_refs": capec_cwe_refs,
    }

    node["heavens_properties"] = _derive_heavens_properties(node, architecture)

    _hp = node["heavens_properties"]
    _dm = _hp.get("degradation_mode", {}).get("mode")
    _asil = _hp.get("degradation_mode", {}).get("iso26262_asil")
    _hcat = _hp.get("identification_purpose", {}).get("heavens_category")
    _ipurpose = _hp.get("identification_purpose", {}).get("purpose")
    (
        node["sfop_primary_category"],
        node["harm_severity"],
        node["financial_severity"],
        node["operational_severity"],
        node["privacy_severity"],
        node["sfop_evidence"],
    ) = _derive_sfop_metadata(
        domain, dual_domain, consequences,
        degradation_mode=_dm,
        asil=_asil,
        heavens_category=_hcat,
        identification_purpose=_ipurpose,
    )

    return node


def merge_nodes_by_domain(nodes, architecture):
    merge_groups = defaultdict(list)

    for node in nodes:
        ecu_id = node["mapped_ecus"][0]
        merge_key = _compute_merge_key(ecu_id, node, architecture)
        merge_groups[merge_key].append(node)

    merged = []
    for merge_key, group in merge_groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        base = group[0]
        all_ecus = []
        all_interfaces = []
        all_consequences = []
        all_damage_seeds = []
        all_attack_surfaces = []
        min_confidence = 1.0

        for n in group:
            all_ecus.extend(n["mapped_ecus"])
            all_interfaces.extend(n["mapped_interfaces"])
            all_consequences.extend(n["functional_consequences"])
            all_damage_seeds.extend(n["damage_scenario_seeds"])
            all_attack_surfaces.extend(n["attack_surface_classes"])
            if n["confidence"] < min_confidence:
                min_confidence = n["confidence"]

        domain = base["functional_domain"]
        subdomains = base["subdomains"]
        base["mapped_ecus"] = sorted(set(all_ecus))
        base["mapped_interfaces"] = sorted(set(all_interfaces))
        base["functional_consequences"] = list(dict.fromkeys(all_consequences))
        base["damage_scenario_seeds"] = list(dict.fromkeys(all_damage_seeds))
        base["attack_surface_classes"] = list(dict.fromkeys(all_attack_surfaces))
        base["confidence"] = round(min_confidence, 4)
        base["asset_target_properties"] = _derive_asset_target_properties(domain, subdomains)
        base["reachable_threat_actor_classes"] = _derive_reachable_threat_actor_classes(
            base["attack_surface_classes"],
            base["mapped_ecus"][0] if base["mapped_ecus"] else None,
            architecture,
        )
        base["entry_point"] = _derive_entry_point(
            base["attack_surface_classes"],
            None,
            base["mapped_ecus"][0] if base["mapped_ecus"] else None,
            architecture,
        )
        base["provenance"]["justification"] = (
            f"Merged node for {domain} covering ECUs: {', '.join(base['mapped_ecus'])}"
        )

        base["heavens_properties"] = _derive_heavens_properties(base, architecture)

        _mhp = base["heavens_properties"]
        _mdm = _mhp.get("degradation_mode", {}).get("mode")
        _masil = _mhp.get("degradation_mode", {}).get("iso26262_asil")
        _mhcat = _mhp.get("identification_purpose", {}).get("heavens_category")
        _mipurpose = _mhp.get("identification_purpose", {}).get("purpose")
        (
            base["sfop_primary_category"],
            base["harm_severity"],
            base["financial_severity"],
            base["operational_severity"],
            base["privacy_severity"],
            base["sfop_evidence"],
        ) = _derive_sfop_metadata(
            domain,
            base.get("dual_domain"),
            base["functional_consequences"],
            degradation_mode=_mdm,
            asil=_masil,
            heavens_category=_mhcat,
            identification_purpose=_mipurpose,
        )

        merged.append(base)

    return merged


def _normalise_via_flows(via_flows, valid_ecu_ids):
    normalised = []
    for entry in via_flows:
        if entry in valid_ecu_ids:
            if entry not in normalised:
                normalised.append(entry)
    return normalised


def _annotate_trust_crossings(crossings):
    annotated = []
    for c in crossings:
        sl = c.get("src_trust_level", 0)
        dl = c.get("dst_trust_level", 0)
        if sl > dl:
            direction = "HIGH_TO_LOW"
        elif sl < dl:
            direction = "LOW_TO_HIGH_ESCALATION"
        else:
            direction = "SAME_LEVEL"
        annotated.append({
            "src_ecu": c["src_ecu"],
            "dst_ecu": c["dst_ecu"],
            "src_trust_level": sl,
            "dst_trust_level": dl,
            "direction": direction,
        })
    return annotated


def build_topology_links(topology_index, ecu_ids, architecture):
    ecu_set = set(ecu_ids)
    links = {eid: {"connected_ecus": set(), "via_buses": [], "via_flows": []} for eid in ecu_set}

    for bus_id, bus_data in topology_index["bus_map"].items():
        members = [e for e in bus_data.get("connected_ecus", []) if e in ecu_set]
        for i, src in enumerate(members):
            for dst in members[i + 1:]:
                links[src]["connected_ecus"].add(dst)
                links[dst]["connected_ecus"].add(src)
                if bus_id not in links[src]["via_buses"]:
                    links[src]["via_buses"].append(bus_id)
                if bus_id not in links[dst]["via_buses"]:
                    links[dst]["via_buses"].append(bus_id)

    for ecu_id, outflows in topology_index["ecu_to_outflows"].items():
        if ecu_id not in ecu_set:
            continue
        for flow in outflows:
            dest = flow["destination"]
            if dest in ecu_set and dest != ecu_id:
                links[ecu_id]["connected_ecus"].add(dest)
                links[dest]["connected_ecus"].add(ecu_id)
                if dest not in links[ecu_id]["via_flows"]:
                    links[ecu_id]["via_flows"].append(dest)
                if ecu_id not in links[dest]["via_flows"]:
                    links[dest]["via_flows"].append(ecu_id)

    for iface_id, iface_data in topology_index["interface_map"].items():
        if iface_data.get("type") not in NETWORK_EXPOSED_INTERFACE_TYPES:
            continue
        if not iface_data.get("exposed", False):
            continue
        connected_ecus_via_iface = []
        for ecu_id in ecu_set:
            for flow in topology_index["ecu_to_outflows"].get(ecu_id, []):
                if flow["destination"] == iface_id:
                    connected_ecus_via_iface.append(ecu_id)
            for flow in topology_index["ecu_to_inflows"].get(ecu_id, []):
                if flow["source"] == iface_id:
                    connected_ecus_via_iface.append(ecu_id)
        for idx, src in enumerate(connected_ecus_via_iface):
            for dst in connected_ecus_via_iface[idx + 1:]:
                if src != dst:
                    links[src]["connected_ecus"].add(dst)
                    links[dst]["connected_ecus"].add(src)
                    if dst not in links[src]["via_flows"]:
                        links[src]["via_flows"].append(dst)
                    if src not in links[dst]["via_flows"]:
                        links[dst]["via_flows"].append(src)

    for ecu_id in ecu_set:
        zone_id = topology_index["ecu_to_zone"].get(ecu_id, "UNKNOWN")
        trust_level = topology_index["zone_to_trust"].get(zone_id, 0)
        links[ecu_id]["trust_zone"] = zone_id
        links[ecu_id]["trust_level"] = trust_level
        links[ecu_id]["connected_ecus"] = sorted(links[ecu_id]["connected_ecus"])

    for ecu_id in ecu_set:
        src_trust = links[ecu_id]["trust_level"]
        crossings = []
        for peer in links[ecu_id]["connected_ecus"]:
            dst_trust = links.get(peer, {}).get("trust_level", 0)
            if src_trust != dst_trust:
                sl = src_trust
                dl = dst_trust
                direction = "HIGH_TO_LOW" if sl > dl else "LOW_TO_HIGH_ESCALATION"
                crossings.append({
                    "src_ecu": ecu_id,
                    "dst_ecu": peer,
                    "src_trust_level": sl,
                    "dst_trust_level": dl,
                    "direction": direction,
                })
        links[ecu_id]["trust_boundary_crossings"] = crossings

    return links


def generate_full_ontology(architecture_path, output_path, capec_path=None):
    architecture = load_architecture(architecture_path)
    topology_index = build_topology_index(architecture)
    capec_index = load_capec_index(capec_path)

    ecu_ids = [ecu["id"] for ecu in architecture["ecus"]]
    topology_links = build_topology_links(topology_index, ecu_ids, architecture)

    raw_nodes = []
    counter = 1
    for ecu in architecture["ecus"]:
        node = generate_ontology_node(ecu["id"], counter, architecture, capec_index)
        raw_nodes.append(node)
        counter += 1

    merged_nodes = merge_nodes_by_domain(raw_nodes, architecture)

    for idx, node in enumerate(merged_nodes, start=1):
        node["ontology_id"] = f"FUNC-{idx:03d}"

    valid_ecu_ids = set(ecu_ids)

    for node in merged_nodes:
        node_ecus = node["mapped_ecus"]
        node_ecu_set = set(node_ecus)
        connected_ecus = set()
        via_buses = []
        via_flows_raw = []
        trust_boundary_crossings = []
        seen_crossing_keys = set()

        for ecu_id in node_ecus:
            link = topology_links.get(ecu_id, {})
            connected_ecus.update(link.get("connected_ecus", []))
            for b in link.get("via_buses", []):
                if b not in via_buses:
                    via_buses.append(b)
            for f in link.get("via_flows", []):
                if f not in via_flows_raw:
                    via_flows_raw.append(f)
            for crossing in link.get("trust_boundary_crossings", []):
                if crossing["dst_ecu"] in node_ecu_set:
                    continue
                key = (crossing["src_ecu"], crossing["dst_ecu"])
                if key not in seen_crossing_keys:
                    seen_crossing_keys.add(key)
                    trust_boundary_crossings.append(crossing)

        connected_ecus -= node_ecu_set
        via_flows = _normalise_via_flows(via_flows_raw, valid_ecu_ids)

        node["topology"] = {
            "connected_ecus":           sorted(connected_ecus),
            "via_buses":                sorted(via_buses),
            "via_flows":                sorted(via_flows),
            "trust_boundary_crossings": trust_boundary_crossings,
        }

        node["heavens_properties"] = _derive_heavens_properties(node, architecture)

        _thp = node["heavens_properties"]
        _tdm = _thp.get("degradation_mode", {}).get("mode")
        _tasil = _thp.get("degradation_mode", {}).get("iso26262_asil")
        _thcat = _thp.get("identification_purpose", {}).get("heavens_category")
        _tipurpose = _thp.get("identification_purpose", {}).get("purpose")
        (
            node["sfop_primary_category"],
            node["harm_severity"],
            node["financial_severity"],
            node["operational_severity"],
            node["privacy_severity"],
            node["sfop_evidence"],
        ) = _derive_sfop_metadata(
            node["functional_domain"],
            node.get("dual_domain"),
            node["functional_consequences"],
            degradation_mode=_tdm,
            asil=_tasil,
            heavens_category=_thcat,
            identification_purpose=_tipurpose,
        )

    merged_nodes = _propagate_heavens_properties(merged_nodes)

    ontology = {
        "ontology_version":  "1.7",
        "inference_method":  "weighted_evidence_convergence_v2",
        "heavens_derivation_version": "heavens_v2_derivation_v1.1",
        "item_id":           architecture["item_definition"]["item_id"],
        "item_name":         architecture["item_definition"]["item_name"],
        "node_count":        len(merged_nodes),
        "nodes":             merged_nodes,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(ontology, f, indent=2)

    print(f"[ontology_generator] v1.7 — {len(merged_nodes)} nodes → {output_path}")
    _print_heavens_summary(merged_nodes)
    return ontology


def _print_heavens_summary(nodes):
    from collections import Counter
    c_dist = Counter()
    s_dist = Counter()
    l_dist = Counter()
    p_dist = Counter()
    fb_dist = Counter()
    prop_ctrl = 0
    prop_hcat = 0
    for node in nodes:
        hp = node.get("heavens_properties", {})
        c_dist[hp.get("controllability", {}).get("rating", "?")] += 1
        s_dist[hp.get("sae_automation_level", {}).get("level", "?")] += 1
        l_dist[hp.get("identification_purpose", {}).get("heavens_category", "?")] += 1
        p_dist[hp.get("degradation_mode", {}).get("iso26262_asil", "?")] += 1
        fb_dist[hp.get("fallback_mechanism", {}).get("profile_class", "?")] += 1
        if hp.get("controllability", {}).get("propagated"):
            prop_ctrl += 1
        if hp.get("identification_purpose", {}).get("propagated"):
            prop_hcat += 1
    print(f"  Controllability:           {dict(c_dist)}")
    print(f"  SAE levels:                {dict(s_dist)}")
    print(f"  HEAVENS categories:        {dict(l_dist)}")
    print(f"  ISO 26262 ASIL:            {dict(p_dist)}")
    print(f"  Fallback profile classes:  {dict(fb_dist)}")
    print(f"  Propagated controllability:{prop_ctrl} node(s)")
    print(f"  Propagated HEAVENS cat.:   {prop_hcat} node(s)")
    s_sfop = Counter()
    o_sfop = Counter()
    f_sfop = Counter()
    p_sfop = Counter()
    for node in nodes:
        s_sfop[node.get("harm_severity", {}).get("physical_harm", "?")] += 1
        o_sfop[node.get("operational_severity", {}).get("physical_harm", "?")] += 1
        f_sfop[node.get("financial_severity", {}).get("physical_harm", "?")] += 1
        p_sfop[node.get("privacy_severity", {}).get("physical_harm", "?")] += 1
    print(f"  S distribution (harm):     {dict(sorted(s_sfop.items()))}")
    print(f"  O distribution (oper):     {dict(sorted(o_sfop.items()))}")
    print(f"  F distribution (fin):      {dict(sorted(f_sfop.items()))}")
    print(f"  P distribution (priv):     {dict(sorted(p_sfop.items()))}")


if __name__ == "__main__":
    architecture_path = sys.argv[1] if len(sys.argv) > 1 else "architecture.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "output/functional_automotive_ontology.json"
    capec_path = sys.argv[3] if len(sys.argv) > 3 else None
    generate_full_ontology(architecture_path, output_path, capec_path)