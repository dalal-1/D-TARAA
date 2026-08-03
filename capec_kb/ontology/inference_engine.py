from collections import defaultdict
from ontology_taxonomy import (
    FUNCTIONAL_DOMAINS,
    SUBDOMAIN_MAP,
    TRUST_ZONE_NAME_SIGNALS,
    CYBERSECURITY_DOMAIN_MAP,
    R155_THREAT_MAP,
    REFERENCE_STANDARDS,
    INTERFACE_PROXIMITY_SIGNALS,
    LEXICAL_VOCABULARY,
)
from signal_extractors import (
    extract_trust_zone_signal,
    extract_bus_participation_signal,
    extract_data_flow_role_signal,
    extract_interface_proximity_signal,
    extract_protocol_signal,
    extract_lexical_signal,
    extract_actuator_sensor_type_signal,
)


AMBIGUITY_THRESHOLD = 0.10

SIGNAL_WEIGHT_NAMES = {
    "trust_zone_signal": 0.25,
    "data_flow_role": 0.25,
    "interface_proximity": 0.20,
    "protocol_signal": 0.15,
    "bus_membership": 0.10,
    "lexical_tokens": 0.03,
    "actuator_sensor_role": 0.02,
}

MAX_POSSIBLE_EVIDENCE = sum(SIGNAL_WEIGHT_NAMES.values())
CONFIDENCE_SPARSITY_PENALTY_THRESHOLD = 2
CONFIDENCE_SPARSITY_PENALTY_FACTOR = 0.80

FUNCTIONAL_ROLE_ARCHETYPES = {
    "PURE_SENSOR_PRODUCER",
    "PURE_ACTUATOR_CONSUMER",
    "SUPERVISORY_CONTROLLER",
    "BUS_BRIDGE",
    "AUTHENTICATION_GATEKEEPER",
    "ENERGY_MANAGER",
    "SERVICE_INTERFACE",
    "AMBIGUOUS",
}

SAFETY_CRITICAL_TRUST_ZONES = {"TZ-BRAKE", "TZ-STEERING", "TZ-SRS", "TZ-POWERTRAIN"}
MOTION_CONTROL_TRUST_ZONES = {"TZ-BRAKE", "TZ-STEERING"}

DIAGNOSTIC_AUXILIARY_DOMAINS = {
    "VEHICLE_MOTION_CONTROL",
    "POWERTRAIN_MANAGEMENT",
    "OCCUPANT_SAFETY_SYSTEMS",
    "AUTOMATED_DRIVING_CONTROL",
    "PERCEPTION_AND_SENSING",
    "NETWORK_GATEWAYING",
    "VEHICLE_ACCESS_CONTROL",
    "TELEMATICS_AND_CONNECTIVITY",
    "BODY_AND_COMFORT",
}

DIAGNOSTIC_SIGNAL_PENALTY = 0.45

MOTION_CONTROL_DOMAINS = {
    "VEHICLE_MOTION_CONTROL",
    "AUTOMATED_DRIVING_CONTROL",
    "POWERTRAIN_MANAGEMENT",
    "OCCUPANT_SAFETY_SYSTEMS",
}

PRIMARY_FUNCTION_DOMAINS = {
    "VEHICLE_MOTION_CONTROL",
    "POWERTRAIN_MANAGEMENT",
    "OCCUPANT_SAFETY_SYSTEMS",
    "AUTOMATED_DRIVING_CONTROL",
    "PERCEPTION_AND_SENSING",
    "NETWORK_GATEWAYING",
    "VEHICLE_ACCESS_CONTROL",
    "TELEMATICS_AND_CONNECTIVITY",
    "BODY_AND_COMFORT",
}


def _tokenize_ecu_id(ecu_id):
    import re
    parts = re.split(r"[_\-]", ecu_id)
    tokens = set()
    for part in parts:
        if part.isupper():
            tokens.add(part.lower())
        else:
            camel_parts = re.sub(r"([A-Z])", r"_\1", part).split("_")
            tokens.update(p.lower() for p in camel_parts if p)
    return tokens


def _get_ecu_zone(ecu_id, architecture):
    ecu = next((e for e in architecture["ecus"] if e["id"] == ecu_id), None)
    if not ecu:
        return None, 0
    zone_id = ecu["trust_zone"]
    zone = next((z for z in architecture["trust_zones"] if z["id"] == zone_id), None)
    trust_level = zone["trust_level"] if zone else 0
    return zone_id, trust_level


def _get_connected_buses(ecu_id, architecture):
    return [bus["id"] for bus in architecture["communication_buses"] if ecu_id in bus["connected_ecus"]]


def _get_buses_crossing_trust_boundaries(ecu_id, buses, architecture):
    ecu_zone, _ = _get_ecu_zone(ecu_id, architecture)
    crossing = []
    for bus_id in buses:
        bus = next((b for b in architecture["communication_buses"] if b["id"] == bus_id), None)
        if not bus:
            continue
        zones_on_bus = set()
        for member_id in bus.get("connected_ecus", []):
            member_zone, _ = _get_ecu_zone(member_id, architecture)
            if member_zone:
                zones_on_bus.add(member_zone)
        if len(zones_on_bus) > 1:
            crossing.append(bus_id)
    return crossing


def _get_outflow_destinations(ecu_id, architecture):
    interface_ids = {i["id"] for i in architecture["external_interfaces"]}
    ecu_ids = {e["id"] for e in architecture["ecus"]}
    iface_dests = []
    ecu_dests = []
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id:
            d = flow["destination"]
            if d in interface_ids:
                iface_dests.append(d)
            elif d in ecu_ids:
                ecu_dests.append(d)
    return iface_dests, ecu_dests


def _get_inflow_sources(ecu_id, architecture):
    interface_ids = {i["id"] for i in architecture["external_interfaces"]}
    ecu_ids = {e["id"] for e in architecture["ecus"]}
    iface_sources = []
    ecu_sources = []
    for flow in architecture["data_flows"]:
        if flow["destination"] == ecu_id:
            s = flow["source"]
            if s in interface_ids:
                iface_sources.append(s)
            elif s in ecu_ids:
                ecu_sources.append(s)
    return iface_sources, ecu_sources


def _interface_type(iface_id, architecture):
    iface = next((i for i in architecture["external_interfaces"] if i["id"] == iface_id), None)
    return iface.get("type", "unknown") if iface else "unknown"


def _has_actuator_outputs(ecu_id, architecture):
    iface_dests, _ = _get_outflow_destinations(ecu_id, architecture)
    return any(_interface_type(d, architecture) == "actuator" for d in iface_dests)


def _has_sensor_inputs(ecu_id, architecture):
    iface_sources, _ = _get_inflow_sources(ecu_id, architecture)
    return any(_interface_type(s, architecture) == "sensor" for s in iface_sources)


def _has_wireless_inputs(ecu_id, architecture):
    iface_sources, _ = _get_inflow_sources(ecu_id, architecture)
    return any(_interface_type(s, architecture) == "wireless" for s in iface_sources)


def _has_diagnostic_interfaces(ecu_id, architecture):
    iface_dests, _ = _get_outflow_destinations(ecu_id, architecture)
    iface_sources, _ = _get_inflow_sources(ecu_id, architecture)
    all_ifaces = iface_dests + iface_sources
    return any(_interface_type(i, architecture) == "diagnostic" for i in all_ifaces)


def _has_hv_interfaces(ecu_id, architecture):
    iface_dests, _ = _get_outflow_destinations(ecu_id, architecture)
    iface_sources, _ = _get_inflow_sources(ecu_id, architecture)
    all_ifaces = iface_dests + iface_sources
    return any("HV" in i.upper() for i in all_ifaces)


def _bridges_multiple_buses(ecu_id, architecture):
    return len(_get_connected_buses(ecu_id, architecture)) > 1


def _is_pure_sensor_producer(ecu_id, architecture, flow_role):
    if flow_role not in ("sensor_producer",):
        return False
    if _has_actuator_outputs(ecu_id, architecture):
        return False
    if _bridges_multiple_buses(ecu_id, architecture):
        return False
    iface_sources, ecu_sources = _get_inflow_sources(ecu_id, architecture)
    iface_dests, ecu_dests = _get_outflow_destinations(ecu_id, architecture)
    for d in iface_dests:
        if _interface_type(d, architecture) == "actuator":
            return False
    supervisory_tokens = {"autopilot", "adas", "ad", "autonomous", "planner", "supervisor", "controller"}
    tokens = _tokenize_ecu_id(ecu_id)
    motion_tokens = {"brake", "steer", "steering", "throttle", "eps", "abs", "esc"}
    if tokens & motion_tokens:
        return False
    return True


def _classify_functional_role(ecu_id, architecture, flow_role):
    buses = _get_connected_buses(ecu_id, architecture)
    tokens = _tokenize_ecu_id(ecu_id)
    zone_id, _ = _get_ecu_zone(ecu_id, architecture)

    if len(buses) >= 2 and zone_id not in SAFETY_CRITICAL_TRUST_ZONES:
        crossing = _get_buses_crossing_trust_boundaries(ecu_id, buses, architecture)
        if crossing:
            return "BUS_BRIDGE"

    if _is_pure_sensor_producer(ecu_id, architecture, flow_role):
        return "PURE_SENSOR_PRODUCER"

    if flow_role in ("sensor_consumer_actuator_producer", "sensor_to_actuator"):
        return "PURE_ACTUATOR_CONSUMER"

    if _has_wireless_inputs(ecu_id, architecture):
        wireless_tokens = {"ksm", "peps", "security", "access", "key", "lock", "entry", "ble"}
        if tokens & wireless_tokens:
            return "AUTHENTICATION_GATEKEEPER"

    hv_tokens = {"battery", "bms", "hv", "charge", "charging", "inverter", "motor", "drive"}
    if tokens & hv_tokens or _has_hv_interfaces(ecu_id, architecture):
        return "ENERGY_MANAGER"

    diag_tokens = {"obd", "diag", "uds"}
    if tokens & diag_tokens:
        return "SERVICE_INTERFACE"

    supervisory_tokens = {"autopilot", "adas", "ad", "autonomous", "planner", "supervisor", "fusion"}
    if tokens & supervisory_tokens:
        return "SUPERVISORY_CONTROLLER"

    return "AMBIGUOUS"


def _apply_precedence_rules(ecu_id, functional_role, zone_id, trust_level, flow_role, architecture):
    tokens = _tokenize_ecu_id(ecu_id)

    if functional_role == "PURE_SENSOR_PRODUCER":
        return "PERCEPTION_AND_SENSING", "P1"

    if functional_role == "BUS_BRIDGE":
        return "NETWORK_GATEWAYING", "P2"

    if functional_role == "SUPERVISORY_CONTROLLER":
        return "AUTOMATED_DRIVING_CONTROL", "P3"

    if functional_role == "PURE_ACTUATOR_CONSUMER":
        if zone_id in MOTION_CONTROL_TRUST_ZONES:
            return "VEHICLE_MOTION_CONTROL", "P4"
        airbag_tokens = {"airbag", "srs", "rcm", "restraint", "restraints"}
        if tokens & airbag_tokens:
            return "OCCUPANT_SAFETY_SYSTEMS", "P4"
        return "VEHICLE_MOTION_CONTROL", "P4"

    if functional_role == "AUTHENTICATION_GATEKEEPER":
        return "VEHICLE_ACCESS_CONTROL", "P5"

    if functional_role == "ENERGY_MANAGER":
        return "POWERTRAIN_MANAGEMENT", "P6"

    if functional_role == "SERVICE_INTERFACE":
        return "DIAGNOSTIC_AND_SERVICE", "P7"

    if zone_id in MOTION_CONTROL_TRUST_ZONES:
        motion_tokens = {"brake", "abs", "ebs", "esc", "steer", "steering", "eps", "throttle", "accel"}
        if tokens & motion_tokens:
            return "VEHICLE_MOTION_CONTROL", "P8"

    return None, None


def _verify_domain_constraints(domain, ecu_id, functional_role, buses, zone_id, architecture, flow_role):
    violations = []

    if domain == "NETWORK_GATEWAYING":
        if len(buses) < 2:
            violations.append(f"NETWORK_GATEWAYING requires >=2 buses; found {len(buses)}")

    if domain == "PERCEPTION_AND_SENSING":
        if _has_actuator_outputs(ecu_id, architecture):
            violations.append("PERCEPTION_AND_SENSING node must not produce actuator commands")

    if domain == "AUTOMATED_DRIVING_CONTROL":
        iface_sources, ecu_sources = _get_inflow_sources(ecu_id, architecture)
        has_sensor_in = _has_sensor_inputs(ecu_id, architecture) or len(ecu_sources) > 0
        if not has_sensor_in:
            violations.append("AUTOMATED_DRIVING_CONTROL node must consume sensor or ECU inputs")

    if domain == "VEHICLE_MOTION_CONTROL":
        if not _has_actuator_outputs(ecu_id, architecture):
            tokens = _tokenize_ecu_id(ecu_id)
            motion_tokens = {"brake", "abs", "ebs", "esc", "steer", "steering", "eps", "throttle", "accel"}
            if not (tokens & motion_tokens):
                violations.append("VEHICLE_MOTION_CONTROL node has no actuator interface and no motion lexical identity")

    if domain == "DIAGNOSTIC_AND_SERVICE":
        if not _has_diagnostic_interfaces(ecu_id, architecture):
            tokens = _tokenize_ecu_id(ecu_id)
            diag_tokens = {"obd", "diag", "uds"}
            if not (tokens & diag_tokens):
                violations.append("DIAGNOSTIC_AND_SERVICE node has no diagnostic interface proximity")

    return violations


def _build_precedence_justification(ecu_id, domain, rule_ref, functional_role, zone_id, trust_level, buses, adjacent_interfaces, tokens):
    parts = [
        f"Rule {rule_ref} ({functional_role}): domain={domain}",
        f"trust_zone={zone_id} (level {trust_level}) [deployment annotation]",
    ]
    if buses:
        parts.append(f"buses={'+'.join(buses)} [communication annotation]")
    if adjacent_interfaces:
        parts.append(f"adjacent_interfaces={'+'.join(adjacent_interfaces[:3])}")
    if tokens:
        sample = list(tokens)[:3]
        parts.append(f"lexical_tokens={'+'.join(sample)}")
    return ", ".join(parts)


def _build_fallback_justification(ecu_id, domain, evidence_record, zone_id, trust_level, buses, adjacent_interfaces, tokens):
    parts = [f"Stage3 evidence convergence: domain={domain}"]
    parts.append(f"trust_zone={zone_id} (level {trust_level})")
    if buses:
        parts.append(f"bus={'|'.join(buses)}")
    if adjacent_interfaces:
        parts.append(f"adjacent_interfaces={'+'.join(adjacent_interfaces[:3])}")
    flow_role = evidence_record.get("data_flow_role", {}).get("role", "")
    if flow_role and flow_role != "unknown":
        parts.append(f"data_flow_role={flow_role}")
    matched = evidence_record.get("lexical_tokens", {}).get("matched_vocabulary", [])
    if matched:
        parts.append(f"lexical_tokens={'+'.join(matched[:2])}")
    return ", ".join(parts)


def _count_contributing_signals(evidence_record):
    count = 0
    for signal_name in SIGNAL_WEIGHT_NAMES:
        signal = evidence_record.get(signal_name)
        if not signal:
            continue
        contributed = signal.get("contributed_domain", "NONE")
        if contributed and contributed not in ("NONE", "UNKNOWN"):
            count += 1
            continue
        matched = signal.get("matched_vocabulary", [])
        if matched:
            count += 1
            continue
        protocols = signal.get("protocols", [])
        if protocols:
            count += 1
            continue
    return count


def _compute_confidence(top_score, total_evidence, evidence_record):
    if total_evidence <= 0:
        return 0.0
    raw_confidence = top_score / total_evidence
    contributing_signals = _count_contributing_signals(evidence_record)
    if contributing_signals <= CONFIDENCE_SPARSITY_PENALTY_THRESHOLD:
        raw_confidence *= CONFIDENCE_SPARSITY_PENALTY_FACTOR
    evidence_coverage = total_evidence / MAX_POSSIBLE_EVIDENCE
    if evidence_coverage < 0.30:
        raw_confidence *= 0.85
    return round(min(raw_confidence, 0.97), 4)


def _build_evidence_record(ecu_id, architecture):
    evidence_vector = {d: 0.0 for d in FUNCTIONAL_DOMAINS}
    evidence_record = {}
    evidence_record["_ecu_id"] = ecu_id

    tz_votes = extract_trust_zone_signal(ecu_id, architecture)
    for domain, score in tz_votes.items():
        evidence_vector[domain] += score
    ecu = next((e for e in architecture["ecus"] if e["id"] == ecu_id), None)
    zone_id = ecu["trust_zone"] if ecu else "UNKNOWN"
    zone = next((z for z in architecture["trust_zones"] if z["id"] == zone_id), None)
    trust_level = zone["trust_level"] if zone else 0
    contributed_domain_tz = max(tz_votes, key=tz_votes.get) if tz_votes else "UNKNOWN"
    evidence_record["trust_zone_signal"] = {
        "zone_id": zone_id,
        "trust_level": trust_level,
        "contributed_domain": contributed_domain_tz,
        "weight": 0.25,
    }

    bus_votes, connected_buses = extract_bus_participation_signal(ecu_id, architecture)
    for domain, score in bus_votes.items():
        evidence_vector[domain] += score
    contributed_domain_bus = max(bus_votes, key=bus_votes.get) if bus_votes else "NONE"
    evidence_record["bus_membership"] = {
        "buses": connected_buses,
        "contributed_domain": contributed_domain_bus,
        "weight": 0.10,
    }

    flow_votes, flow_role = extract_data_flow_role_signal(ecu_id, architecture)
    for domain, score in flow_votes.items():
        evidence_vector[domain] += score
    contributed_domain_flow = max(flow_votes, key=flow_votes.get) if flow_votes else "NONE"
    evidence_record["data_flow_role"] = {
        "role": flow_role,
        "contributed_domain": contributed_domain_flow,
        "weight": 0.25,
    }

    proximity_votes, adjacent_interfaces = extract_interface_proximity_signal(ecu_id, architecture)
    for domain, score in proximity_votes.items():
        evidence_vector[domain] += score
    contributed_domain_prox = max(proximity_votes, key=proximity_votes.get) if proximity_votes else "NONE"
    evidence_record["interface_proximity"] = {
        "adjacent_interfaces": adjacent_interfaces,
        "contributed_domain": contributed_domain_prox,
        "weight": 0.20,
    }

    protocol_votes, protocols = extract_protocol_signal(ecu_id, architecture)
    for domain, score in protocol_votes.items():
        evidence_vector[domain] += score
    contributed_domain_proto = max(protocol_votes, key=protocol_votes.get) if protocol_votes else "NONE"
    evidence_record["protocol_signal"] = {
        "protocols": protocols,
        "contributed_domain": contributed_domain_proto,
        "weight": 0.15,
    }

    lex_votes, tokens, matched_vocab = extract_lexical_signal(ecu_id)
    for domain, score in lex_votes.items():
        evidence_vector[domain] += score
    evidence_record["lexical_tokens"] = {
        "tokens": tokens,
        "matched_vocabulary": matched_vocab,
        "weight": 0.03,
    }

    act_votes, act_role = extract_actuator_sensor_type_signal(ecu_id, architecture)
    for domain, score in act_votes.items():
        evidence_vector[domain] += score
    contributed_domain_act = max(act_votes, key=act_votes.get) if act_votes else "NONE"
    evidence_record["actuator_sensor_role"] = {
        "role": act_role,
        "contributed_domain": contributed_domain_act,
        "weight": 0.02,
    }

    return evidence_vector, evidence_record, flow_role, zone_id, trust_level, connected_buses, adjacent_interfaces, tokens


def _apply_diagnostic_auxiliary_rule(domain, ecu_id, evidence_vector, evidence_record):
    if domain != "DIAGNOSTIC_AND_SERVICE":
        return domain

    diag_score = evidence_vector.get("DIAGNOSTIC_AND_SERVICE", 0.0)
    primary_score = sum(evidence_vector.get(d, 0.0) for d in DIAGNOSTIC_AUXILIARY_DOMAINS)

    if primary_score > 0.0:
        adjusted = dict(evidence_vector)
        adjusted["DIAGNOSTIC_AND_SERVICE"] *= DIAGNOSTIC_SIGNAL_PENALTY
        sorted_domains = sorted(adjusted.items(), key=lambda x: x[1], reverse=True)
        return sorted_domains[0][0]

    return domain


def _apply_archetype_adjusted_weights(evidence_vector, functional_role):
    adjusted = dict(evidence_vector)

    if functional_role == "AMBIGUOUS":
        return adjusted

    if functional_role == "PURE_SENSOR_PRODUCER":
        adjusted["AUTOMATED_DRIVING_CONTROL"] = adjusted.get("AUTOMATED_DRIVING_CONTROL", 0.0) * 0.20
        adjusted["VEHICLE_MOTION_CONTROL"] = adjusted.get("VEHICLE_MOTION_CONTROL", 0.0) * 0.20
        adjusted["POWERTRAIN_MANAGEMENT"] = adjusted.get("POWERTRAIN_MANAGEMENT", 0.0) * 0.20
        adjusted["OCCUPANT_SAFETY_SYSTEMS"] = adjusted.get("OCCUPANT_SAFETY_SYSTEMS", 0.0) * 0.20
        adjusted["PERCEPTION_AND_SENSING"] = max(adjusted.get("PERCEPTION_AND_SENSING", 0.0), 0.10)

    if functional_role == "BUS_BRIDGE":
        adjusted["NETWORK_GATEWAYING"] = max(adjusted.get("NETWORK_GATEWAYING", 0.0), 0.10)

    if functional_role == "SUPERVISORY_CONTROLLER":
        adjusted["AUTOMATED_DRIVING_CONTROL"] = max(adjusted.get("AUTOMATED_DRIVING_CONTROL", 0.0), 0.10)

    diag_score = adjusted.get("DIAGNOSTIC_AND_SERVICE", 0.0)
    if diag_score > 0.0:
        primary_score = sum(adjusted.get(d, 0.0) for d in DIAGNOSTIC_AUXILIARY_DOMAINS)
        if primary_score > 0.0:
            adjusted["DIAGNOSTIC_AND_SERVICE"] *= DIAGNOSTIC_SIGNAL_PENALTY

    return adjusted


def _infer_subdomain(ecu_id, domain, zone_id, adjacent_interfaces, tokens, architecture):
    zone_match = TRUST_ZONE_NAME_SIGNALS.get(zone_id)
    if zone_match and zone_match[0] == domain and zone_match[1]:
        return zone_match[1]

    for token in tokens:
        lex_match = LEXICAL_VOCABULARY.get(token)
        if lex_match and lex_match[0] == domain and lex_match[1]:
            return lex_match[1]

    for iface_id in adjacent_interfaces:
        prox_signal = INTERFACE_PROXIMITY_SIGNALS.get(iface_id)
        if prox_signal and prox_signal[0] == domain and prox_signal[1]:
            return prox_signal[1]

    available = SUBDOMAIN_MAP.get(domain, [])
    return available[0] if available else None


def infer_functional_domain(ecu_id, architecture):
    (
        evidence_vector,
        evidence_record,
        flow_role,
        zone_id,
        trust_level,
        connected_buses,
        adjacent_interfaces,
        tokens,
    ) = _build_evidence_record(ecu_id, architecture)

    functional_role = _classify_functional_role(ecu_id, architecture, flow_role)

    definitive_domain, rule_ref = _apply_precedence_rules(
        ecu_id, functional_role, zone_id, trust_level, flow_role, architecture
    )

    rule_fired = definitive_domain is not None

    if rule_fired:
        constraint_violations = _verify_domain_constraints(
            definitive_domain, ecu_id, functional_role, connected_buses, zone_id, architecture, flow_role
        )

        justification = _build_precedence_justification(
            ecu_id, definitive_domain, rule_ref, functional_role,
            zone_id, trust_level, connected_buses, adjacent_interfaces, tokens
        )

        if constraint_violations:
            justification += f" | CONSTRAINT_VIOLATIONS: {'; '.join(constraint_violations)}"

        subdomain = _infer_subdomain(ecu_id, definitive_domain, zone_id, adjacent_interfaces, tokens, architecture)

        evidence_record.pop("_ecu_id", None)

        return {
            "functional_domain": definitive_domain,
            "subdomains": [subdomain] if subdomain else [],
            "confidence": 0.95,
            "dual_domain": None,
            "evidence_vector": evidence_vector,
            "evidence_record": evidence_record,
            "justification": justification,
            "functional_role_archetype": functional_role,
            "inference_stage": "precedence_rule",
            "rule_reference": rule_ref,
            "constraint_violations": constraint_violations,
        }

    adjusted_vector = _apply_archetype_adjusted_weights(evidence_vector, functional_role)

    sorted_domains = sorted(adjusted_vector.items(), key=lambda x: x[1], reverse=True)
    top_domain, top_score = sorted_domains[0]
    second_domain, second_score = sorted_domains[1] if len(sorted_domains) > 1 else ("NONE", 0.0)

    top_domain = _apply_diagnostic_auxiliary_rule(top_domain, ecu_id, adjusted_vector, evidence_record)

    total_evidence = sum(v for k, v in adjusted_vector.items() if not k.startswith("_"))
    confidence = _compute_confidence(top_score, total_evidence, evidence_record)

    dual_domain = None
    if (top_score - second_score) < AMBIGUITY_THRESHOLD and second_score > 0 and second_domain != top_domain:
        dual_domain = second_domain

    constraint_violations = _verify_domain_constraints(
        top_domain, ecu_id, functional_role, connected_buses, zone_id, architecture, flow_role
    )

    justification = _build_fallback_justification(
        ecu_id, top_domain, evidence_record, zone_id, trust_level,
        connected_buses, adjacent_interfaces, tokens
    )

    if constraint_violations:
        justification += f" | CONSTRAINT_VIOLATIONS: {'; '.join(constraint_violations)}"

    subdomain = _infer_subdomain(ecu_id, top_domain, zone_id, adjacent_interfaces, tokens, architecture)

    evidence_record.pop("_ecu_id", None)

    return {
        "functional_domain": top_domain,
        "subdomains": [subdomain] if subdomain else [],
        "confidence": confidence,
        "dual_domain": dual_domain,
        "evidence_vector": adjusted_vector,
        "evidence_record": evidence_record,
        "justification": justification,
        "functional_role_archetype": functional_role,
        "inference_stage": "evidence_convergence",
        "rule_reference": None,
        "constraint_violations": constraint_violations,
    }