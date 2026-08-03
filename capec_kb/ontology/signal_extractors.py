import re
from collections import defaultdict
from ontology_taxonomy import (
    TRUST_ZONE_NAME_SIGNALS,
    TRUST_LEVEL_DOMAIN_WEIGHTS,
    BUS_ID_SIGNALS,
    PROTOCOL_SIGNALS,
    LEXICAL_VOCABULARY,
    INTERFACE_PROXIMITY_SIGNALS,
    FUNCTIONAL_DOMAINS,
    OCCUPANT_SENSING_DESTINATION_ECUS,
)


SENSOR_INTERFACE_TYPES    = {"sensor", "radar", "lidar", "camera"}
ACTUATOR_INTERFACE_TYPES  = {"actuator"}
DIAGNOSTIC_INTERFACE_TYPES= {"diagnostic"}
WIRELESS_INTERFACE_TYPES  = {"wireless"}
NETWORK_INTERFACE_TYPES   = {"network"}

SENSOR_LEXICAL_HINTS  = {"radar", "lidar", "camera", "sensor", "accel", "gyro", "imu", "ultrasonic"}
ACTUATOR_LEXICAL_HINTS= {"brake", "steer", "throttle", "actuator", "motor", "valve"}
CONTROL_LEXICAL_HINTS = {"autopilot", "adas", "ad", "autonomous", "controller", "planner", "supervisor"}
MOTION_LEXICAL_HINTS  = {"brake", "abs", "ebs", "esc", "steer", "steering", "eps", "throttle", "accel"}
INTERIOR_SENSOR_LEXICAL_HINTS = {"interior", "camera", "dms", "oms"}

ANGLE_SENSOR_LEXICAL_HINTS = {"angle", "steering", "eps"}

SENSOR_DESTINATION_ECU_HINTS = {"gateway", "gw", "autopilot", "adas", "ad", "autonomous", "planner", "fusion"}


def _get_ecu_tokens(ecu_id):
    return set(_tokenize(ecu_id))


def _destination_ecu_is_consumer(dest_id, architecture):
    tokens = set(_tokenize(dest_id))
    if tokens & SENSOR_DESTINATION_ECU_HINTS:
        return True
    iface = next((i for i in architecture["external_interfaces"] if i["id"] == dest_id), None)
    if iface and iface.get("type") in SENSOR_INTERFACE_TYPES:
        return True
    return False


def _destination_ecu_is_occupant_sensing_consumer(dest_id, architecture):
    return dest_id in OCCUPANT_SENSING_DESTINATION_ECUS


def _classify_producer_type(ecu_id, architecture):
    tokens = _get_ecu_tokens(ecu_id)

    if tokens & INTERIOR_SENSOR_LEXICAL_HINTS:
        destinations = [f["destination"] for f in architecture["data_flows"] if f["source"] == ecu_id]
        if any(_destination_ecu_is_occupant_sensing_consumer(d, architecture) for d in destinations):
            return "occupant_sensor_producer"

    if tokens & MOTION_LEXICAL_HINTS:
        return "actuator_producer"

    if tokens & CONTROL_LEXICAL_HINTS:
        return "control_producer"

    if tokens & SENSOR_LEXICAL_HINTS:
        return "sensor_producer"

    if tokens & ACTUATOR_LEXICAL_HINTS:
        return "actuator_producer"

    destinations = []
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id:
            destinations.append(flow["destination"])

    dest_types = []
    for d in destinations:
        iface = next((i for i in architecture["external_interfaces"] if i["id"] == d), None)
        if iface:
            dest_types.append(iface.get("type", ""))

    if any(t in SENSOR_INTERFACE_TYPES for t in dest_types):
        return "sensor_producer"

    sensor_consumer_dests = sum(
        1 for d in destinations if _destination_ecu_is_consumer(d, architecture)
    )
    total_dests = len(destinations)
    if total_dests > 0 and sensor_consumer_dests / total_dests >= 0.5:
        return "sensor_producer"

    sources = []
    for flow in architecture["data_flows"]:
        if flow["destination"] == ecu_id:
            sources.append(flow["source"])

    source_types = []
    for s in sources:
        iface = next((i for i in architecture["external_interfaces"] if i["id"] == s), None)
        if iface:
            source_types.append(iface.get("type", ""))

    if any(t in SENSOR_INTERFACE_TYPES for t in source_types):
        return "sensor_producer"

    has_wireless = any(t in WIRELESS_INTERFACE_TYPES for t in source_types)
    if has_wireless:
        return "wireless_producer"

    connected_bus_count = sum(
        1 for bus in architecture["communication_buses"]
        if ecu_id in bus["connected_ecus"]
    )
    if connected_bus_count > 1:
        return "cross_domain_producer"

    return "control_producer"


def extract_trust_zone_signal(ecu_id, architecture):
    ecu = next((e for e in architecture["ecus"] if e["id"] == ecu_id), None)
    if not ecu:
        return {}

    zone_id = ecu["trust_zone"]
    zone = next((z for z in architecture["trust_zones"] if z["id"] == zone_id), None)
    if not zone:
        return {}

    trust_level = zone["trust_level"]
    base_weight = TRUST_LEVEL_DOMAIN_WEIGHTS.get(trust_level, 0.05)

    ecu_tokens = _get_ecu_tokens(ecu_id)
    is_ad_control_ecu = bool(ecu_tokens & CONTROL_LEXICAL_HINTS)

    votes = defaultdict(float)
    zone_name_match = TRUST_ZONE_NAME_SIGNALS.get(zone_id)
    if zone_name_match:
        domain, _ = zone_name_match
        if domain == "PERCEPTION_AND_SENSING" and is_ad_control_ecu:
            votes["AUTOMATED_DRIVING_CONTROL"] += base_weight
        else:
            votes[domain] += base_weight
    else:
        if trust_level == 3:
            votes["VEHICLE_MOTION_CONTROL"]    += base_weight * 0.3
            votes["OCCUPANT_SAFETY_SYSTEMS"]   += base_weight * 0.3
            votes["POWERTRAIN_MANAGEMENT"]     += base_weight * 0.2
            votes["AUTOMATED_DRIVING_CONTROL"] += base_weight * 0.2
        elif trust_level == 2:
            votes["PERCEPTION_AND_SENSING"] += base_weight * 0.5
            votes["BODY_AND_COMFORT"]       += base_weight * 0.5
        elif trust_level == 1:
            votes["NETWORK_GATEWAYING"]     += base_weight * 0.5
            votes["DIAGNOSTIC_AND_SERVICE"] += base_weight * 0.5

    return dict(votes)


def extract_bus_participation_signal(ecu_id, architecture):
    votes = defaultdict(float)
    weight = 0.10

    connected_buses = []
    for bus in architecture["communication_buses"]:
        if ecu_id in bus["connected_ecus"]:
            connected_buses.append(bus["id"])

    if len(connected_buses) > 1:
        votes["NETWORK_GATEWAYING"] += weight
        return dict(votes), connected_buses

    for bus_id in connected_buses:
        for key, domain in BUS_ID_SIGNALS.items():
            if key.upper() in bus_id.upper():
                if "CAN" in bus_id.upper() and domain == "VEHICLE_MOTION_CONTROL":
                    break
                votes[domain] += weight
                break

    return dict(votes), connected_buses


def extract_data_flow_role_signal(ecu_id, architecture):
    weight = 0.25
    votes = defaultdict(float)

    sources_from = []
    destinations_to = []

    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id:
            destinations_to.append(flow["destination"])
        if flow["destination"] == ecu_id:
            sources_from.append(flow["source"])

    interface_ids = {iface["id"] for iface in architecture["external_interfaces"]}

    sources_are_sensors = all(
        s in interface_ids and _is_interface_type(s, "sensor", architecture)
        for s in sources_from
    ) and len(sources_from) > 0

    destinations_are_actuators = all(
        d in interface_ids and _is_interface_type(d, "actuator", architecture)
        for d in destinations_to
    ) and len(destinations_to) > 0

    bridges_multiple_buses = _bridges_multiple_buses(ecu_id, architecture)

    receives_wireless = any(
        s in interface_ids and _is_interface_type(s, "wireless", architecture)
        for s in sources_from
    )

    receives_diagnostic = any(
        s in interface_ids and _is_interface_type(s, "diagnostic", architecture)
        for s in sources_from
    )

    ecu_trust_level = _get_ecu_trust_level_local(ecu_id, architecture)
    diagnostic_vote_suppressed = (ecu_trust_level >= 3)

    sends_to_network = any(
        d in interface_ids and _is_interface_type(d, "network", architecture)
        for d in destinations_to
    )

    ecu_tokens = _get_ecu_tokens(ecu_id)
    is_interior_sensor = bool(ecu_tokens & INTERIOR_SENSOR_LEXICAL_HINTS)

    role = "unknown"

    if bridges_multiple_buses:
        votes["NETWORK_GATEWAYING"] += weight
        role = "bus_bridge"
    elif sources_are_sensors and destinations_are_actuators:
        votes["OCCUPANT_SAFETY_SYSTEMS"] += weight
        role = "sensor_consumer_actuator_producer"
    elif receives_wireless and sends_to_network:
        votes["VEHICLE_ACCESS_CONTROL"]       += weight * 0.6
        votes["TELEMATICS_AND_CONNECTIVITY"]  += weight * 0.4
        role = "wireless_to_network_bridge"
    elif receives_diagnostic and not diagnostic_vote_suppressed:
        votes["DIAGNOSTIC_AND_SERVICE"] += weight * 0.5
        role = "diagnostic_consumer"
    elif receives_diagnostic and diagnostic_vote_suppressed:
        role = "passive_receiver"
    elif len(sources_from) > 0 and len(destinations_to) == 0:
        if is_interior_sensor:
            votes["PERCEPTION_AND_SENSING"] += weight * 0.8
            role = "occupant_sensor_producer"
        else:
            votes["PERCEPTION_AND_SENSING"] += weight * 0.5
            role = "pure_consumer"
    elif len(sources_from) == 0 and len(destinations_to) > 0:
        producer_type = _classify_producer_type(ecu_id, architecture)
        role = producer_type
        if producer_type == "occupant_sensor_producer":
            votes["PERCEPTION_AND_SENSING"] += weight * 0.9
        elif producer_type == "sensor_producer":
            votes["PERCEPTION_AND_SENSING"] += weight * 0.8
        elif producer_type == "actuator_producer":
            votes["VEHICLE_MOTION_CONTROL"]  += weight * 0.4
            votes["POWERTRAIN_MANAGEMENT"]   += weight * 0.2
        elif producer_type == "control_producer":
            votes["AUTOMATED_DRIVING_CONTROL"] += weight * 0.3
            votes["VEHICLE_MOTION_CONTROL"]    += weight * 0.15
        elif producer_type == "wireless_producer":
            votes["TELEMATICS_AND_CONNECTIVITY"] += weight * 0.4
        elif producer_type == "cross_domain_producer":
            votes["NETWORK_GATEWAYING"] += weight * 0.4
        else:
            votes["AUTOMATED_DRIVING_CONTROL"] += weight * 0.15
            votes["VEHICLE_MOTION_CONTROL"]    += weight * 0.15
    else:
        role = "mixed"

    return dict(votes), role


def extract_interface_proximity_signal(ecu_id, architecture):
    weight = 0.20
    votes = defaultdict(float)

    adjacent_interfaces = []
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id:
            dest = flow["destination"]
            if any(i["id"] == dest for i in architecture["external_interfaces"]):
                adjacent_interfaces.append(dest)
        if flow["destination"] == ecu_id:
            src = flow["source"]
            if any(i["id"] == src for i in architecture["external_interfaces"]):
                adjacent_interfaces.append(src)

    interface_votes = defaultdict(float)
    diagnostic_adjacent = 0
    non_diagnostic_adjacent = 0

    for iface_id in adjacent_interfaces:
        signal = INTERFACE_PROXIMITY_SIGNALS.get(iface_id)
        if signal:
            domain, _ = signal
            if domain == "DIAGNOSTIC_AND_SERVICE":
                diagnostic_adjacent += 1
            else:
                non_diagnostic_adjacent += 1
                interface_votes[domain] += 1.0

    if non_diagnostic_adjacent == 0 and diagnostic_adjacent > 0:
        interface_votes["DIAGNOSTIC_AND_SERVICE"] += diagnostic_adjacent * 0.5

    if interface_votes:
        total = sum(interface_votes.values())
        for domain, count in interface_votes.items():
            votes[domain] += weight * (count / total)

    return dict(votes), adjacent_interfaces


def extract_protocol_signal(ecu_id, architecture):
    weight = 0.15
    votes = defaultdict(float)

    protocols_seen = set()
    for flow in architecture["data_flows"]:
        if flow["source"] == ecu_id or flow["destination"] == ecu_id:
            transport = flow["protocol"].get("transport", "NONE")
            application = flow["protocol"].get("application", "NONE")
            protocols_seen.add((transport, application))

    ecu_tokens = _get_ecu_tokens(ecu_id)
    is_sensor_ecu = bool(ecu_tokens & SENSOR_LEXICAL_HINTS)

    protocol_votes = defaultdict(float)
    for proto_key in protocols_seen:
        domain = PROTOCOL_SIGNALS.get(proto_key)
        if domain:
            if proto_key == ("ETH", "SOMEIP") and is_sensor_ecu:
                continue
            proto_weight = 0.4 if domain == "DIAGNOSTIC_AND_SERVICE" else 1.0
            protocol_votes[domain] += proto_weight

    if protocol_votes:
        total = sum(protocol_votes.values())
        for domain, count in protocol_votes.items():
            votes[domain] += weight * (count / total)

    return dict(votes), [f"{t}/{a}" for t, a in protocols_seen]


def extract_lexical_signal(ecu_id):
    weight = 0.03
    votes = defaultdict(float)

    tokens = _tokenize(ecu_id)
    matched_vocab = []

    token_votes = defaultdict(float)
    for token in tokens:
        match = LEXICAL_VOCABULARY.get(token)
        if match:
            domain, _ = match
            token_votes[domain] += 1.0
            matched_vocab.append(f"{token}→{domain}")

    if token_votes:
        total = sum(token_votes.values())
        for domain, count in token_votes.items():
            votes[domain] += weight * (count / total)

    return dict(votes), tokens, matched_vocab


def _infer_actuator_sensor_role_from_interfaces(ecu_id, architecture, source_types, dest_types, ecu_tokens):
    if "sensor" in source_types and "actuator" in dest_types:
        return "sensor_to_actuator"

    if "sensor" in source_types:
        return "sensor_consumer"

    if "actuator" in dest_types:
        if ecu_tokens & MOTION_LEXICAL_HINTS:
            return "actuator_producer"
        return "actuator_producer"

    flows_to_ecus_only = not source_types and not dest_types
    if flows_to_ecus_only or (not source_types and not dest_types):
        if ecu_tokens & SENSOR_LEXICAL_HINTS:
            if ecu_tokens & ANGLE_SENSOR_LEXICAL_HINTS:
                return "angle_sensor_producer"
            return "sensor_producer"

    return None


def extract_actuator_sensor_type_signal(ecu_id, architecture):
    weight = 0.02
    votes = defaultdict(float)

    sources = []
    destinations = []
    for flow in architecture["data_flows"]:
        if flow["destination"] == ecu_id:
            sources.append(flow["source"])
        if flow["source"] == ecu_id:
            destinations.append(flow["destination"])

    def get_type(node_id):
        iface = next((i for i in architecture["external_interfaces"] if i["id"] == node_id), None)
        return iface["type"] if iface else None

    source_types  = [get_type(s) for s in sources if get_type(s)]
    dest_types    = [get_type(d) for d in destinations if get_type(d)]

    has_sensor_input   = "sensor" in source_types
    has_actuator_output= "actuator" in dest_types
    has_network_bridge = "network" in source_types or "network" in dest_types
    has_diagnostic     = "diagnostic" in source_types or "diagnostic" in dest_types
    has_wireless       = "wireless" in source_types

    ecu_tokens = _get_ecu_tokens(ecu_id)
    is_interior = bool(ecu_tokens & INTERIOR_SENSOR_LEXICAL_HINTS)

    dest_ecu_ids = [d for d in destinations if any(e["id"] == d for e in architecture["ecus"])]
    sends_to_access_control = any(
        d in OCCUPANT_SENSING_DESTINATION_ECUS for d in dest_ecu_ids
    )

    role = "unknown"

    if has_sensor_input and has_actuator_output:
        votes["OCCUPANT_SAFETY_SYSTEMS"] += weight
        role = "sensor_to_actuator"
    elif is_interior and sends_to_access_control:
        votes["PERCEPTION_AND_SENSING"] += weight
        role = "occupant_sensor"
    elif has_sensor_input and not has_actuator_output:
        votes["PERCEPTION_AND_SENSING"] += weight * 0.5
        role = "sensor_consumer"
    elif has_network_bridge:
        votes["NETWORK_GATEWAYING"] += weight
        role = "network_bridge"
    elif has_diagnostic and not has_sensor_input:
        votes["DIAGNOSTIC_AND_SERVICE"] += weight * 0.5
        role = "diagnostic_node"
    elif has_wireless:
        votes["VEHICLE_ACCESS_CONTROL"] += weight
        role = "wireless_node"
    else:
        inferred = _infer_actuator_sensor_role_from_interfaces(
            ecu_id, architecture, source_types, dest_types, ecu_tokens
        )
        if inferred:
            role = inferred
            if "sensor" in inferred:
                votes["PERCEPTION_AND_SENSING"] += weight * 0.5
            elif "actuator" in inferred:
                votes["VEHICLE_MOTION_CONTROL"] += weight * 0.5

    return dict(votes), role


def _is_interface_type(iface_id, iface_type, architecture):
    iface = next((i for i in architecture["external_interfaces"] if i["id"] == iface_id), None)
    return iface is not None and iface.get("type") == iface_type


def _bridges_multiple_buses(ecu_id, architecture):
    connected_bus_count = sum(
        1 for bus in architecture["communication_buses"]
        if ecu_id in bus["connected_ecus"]
    )
    return connected_bus_count > 1


def _get_ecu_trust_level_local(ecu_id, architecture):
    ecu = next((e for e in architecture["ecus"] if e["id"] == ecu_id), None)
    if not ecu:
        return 0
    zone = next((z for z in architecture["trust_zones"] if z["id"] == ecu["trust_zone"]), None)
    return zone["trust_level"] if zone else 0


def _tokenize(name):
    parts = re.split(r"[_\-]", name)
    tokens = []
    for part in parts:
        if part.isupper():
            tokens.append(part.lower())
        else:
            camel_parts = re.sub(r"([A-Z])", r"_\1", part).split("_")
            tokens.extend([p.lower() for p in camel_parts if p])
    return [t for t in tokens if len(t) > 1]