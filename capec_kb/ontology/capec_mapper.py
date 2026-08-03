import json
from pathlib import Path

AUTOMOTIVE_CAPEC_ALLOWLIST = {
    '1','2','8','9','10','12','16','20','21','29','30','36','49','50','54','59',
    '60','68','69','70','77','90','92','94','100','112','141','157','158','161',
    '166','167','180','189','190','191','194','195','196','206','212','217','268',
    '276','277','384','391','395','397','399','400','401','442','443','444','445',
    '446','452','456','457','458','459','473','474','475','476','477','485','516',
    '520','521','522','523','534','535','536','537','540','542','547','578','580',
    '583','599','604','606','608','614','616','620','622','625','627','628','638',
    '645','654','657','664','665','666','667','668','669','674','677','679','680',
    '681','682','702',
}

SURFACE_CAPEC_MAP = {
    'wireless_interface': {
        '20','60','90','94','112','141','157','158','194','195','196','276','277',
        '384','395','397','399','400','473','474','475','476','477','485','599',
        '604','606','608','614','616','620','622','625','627','628','645','654',
        '657','666','667','668','669',
    },
    'diagnostic_interface': {
        '1','2','12','16','21','36','49','50','54','59','60','68','69','70','77',
        '90','92','94','100','112','141','161','166','167','180','189','190','191',
        '194','195','196','206','212','217','268','276','277','442','443','444',
        '445','446','457','458','459','473','474','475','476','477','485','523',
        '536','540','542','578','580','638','645','654','657','669','679','680',
        '681','682','702',
    },
    'in_vehicle_network': {
        '1','2','12','16','21','29','30','36','49','54','59','68','69','70','77',
        '90','92','94','100','112','141','157','158','161','166','180','194','195',
        '196','212','217','276','277','473','474','475','476','477','485','523',
        '536','540','542','578','580','638','645','654','664','669','679','680',
        '681','682',
    },
    'physical_access': {
        '8','9','10','29','30','36','69','77','92','100','157','161','166','167',
        '180','189','190','191','206','212','268','391','395','397','399','400',
        '401','442','443','444','445','446','452','456','457','458','459','473',
        '474','475','476','477','485','516','520','521','522','523','534','535',
        '536','537','540','542','547','578','580','583','622','625','638','645',
        '654','664','665','674','677','679','680','681','682','702',
    },
    'remote_network': {
        '1','2','16','20','21','36','49','50','54','59','60','68','90','94','112',
        '141','157','158','180','194','195','196','212','217','276','277','384',
        '473','475','476','477','485','523','540','542','578','580','614','616',
        '638','645','657','664','666','667','668','669','679','681','682',
    },
}

CONSEQUENCE_CAPEC_MAP = {
    'sensor_data_spoofing':                {'94','141','194','195','276','277','627','628'},
    'false_object_injection':              {'94','141','194','276','277','627'},
    'sensor_blinding':                     {'599','604','547','583'},
    'trajectory_hijacking':                {'94','141','194','276','277','384'},
    'motion_command_injection':            {'94','141','194','276','277','664'},
    'supervisory_mode_manipulation':       {'1','21','180','94','277'},
    'fallback_suppression':                {'578','161','166','276'},
    'unauthorized_firmware_modification':  {'523','638','657','669','534'},
    'ota_channel_hijacking':               {'657','384','669','459'},
    'cross_domain_lateral_movement':       {'1','21','161','180','94','277'},
    'routing_manipulation':                {'94','141','276','277','384'},
    'firewall_bypass':                     {'1','21','180','36'},
    'unauthorized_diagnostic_session':     {'1','21','36','49','70','180'},
    'ecu_configuration_manipulation':      {'212','536','77','94'},
    'diagnostic_session_hijacking':        {'60','59','196'},
    'audit_log_tampering':                 {'268'},
    'authentication_bypass':               {'1','21','90','180','196','473','475'},
    'relay_attack_enablement':             {'60','399','667'},
    'immobilizer_bypass':                  {'395','1','21','180','473'},
    'unauthorized_vehicle_unlock':         {'395','399','667','668'},
    'false_airbag_deployment':             {'94','141','194','276'},
    'airbag_suppression_in_collision':     {'578','161','166','276'},
    'unintended_braking':                  {'94','141','194','276'},
    'loss_of_deceleration_control':        {'94','578','161','166'},
    'uncontrolled_torque_output':          {'94','141','194','212','276','664'},
    'loss_of_propulsion':                  {'94','212','276','664'},
    'hv_system_compromise':               {'401','680','681','682'},
    'thermal_runaway_enablement':          {'680','681'},
    'charging_system_manipulation':        {'94','276','536'},
    'occupant_state_falsification':        {'94','194','276','627'},
    'presence_detection_bypass':           {'578','547','94','194'},
    'safety_decision_corruption':          {'94','141','194','195','276','578'},
    'unauthorized_privileged_access':      {'1','21','69','180','36'},
    'unintended_steering':                 {'94','141','194','276'},
    'uncontrolled_lateral_motion':         {'94','578','161','166'},
    'message_injection_to_safety_domains': {'94','141','276','277','664'},
    'confidentiality_loss_in_powertrain_management': {'167','268','534','536'},
}

CAPEC_EXCLUDE_CONSEQUENCES = {
    'safety_function_unavailability',
    'integrity_loss_in_vehicle_motion_control',
    'integrity_loss_in_powertrain_management',
    'integrity_loss_in_occupant_safety_systems',
    'integrity_loss_in_automated_driving_control',
    'integrity_loss_in_network_gatewaying',
    'integrity_loss_in_diagnostic_and_service',
    'integrity_loss_in_body_and_comfort',
    'integrity_loss_in_perception_and_sensing',
    'integrity_loss_in_vehicle_access_control',
    'integrity_loss_in_telematics_and_connectivity',
    'confidentiality_loss_in_telematics_and_connectivity',
    'confidentiality_loss_in_vehicle_access_control',
    'unauthorized_privileged_access',
}

R155_CAPEC_MAP = {
    'R155 Annex 5 Threat 3.1': [
        {'capec_id': '94',  'join_dim': 'r155:3.1'},
        {'capec_id': '141', 'join_dim': 'r155:3.1'},
        {'capec_id': '194', 'join_dim': 'r155:3.1'},
        {'capec_id': '276', 'join_dim': 'r155:3.1'},
    ],
    'R155 Annex 5 Threat 3.2': [
        {'capec_id': '1',   'join_dim': 'r155:3.2'},
        {'capec_id': '21',  'join_dim': 'r155:3.2'},
        {'capec_id': '180', 'join_dim': 'r155:3.2'},
    ],
    'R155 Annex 5 Threat 3.3': [
        {'capec_id': '94',  'join_dim': 'r155:3.3'},
        {'capec_id': '141', 'join_dim': 'r155:3.3'},
        {'capec_id': '194', 'join_dim': 'r155:3.3'},
        {'capec_id': '195', 'join_dim': 'r155:3.3'},
        {'capec_id': '627', 'join_dim': 'r155:3.3'},
    ],
    'R155 Annex 5 Threat 4.1': [
        {'capec_id': '523', 'join_dim': 'r155:4.1'},
        {'capec_id': '638', 'join_dim': 'r155:4.1'},
        {'capec_id': '669', 'join_dim': 'r155:4.1'},
    ],
    'R155 Annex 5 Threat 4.3': [
        {'capec_id': '657', 'join_dim': 'r155:4.3'},
        {'capec_id': '384', 'join_dim': 'r155:4.3'},
    ],
    'R155 Annex 5 Threat 6.1': [
        {'capec_id': '21',  'join_dim': 'r155:6.1'},
        {'capec_id': '112', 'join_dim': 'r155:6.1'},
        {'capec_id': '196', 'join_dim': 'r155:6.1'},
    ],
    'R155 Annex 5 Threat 6.2': [
        {'capec_id': '384', 'join_dim': 'r155:6.2'},
        {'capec_id': '664', 'join_dim': 'r155:6.2'},
        {'capec_id': '668', 'join_dim': 'r155:6.2'},
    ],
    'R155 Annex 5 Threat 7.1': [
        {'capec_id': '94',  'join_dim': 'r155:7.1'},
        {'capec_id': '194', 'join_dim': 'r155:7.1'},
        {'capec_id': '667', 'join_dim': 'r155:7.1'},
    ],
    'R155 Annex 5 Threat 7.2': [
        {'capec_id': '1',   'join_dim': 'r155:7.2'},
        {'capec_id': '21',  'join_dim': 'r155:7.2'},
        {'capec_id': '180', 'join_dim': 'r155:7.2'},
    ],
    'R155 Annex 5 Threat 7.3': [
        {'capec_id': '523', 'join_dim': 'r155:7.3'},
        {'capec_id': '638', 'join_dim': 'r155:7.3'},
    ],
    'R155 Annex 5 Threat 8.1': [
        {'capec_id': '167', 'join_dim': 'r155:8.1'},
        {'capec_id': '268', 'join_dim': 'r155:8.1'},
    ],
}

WIRELESS_ONLY_CAPECS = {
    '599', '604', '606', '608', '614', '616', '620', '622', '625',
    '627', '628', '666', '667', '668', '669',
}

ETH_API_ONLY_CAPECS = {'384', '657'}

GPS_CAPECS = {'627', '628'}

SUBDOMAIN_CAPEC_EXCLUSIONS = {
    'occupant_sensing': GPS_CAPECS,
}

KNOWN_FALSE_POSITIVES = {
    '578': (
        'CAPEC-578 (Disable Security Software) is conceptually thin for CAN-connected safety '
        'ECUs with no traditional security software stack. Applied as defeating any monitoring '
        'mechanism. Attack path generator must not use as a concrete attack step on '
        'VEHICLE_MOTION_CONTROL, OCCUPANT_SAFETY_SYSTEMS, or PERCEPTION_AND_SENSING nodes '
        'without additional evidence of a software security monitor being present.'
    ),
    '60': (
        'CAPEC-60 (Reusing Session IDs) is retained as an analogy for UDS SecurityAccess '
        'replay attacks per R155:6.1. CWE linkage is imprecise for bare-metal ECU contexts. '
        'Filter web-specific CWEs (CWE-294, CWE-488, CWE-539) from this entry in ISO 21434 '
        'output rendering. Prefer CAPEC-112 or CAPEC-21 for CAN/UDS credential reuse scenarios.'
    ),
}

CAPEC_COVERAGE_GAPS = {
    'charge_port_iso15118': (
        'CHARGE_PORT_ECU requires EV-specific CAPEC coverage for ISO 15118 / DIN 70121 '
        'charge-protocol exploitation and charge-infrastructure attack vectors. No suitable '
        'CAPEC entry exists in the current KB. Downstream threat scenario generator cannot '
        'produce charge-infrastructure scenarios without this coverage.'
    ),
    'can_bus_flooding_dos': (
        'RESTRAINTS_CONTROLLER and VEHICLE_MOTION_CONTROL nodes are missing DoS-class CAPEC '
        'for CAN bus flooding affecting safety_function_unavailability. CAPEC-131 or equivalent '
        'needed when available in KB.'
    ),
    'gateway_pivot_lateral': (
        'BODY_CONTROLLER and SECURITY_CONTROLLER lateral-movement pivot scenarios benefit from '
        'CAPEC-161 (Infrastructure Manipulation) for TZ-BODY→TZ-ADAS cross-domain escalation. '
        'Add when CAPEC-161 is available in the KB with automotive scope confirmation.'
    ),
}

CIA_SCOPE_MAP = {
    'Integrity':       {'integrity', 'modification'},
    'Availability':    {'availability', 'denial'},
    'Confidentiality': {'confidentiality', 'read'},
    'Authenticity':    {'authentication', 'integrity'},
    'Authorization':   {'authorization', 'access control'},
    'Non-repudiation': {'non-repudiation'},
}

BLE_PROTOCOL_KEYS = {('BLE', 'NONE'), ('BLE', 'ATT'), ('BLE', 'GATT')}

def _load_capec_index(capec_path):
    with open(capec_path, encoding='utf-8') as f:
        nodes = json.load(f)
    index = {}
    for node in nodes:
        if node['abstraction'] in ('Standard', 'Detailed') and node['capec_id'] in AUTOMOTIVE_CAPEC_ALLOWLIST:
            index[node['capec_id']] = node
    return index

def load_capec_index(capec_path=None):
    if capec_path is None:
        here = Path(__file__).resolve().parent
        candidates = [
            here / 'capec_nodes.json',
            here.parent / 'capec_nodes.json',
            here.parent / 'output' / 'capec_nodes.json',
        ]
        for candidate in candidates:
            if candidate.exists():
                capec_path = candidate
                break
        else:
            raise FileNotFoundError(
                f"capec_nodes.json not found; searched: {[str(c) for c in candidates]}"
            )
    return _load_capec_index(capec_path)

def _normalise_likelihood_severity(value):
    if value is None or (isinstance(value, str) and value.strip() == ''):
        return 'Unknown'
    return value

def _consequence_capec_ids(consequences):
    ids = set()
    for c in consequences:
        if c not in CAPEC_EXCLUDE_CONSEQUENCES:
            ids |= CONSEQUENCE_CAPEC_MAP.get(c, set())
    return ids

def _r155_capec_ids(r155_sources, attack_surfaces):
    has_wireless = 'wireless_interface' in attack_surfaces
    has_eth = 'remote_network' in attack_surfaces or 'wireless_interface' in attack_surfaces
    result = {}
    for source in r155_sources:
        for entry in R155_CAPEC_MAP.get(source, []):
            cid = entry['capec_id']
            if cid in WIRELESS_ONLY_CAPECS and not has_wireless:
                continue
            if cid in ETH_API_ONLY_CAPECS and not has_eth:
                continue
            if cid not in result:
                result[cid] = []
            result[cid].append(entry['join_dim'])
    return result

def _scope_match(node, cyber_props):
    node_scopes = set()
    for c in node.get('consequences', []):
        for s in c.get('scopes', []):
            node_scopes.add(s.lower())
    if not node_scopes:
        return True
    target_scopes = set()
    for prop in cyber_props.get('primary', []):
        target_scopes |= CIA_SCOPE_MAP.get(prop, set())
    if not target_scopes:
        return True
    return bool(node_scopes & target_scopes)

def _is_ble_protocol(protocols_seen):
    return bool(set(protocols_seen) & {f"{t}/{a}" for t, a in BLE_PROTOCOL_KEYS})

def build_capec_refs(attack_surfaces, cyber_props, consequences, r155_sources, capec_index,
                     subdomains=None, protocols_seen=None):
    subdomains = subdomains or []
    protocols_seen = protocols_seen or []

    subdomain_exclusions = set()
    for sd in subdomains:
        subdomain_exclusions |= SUBDOMAIN_CAPEC_EXCLUSIONS.get(sd, set())

    has_wireless = 'wireless_interface' in attack_surfaces
    has_eth = 'remote_network' in attack_surfaces or 'wireless_interface' in attack_surfaces
    is_ble_node = _is_ble_protocol(protocols_seen)

    dim_a = set()
    for surface in attack_surfaces:
        dim_a |= SURFACE_CAPEC_MAP.get(surface, set())
    dim_a &= set(capec_index.keys())
    dim_a -= subdomain_exclusions

    if not is_ble_node:
        dim_a -= {'667', '668', '669'}

    dim_b = {cid for cid in dim_a if _scope_match(capec_index[cid], cyber_props)}
    if not dim_b:
        dim_b = dim_a

    dim_c = _consequence_capec_ids(consequences) & set(capec_index.keys())
    dim_c -= subdomain_exclusions

    dim_d = _r155_capec_ids(r155_sources, attack_surfaces)
    dim_d_ids = set(dim_d.keys()) & set(capec_index.keys())
    dim_d_ids -= subdomain_exclusions

    candidate_ids = (dim_b & dim_c) | dim_d_ids
    if not candidate_ids:
        candidate_ids = dim_b | dim_d_ids

    refs = []
    seen = set()
    for capec_id in sorted(candidate_ids, key=lambda x: int(x)):
        if capec_id not in capec_index or capec_id in seen:
            continue
        seen.add(capec_id)
        node = capec_index[capec_id]

        join_dims = []
        for surface in attack_surfaces:
            if capec_id in SURFACE_CAPEC_MAP.get(surface, set()):
                join_dims.append(f'attack_surface:{surface}')
        for dim in dim_d.get(capec_id, []):
            join_dims.append(dim)
        if not join_dims:
            join_dims.append('dim_c:consequence_match')

        raw_severity = node.get('severity', '')
        raw_likelihood = node.get('likelihood', '')

        ref = {
            'capec_id': capec_id,
            'capec_name': node['name'],
            'abstraction': node['abstraction'],
            'join_dimensions': join_dims,
            'cwe_ids': node.get('cwe_mappings', []),
            'severity': _normalise_likelihood_severity(raw_severity),
            'likelihood': _normalise_likelihood_severity(raw_likelihood),
        }

        if capec_id in KNOWN_FALSE_POSITIVES:
            ref['known_false_positive_note'] = KNOWN_FALSE_POSITIVES[capec_id]

        refs.append(ref)

    return refs