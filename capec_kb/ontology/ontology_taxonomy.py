FUNCTIONAL_DOMAINS = [
    "VEHICLE_MOTION_CONTROL",
    "POWERTRAIN_MANAGEMENT",
    "OCCUPANT_SAFETY_SYSTEMS",
    "PERCEPTION_AND_SENSING",
    "AUTOMATED_DRIVING_CONTROL",
    "NETWORK_GATEWAYING",
    "VEHICLE_ACCESS_CONTROL",
    "BODY_AND_COMFORT",
    "DIAGNOSTIC_AND_SERVICE",
    "TELEMATICS_AND_CONNECTIVITY",
]

SUBDOMAIN_MAP = {
    "VEHICLE_MOTION_CONTROL": ["deceleration_control", "acceleration_control", "lateral_control"],
    "POWERTRAIN_MANAGEMENT": ["energy_conversion", "energy_storage", "energy_transfer"],
    "OCCUPANT_SAFETY_SYSTEMS": ["passive_safety", "active_safety"],
    "PERCEPTION_AND_SENSING": ["environmental_sensing", "occupant_sensing", "inertial_sensing"],
    "AUTOMATED_DRIVING_CONTROL": ["path_planning", "motion_arbitration", "supervisory_control"],
    "NETWORK_GATEWAYING": ["domain_routing", "protocol_translation", "firewall_enforcement"],
    "VEHICLE_ACCESS_CONTROL": ["authentication", "authorization", "physical_security"],
    "BODY_AND_COMFORT": ["lighting_control", "climate_control", "convenience_functions"],
    "DIAGNOSTIC_AND_SERVICE": ["obd_access", "ota_management", "logging_and_monitoring"],
    "TELEMATICS_AND_CONNECTIVITY": ["remote_communication", "local_wireless", "external_data_services"],
}

TRUST_ZONE_NAME_SIGNALS = {
    "TZ-BRAKE":     ("VEHICLE_MOTION_CONTROL",  "deceleration_control"),
    "TZ-STEERING":  ("VEHICLE_MOTION_CONTROL",  "lateral_control"),
    "TZ-POWERTRAIN":("POWERTRAIN_MANAGEMENT",   None),
    "TZ-SRS":       ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "TZ-ADAS":      ("AUTOMATED_DRIVING_CONTROL","supervisory_control"),
    "TZ-SENSOR":    ("PERCEPTION_AND_SENSING",  None),
    "TZ-BODY":      ("BODY_AND_COMFORT",        None),
    "TZ-VNET":      ("NETWORK_GATEWAYING",      None),
}

TRUST_LEVEL_DOMAIN_WEIGHTS = {
    3: 0.25,
    2: 0.15,
    1: 0.10,
}

BUS_ID_SIGNALS = {
    "POWERTRAIN": "POWERTRAIN_MANAGEMENT",
    "BODY":       "BODY_AND_COMFORT",
    "DIAG":       "DIAGNOSTIC_AND_SERVICE",
}

PROTOCOL_SIGNALS = {
    ("CAN", "UDS"):  "DIAGNOSTIC_AND_SERVICE",
    ("ETH", "UDS"):  "DIAGNOSTIC_AND_SERVICE",
    ("ETH", "SOMEIP"):"AUTOMATED_DRIVING_CONTROL",
    ("BLE", "NONE"): "VEHICLE_ACCESS_CONTROL",
    ("ETH", "NONE"): "PERCEPTION_AND_SENSING",
}

LEXICAL_VOCABULARY = {
    "brake":      ("VEHICLE_MOTION_CONTROL",  "deceleration_control"),
    "abs":        ("VEHICLE_MOTION_CONTROL",  "deceleration_control"),
    "ebs":        ("VEHICLE_MOTION_CONTROL",  "deceleration_control"),
    "esc":        ("VEHICLE_MOTION_CONTROL",  "deceleration_control"),
    "steer":      ("VEHICLE_MOTION_CONTROL",  "lateral_control"),
    "steering":   ("VEHICLE_MOTION_CONTROL",  "lateral_control"),
    "angle":      ("VEHICLE_MOTION_CONTROL",  "lateral_control"),
    "eps":        ("VEHICLE_MOTION_CONTROL",  "lateral_control"),
    "rack":       ("VEHICLE_MOTION_CONTROL",  "lateral_control"),
    "accel":      ("VEHICLE_MOTION_CONTROL",  "acceleration_control"),
    "throttle":   ("VEHICLE_MOTION_CONTROL",  "acceleration_control"),
    "drive":      ("POWERTRAIN_MANAGEMENT",   "energy_conversion"),
    "inverter":   ("POWERTRAIN_MANAGEMENT",   "energy_conversion"),
    "motor":      ("POWERTRAIN_MANAGEMENT",   "energy_conversion"),
    "torque":     ("POWERTRAIN_MANAGEMENT",   "energy_conversion"),
    "battery":    ("POWERTRAIN_MANAGEMENT",   "energy_storage"),
    "bms":        ("POWERTRAIN_MANAGEMENT",   "energy_storage"),
    "hv":         ("POWERTRAIN_MANAGEMENT",   "energy_storage"),
    "charge":     ("POWERTRAIN_MANAGEMENT",   "energy_transfer"),
    "charging":   ("POWERTRAIN_MANAGEMENT",   "energy_transfer"),
    "airbag":     ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "srs":        ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "rcm":        ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "restraint":  ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "restraints": ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "radar":      ("PERCEPTION_AND_SENSING",  "environmental_sensing"),
    "lidar":      ("PERCEPTION_AND_SENSING",  "environmental_sensing"),
    "camera":     ("PERCEPTION_AND_SENSING",  "occupant_sensing"),
    "sensor":     ("PERCEPTION_AND_SENSING",  None),
    "autopilot":  ("AUTOMATED_DRIVING_CONTROL","supervisory_control"),
    "adas":       ("AUTOMATED_DRIVING_CONTROL",None),
    "ad":         ("AUTOMATED_DRIVING_CONTROL",None),
    "autonomous": ("AUTOMATED_DRIVING_CONTROL",None),
    "gateway":    ("NETWORK_GATEWAYING",      "domain_routing"),
    "gw":         ("NETWORK_GATEWAYING",      "domain_routing"),
    "router":     ("NETWORK_GATEWAYING",      "domain_routing"),
    "body":       ("BODY_AND_COMFORT",        None),
    "bcm":        ("BODY_AND_COMFORT",        None),
    "security":   ("VEHICLE_ACCESS_CONTROL",  None),
    "ksm":        ("VEHICLE_ACCESS_CONTROL",  "authentication"),
    "peps":       ("VEHICLE_ACCESS_CONTROL",  "authentication"),
    "obd":        ("DIAGNOSTIC_AND_SERVICE",  "obd_access"),
    "diag":       ("DIAGNOSTIC_AND_SERVICE",  None),
    "uds":        ("DIAGNOSTIC_AND_SERVICE",  None),
    "tcu":        ("TELEMATICS_AND_CONNECTIVITY","remote_communication"),
    "telematics": ("TELEMATICS_AND_CONNECTIVITY",None),
    "gsm":        ("TELEMATICS_AND_CONNECTIVITY","remote_communication"),
    "interior":   ("PERCEPTION_AND_SENSING",  "occupant_sensing"),
}

INTERFACE_PROXIMITY_SIGNALS = {
    "IMPACT_SENSORS":    ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "PRESSURE_SENSORS":  ("OCCUPANT_SAFETY_SYSTEMS", "passive_safety"),
    "ADAS_SENSORS":      ("PERCEPTION_AND_SENSING",  "environmental_sensing"),
    "SPEED_SENSORS":     ("VEHICLE_MOTION_CONTROL",  "deceleration_control"),
    "ACCEL_SENSOR":      ("VEHICLE_MOTION_CONTROL",  "acceleration_control"),
    "BLE_INTERFACES":    ("VEHICLE_ACCESS_CONTROL",  "authentication"),
    "OBD_INTERFACE":     ("DIAGNOSTIC_AND_SERVICE",  "obd_access"),
    "DIAG_ETHERNET":     ("DIAGNOSTIC_AND_SERVICE",  "obd_access"),
    "HV_DISCONNECT":     ("POWERTRAIN_MANAGEMENT",   "energy_transfer"),
    "RESTRAINT_ACTUATORS":("OCCUPANT_SAFETY_SYSTEMS","passive_safety"),
}

OCCUPANT_SENSING_DESTINATION_ECUS = {"SECURITY_CONTROLLER", "SECURITY", "DMS", "OMS"}

CYBERSECURITY_DOMAIN_MAP = {
    "VEHICLE_MOTION_CONTROL": {
        "primary": ["Integrity", "Availability", "Authenticity"],
        "secondary": ["Non-repudiation"],
        "derivation": "Safety-critical control function; integrity loss enables command injection; availability loss disables safety function",
    },
    "POWERTRAIN_MANAGEMENT": {
        "primary": ["Integrity", "Availability", "Authenticity"],
        "secondary": ["Confidentiality"],
        "derivation": "Safety-critical energy conversion and storage; unauthenticated CAN commands are the primary attack vector for torque/HV manipulation; BMS state data and charging session data carry commercial and privacy sensitivity",
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "primary": ["Integrity", "Availability", "Authenticity"],
        "secondary": [],
        "derivation": "Life-critical passive safety; false activation or suppression directly endangers occupants",
    },
    "PERCEPTION_AND_SENSING": {
        "primary": ["Integrity", "Authenticity", "Availability"],
        "secondary": [],
        "derivation": "Sensor spoofing corrupts situational awareness; sensor blinding disables ADAS safety functions",
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "primary": ["Integrity", "Availability", "Authenticity", "Authorization"],
        "secondary": [],
        "derivation": "Supervisory AD control; trajectory and motion command integrity is safety-critical; mode transitions require Authorization",
    },
    "NETWORK_GATEWAYING": {
        "primary": ["Integrity", "Availability", "Authorization"],
        "secondary": ["Authenticity"],
        "derivation": "Cross-domain boundary enforcement; compromise enables lateral movement to safety-critical domains",
    },
    "VEHICLE_ACCESS_CONTROL": {
        "primary": ["Authenticity", "Authorization", "Integrity"],
        "secondary": ["Confidentiality"],
        "derivation": "Authentication and authorization gating; bypass enables unauthorized vehicle access and control",
    },
    "BODY_AND_COMFORT": {
        "primary": ["Integrity", "Availability", "Authenticity"],
        "secondary": ["Confidentiality"],
        "derivation": "Body domain ECUs control road-legal lighting; unauthorized command injection constitutes a traffic safety hazard",
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "primary": ["Authorization", "Authenticity", "Integrity"],
        "secondary": ["Non-repudiation"],
        "derivation": "Privileged service interface; unauthorized access enables firmware manipulation and configuration changes",
    },
    "TELEMATICS_AND_CONNECTIVITY": {
        "primary": ["Confidentiality", "Integrity", "Authorization"],
        "secondary": ["Authenticity"],
        "derivation": "External communication channel; confidentiality of user data and integrity of remote commands are primary concerns",
    },
}

CONSEQUENCE_DOMAIN_MAP = {
    "VEHICLE_MOTION_CONTROL": {
        "consequences": ["unintended_braking", "unintended_brake_actuation", "loss_of_deceleration_control", "vehicle_instability", "uncontrolled_lateral_motion"],
        "damage_seeds": [
            "Physical harm to vehicle occupants from unintended braking or loss of deceleration control",
            "Vehicle collision or lane departure causing physical harm from uncontrolled lateral motion",
            "Physical harm from uncontrolled vehicle acceleration",
        ],
        "attack_surfaces": ["in_vehicle_network", "diagnostic_interface", "physical_access"],
    },
    "POWERTRAIN_MANAGEMENT": {
        "consequences": ["uncontrolled_torque_output", "loss_of_propulsion", "hv_system_compromise", "thermal_runaway_enablement"],
        "damage_seeds": [
            "Physical harm from unintended acceleration due to uncontrolled torque output",
            "Fire or electrocution risk to occupants from high-voltage system manipulation",
            "Loss of propulsion causing secondary collision in traffic",
            "Financial loss from charging session manipulation or charge-state falsification",
        ],
        "attack_surfaces": ["in_vehicle_network", "diagnostic_interface", "physical_access"],
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "consequences": ["false_airbag_deployment", "airbag_suppression_in_collision", "seatbelt_pretensioner_attack", "restraint_system_unavailability"],
        "damage_seeds": [
            "Physical harm to occupants from unexpected airbag deployment at speed",
            "Occupant death from airbag suppression during real collision",
            "Secondary injury from false seatbelt pretensioner activation",
            "Safety harm from restraint system unavailability during collision",
        ],
        "attack_surfaces": ["in_vehicle_network", "physical_access"],
    },
    "PERCEPTION_AND_SENSING": {
        "consequences": ["sensor_data_spoofing", "environmental_awareness_corruption", "false_object_injection", "sensor_blinding"],
        "damage_seeds": [
            "Vehicle collision due to corrupted sensor data fed to ADAS systems",
            "Physical harm from failure to detect obstacles or road users due to sensor blinding",
            "False collision avoidance response triggered by spoofed sensor input causing physical harm",
        ],
        "attack_surfaces": ["in_vehicle_network", "physical_access", "wireless_interface"],
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "consequences": ["trajectory_hijacking", "motion_command_injection", "supervisory_mode_manipulation", "fallback_suppression"],
        "damage_seeds": [
            "Physical harm from injected trajectory commands causing vehicle to deviate from safe path",
            "Collision from suppressed fallback mechanism during automated driving",
            "Unauthorized assumption of vehicle control by remote attacker causing physical harm",
            "Operational loss from unexpected disengagement of automated driving at highway speed",
        ],
        "attack_surfaces": ["in_vehicle_network", "diagnostic_interface", "wireless_interface", "remote_network"],
    },
    "NETWORK_GATEWAYING": {
        "consequences": ["cross_domain_lateral_movement", "message_injection_to_safety_domains", "firewall_bypass", "routing_manipulation"],
        "damage_seeds": [
            "Safety harm to vehicle occupants through gateway-mediated attack on motion control or occupant safety systems",
            "Injection of malicious commands into chassis or powertrain domain through gateway causing physical harm",
            "Loss of inter-domain security boundary enabling multi-domain attack with safety consequences",
            "Persistent vehicle compromise via gateway lateral movement enabling downstream safety-critical system attacks",
        ],
        "attack_surfaces": ["in_vehicle_network", "diagnostic_interface", "physical_access"],
    },
    "VEHICLE_ACCESS_CONTROL": {
        "consequences": [
            "unauthorized_vehicle_unlock",
            "immobilizer_bypass",
            "relay_attack_enablement",
            "authentication_bypass",
            "authenticated_network_access_enabling_lateral_movement",
        ],
        "damage_seeds": [
            "Vehicle theft via keyless entry system compromise",
            "Unauthorized physical access to vehicle interior enabling further attack",
            "Financial loss to vehicle owner through theft or ransomware enabled by authenticated network access",
            "Regulatory non-compliance from unauthorized access to personal data stored on connected vehicle systems",
        ],
        "attack_surfaces": ["wireless_interface", "physical_access", "in_vehicle_network"],
    },
    "BODY_AND_COMFORT": {
        "consequences": ["comfort_function_disruption", "lighting_manipulation", "hvac_compromise"],
        "damage_seeds": [
            "Driver distraction from unexpected lighting state changes causing traffic safety hazard",
            "Passenger discomfort or environmental harm from HVAC manipulation",
            "Service disruption affecting vehicle usability",
        ],
        "attack_surfaces": ["in_vehicle_network", "diagnostic_interface"],
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "consequences": ["unauthorized_firmware_modification", "ecu_configuration_manipulation", "diagnostic_session_hijacking", "service_credential_theft"],
        "damage_seeds": [
            "Persistent compromise of vehicle ECUs via unauthorized firmware update causing safety harm",
            "Safety configuration modification enabling downstream attacks on motion control",
            "Credential theft enabling repeated unauthorized diagnostic access",
        ],
        "attack_surfaces": ["diagnostic_interface", "physical_access", "wireless_interface"],
    },
    "TELEMATICS_AND_CONNECTIVITY": {
        "consequences": ["remote_command_injection", "vehicle_tracking", "user_data_exfiltration", "remote_access_bridge"],
        "damage_seeds": [
            "Physical harm from remote vehicle control via compromised telematics channel",
            "Privacy violation through covert vehicle location tracking",
            "Use of telematics as entry point for further vehicle network penetration causing safety harm",
            "Financial damage to fleet operator from mass vehicle immobilization or service SLA breach",
            "Regulatory non-compliance under GDPR from mass user data exfiltration across connected fleet",
        ],
        "attack_surfaces": ["wireless_interface", "remote_network", "in_vehicle_network"],
    },
}

R155_THREAT_MAP = {
    "VEHICLE_MOTION_CONTROL":     ["R155 Annex 5 Threat 3.1", "R155 Annex 5 Threat 6.1"],
    "POWERTRAIN_MANAGEMENT":      ["R155 Annex 5 Threat 3.1", "R155 Annex 5 Threat 6.2"],
    "OCCUPANT_SAFETY_SYSTEMS":    ["R155 Annex 5 Threat 3.1", "R155 Annex 5 Threat 6.1"],
    "PERCEPTION_AND_SENSING":     ["R155 Annex 5 Threat 3.3", "R155 Annex 5 Threat 6.1"],
    "AUTOMATED_DRIVING_CONTROL":  ["R155 Annex 5 Threat 3.1", "R155 Annex 5 Threat 3.3"],
    "NETWORK_GATEWAYING":         ["R155 Annex 5 Threat 3.2", "R155 Annex 5 Threat 7.3"],
    "VEHICLE_ACCESS_CONTROL":     ["R155 Annex 5 Threat 7.1", "R155 Annex 5 Threat 7.2"],
    "BODY_AND_COMFORT":           ["R155 Annex 5 Threat 3.2"],
    "DIAGNOSTIC_AND_SERVICE":     ["R155 Annex 5 Threat 7.3", "R155 Annex 5 Threat 4.1"],
    "TELEMATICS_AND_CONNECTIVITY":["R155 Annex 5 Threat 3.3", "R155 Annex 5 Threat 4.3"],
}

REFERENCE_STANDARDS = ["ISO 26262-3:2018", "SAE J3061", "ISO/SAE 21434:2021", "UNECE R155"]

ASSET_TARGET_PROPERTIES_MAP = {
    "VEHICLE_MOTION_CONTROL": {
        "Integrity":    ["commands", "control_signals", "configuration"],
        "Availability": ["service", "safety_function"],
        "Authenticity": ["messages", "command_sources"],
    },
    "POWERTRAIN_MANAGEMENT": {
        "Integrity":       ["torque_commands", "energy_parameters", "configuration"],
        "Availability":    ["service", "safety_function"],
        "Authenticity":    ["messages", "command_sources"],
        "Confidentiality": ["battery_state_data", "charging_session_data"],
    },
    "POWERTRAIN_MANAGEMENT_energy_storage": {
        "Integrity":       ["cell_voltage_data", "SoC_values", "BMS_configuration", "thermal_limits"],
        "Availability":    ["service", "safety_function"],
        "Authenticity":    ["messages"],
        "Confidentiality": ["battery_state_data", "SoC_values"],
    },
    "POWERTRAIN_MANAGEMENT_energy_transfer": {
        "Integrity":       ["charging_commands", "charge_state_data", "HV_interlock_signals"],
        "Availability":    ["service", "safety_function"],
        "Authenticity":    ["messages"],
        "Confidentiality": ["charging_session_data", "charge_state_data"],
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "Integrity":    ["deployment_commands", "sensor_data", "configuration"],
        "Availability": ["service", "safety_function"],
        "Authenticity": ["messages", "command_sources"],
    },
    "PERCEPTION_AND_SENSING": {
        "Integrity":    ["sensor_data", "object_detection_output"],
        "Availability": ["service"],
        "Authenticity": ["sensor_data", "messages"],
    },
    "PERCEPTION_AND_SENSING_occupant_sensing": {
        "Integrity":        ["occupant_state_data", "presence_detection_output", "biometric_data"],
        "Availability":     ["service", "safety_function"],
        "Authenticity":     ["sensor_data", "messages"],
        "Confidentiality":  ["occupant_biometric_data", "presence_data"],
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "Integrity":    ["trajectory_commands", "motion_arbitration_output", "configuration"],
        "Availability": ["service", "safety_function"],
        "Authenticity": ["messages", "command_sources"],
        "Authorization":["supervisory_mode_transitions"],
    },
    "NETWORK_GATEWAYING": {
        "Integrity":    ["routing_rules", "firewall_policy", "messages"],
        "Availability": ["service"],
        "Authorization":["cross_domain_sessions", "policy_rules"],
        "Authenticity": ["messages"],
    },
    "VEHICLE_ACCESS_CONTROL": {
        "Authenticity":     ["credentials", "tokens", "messages"],
        "Authorization":    ["access_decisions", "session_grants"],
        "Integrity":        ["configuration", "key_material"],
        "Confidentiality":  ["occupant_data", "credentials"],
    },
    "BODY_AND_COMFORT": {
        "Integrity":        ["commands", "configuration"],
        "Availability":     ["service"],
        "Authenticity":     ["messages"],
        "Confidentiality":  ["occupant_data"],
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "Authorization":["diagnostic_sessions", "service_credentials"],
        "Authenticity": ["messages", "update_packages"],
        "Integrity":    ["firmware", "configuration", "audit_logs"],
    },
    "TELEMATICS_AND_CONNECTIVITY": {
        "Confidentiality":  ["occupant_data", "location_data", "credentials"],
        "Integrity":        ["remote_commands", "configuration"],
        "Authorization":    ["remote_sessions"],
        "Authenticity":     ["messages", "update_packages"],
    },
}

ATTACK_SURFACE_ACTOR_MAP = {
    "wireless_interface":   ["remote_attacker", "nearby_attacker"],
    "remote_network":       ["remote_attacker"],
    "diagnostic_interface": ["service_technician", "physical_attacker", "insider_attacker"],
    "physical_access":      ["physical_attacker", "insider_attacker"],
    "in_vehicle_network":   ["insider_attacker", "supply_chain_attacker"],
}

TRANSITIVE_REMOTE_ATTACKER_SURFACES = {"remote_network", "wireless_interface"}

ENTRY_POINT_SURFACE_TYPES = {
    "wireless_interface":   "wireless_rf",
    "remote_network":       "remote_ip",
    "diagnostic_interface": "physical_diagnostic",
    "physical_access":      "physical_hardware",
}

EXTERNALLY_REACHABLE_SURFACES = {"wireless_interface", "remote_network", "diagnostic_interface"}

NETWORK_EXPOSED_INTERFACE_TYPES = {"network"}

NETWORK_INTERFACE_ECU_ADJACENCY = {}
from ontology_taxonomy_sfop_addition import SFOP_DOMAIN_MAP