from ontology_taxonomy import CONSEQUENCE_DOMAIN_MAP


SUBDOMAIN_CONSEQUENCE_MAP = {
    "VEHICLE_MOTION_CONTROL": {
        "deceleration_control": ["unintended_braking", "loss_of_deceleration_control"],
        "lateral_control": ["unintended_steering", "uncontrolled_lateral_motion"],
        "acceleration_control": ["uncontrolled_acceleration", "vehicle_instability"],
    },
    "POWERTRAIN_MANAGEMENT": {
        "energy_conversion": ["uncontrolled_torque_output", "loss_of_propulsion"],
        "energy_storage": ["hv_system_compromise", "thermal_runaway_enablement"],
        "energy_transfer": ["charging_system_manipulation", "hv_system_compromise"],
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "passive_safety": ["false_airbag_deployment", "airbag_suppression_in_collision", "seatbelt_pretensioner_attack", "restraint_system_unavailability"],
        "active_safety": ["collision_avoidance_suppression", "emergency_braking_bypass"],
    },
    "PERCEPTION_AND_SENSING": {
        "environmental_sensing": ["sensor_data_spoofing", "false_object_injection", "sensor_blinding"],
        "occupant_sensing": ["occupant_state_falsification", "presence_detection_bypass", "safety_decision_corruption"],
        "inertial_sensing": ["motion_data_corruption", "dead_reckoning_manipulation"],
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "path_planning": ["trajectory_hijacking", "route_manipulation"],
        "motion_arbitration": ["motion_command_injection", "arbitration_bypass"],
        "supervisory_control": ["supervisory_mode_manipulation", "fallback_suppression", "motion_command_injection"],
    },
    "NETWORK_GATEWAYING": {
        "domain_routing": ["cross_domain_lateral_movement", "routing_manipulation"],
        "protocol_translation": ["message_injection_to_safety_domains", "translation_spoofing"],
        "firewall_enforcement": ["firewall_bypass", "policy_rule_manipulation"],
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "obd_access": ["unauthorized_diagnostic_session", "ecu_configuration_manipulation"],
        "ota_management": ["unauthorized_firmware_modification", "ota_channel_hijacking"],
        "logging_and_monitoring": ["audit_log_tampering", "diagnostic_session_hijacking"],
    },
}

SUBDOMAIN_DAMAGE_SEED_MAP = {
    "deceleration_control": [
        "Physical harm to vehicle occupants from unintended braking or loss of deceleration control",
        "Rear-end collision caused by brake command injection",
    ],
    "lateral_control": [
        "Vehicle lane departure or rollover causing physical harm from uncontrolled lateral motion",
        "Collision with road users due to steering command injection",
    ],
    "acceleration_control": [
        "Physical harm from unintended acceleration or uncontrolled torque demand",
        "Collision caused by unexpected vehicle acceleration",
    ],
    "energy_conversion": [
        "Physical harm from unintended acceleration due to uncontrolled torque output",
        "Loss of drive torque causing secondary collision in traffic",
    ],
    "energy_storage": [
        "Fire or electrocution risk to occupants from high-voltage system compromise",
        "Thermal runaway triggered by battery management manipulation causing fire risk",
    ],
    "energy_transfer": [
        "Charging system manipulation causing HV connector damage or fire risk to nearby persons",
        "Financial loss from charge state falsification causing stranding or exploitation",
    ],
    "environmental_sensing": [
        "Vehicle collision due to corrupted environmental sensor data fed to ADAS",
        "Physical harm from failure to detect obstacles or road users from sensor blinding or spoofing",
    ],
    "occupant_sensing": [
        "Physical harm from safety-critical decision corruption caused by falsified occupant state data fed to airbag or AEB systems",
        "Incorrect airbag deployment or suppression triggered by falsified occupant presence or classification data causing physical harm",
        "Privacy violation and regulatory non-compliance through covert biometric monitoring of vehicle occupants",
        "GDPR breach from unauthorised access to or exfiltration of occupant biometric or presence data",
    ],
    "inertial_sensing": [
        "Navigation corruption or dead-reckoning failure from IMU data manipulation causing physical harm",
        "False stability-control response triggered by spoofed inertial data causing vehicle instability",
    ],
    "path_planning": [
        "Physical harm from trajectory hijacking causing vehicle to deviate from safe path",
        "Route manipulation causing vehicle to enter restricted or dangerous areas",
    ],
    "motion_arbitration": [
        "Collision from injected motion commands bypassing safety arbitration",
        "Multi-system conflict from arbitration logic corruption",
    ],
    "supervisory_control": [
        "Unauthorized assumption of full vehicle control by disabling supervisory fallback causing physical harm",
        "Collision from suppressed fallback mechanism during automated driving mode",
    ],
    "domain_routing": [
        "Safety harm to vehicle occupants through gateway-mediated attack on motion control or occupant safety systems",
        "Injection of malicious commands into chassis or powertrain domain via routing manipulation causing physical harm",
    ],
    "protocol_translation": [
        "Safety-domain command injection via protocol translation spoofing causing physical harm",
        "Loss of inter-domain security boundary due to translation layer bypass enabling safety-critical system attacks",
    ],
    "firewall_enforcement": [
        "Unrestricted lateral movement across trust boundaries from firewall bypass enabling safety-critical system attacks",
        "Policy rule manipulation enabling persistent cross-domain attack paths with physical harm potential",
    ],
    "obd_access": [
        "ECU configuration manipulation via unauthorized OBD diagnostic session enabling downstream vehicle attacks",
        "Safety configuration modification enabling downstream attacks on motion control",
    ],
    "ota_management": [
        "Persistent vehicle compromise via unauthorized firmware modification over OTA channel causing safety harm",
        "OTA channel hijacking enabling mass-fleet remote exploitation",
    ],
    "logging_and_monitoring": [
        "Forensic evidence destruction via audit log tampering",
        "Credential theft through diagnostic session hijacking enabling repeated unauthorized access",
    ],
}

SUBDOMAIN_DOMAIN_SCOPE = {
    "deceleration_control": "VEHICLE_MOTION_CONTROL",
    "lateral_control": "VEHICLE_MOTION_CONTROL",
    "acceleration_control": "VEHICLE_MOTION_CONTROL",
    "energy_conversion": "POWERTRAIN_MANAGEMENT",
    "energy_storage": "POWERTRAIN_MANAGEMENT",
    "energy_transfer": "POWERTRAIN_MANAGEMENT",
    "passive_safety": "OCCUPANT_SAFETY_SYSTEMS",
    "active_safety": "OCCUPANT_SAFETY_SYSTEMS",
    "environmental_sensing": "PERCEPTION_AND_SENSING",
    "occupant_sensing": "PERCEPTION_AND_SENSING",
    "inertial_sensing": "PERCEPTION_AND_SENSING",
    "path_planning": "AUTOMATED_DRIVING_CONTROL",
    "motion_arbitration": "AUTOMATED_DRIVING_CONTROL",
    "supervisory_control": "AUTOMATED_DRIVING_CONTROL",
    "domain_routing": "NETWORK_GATEWAYING",
    "protocol_translation": "NETWORK_GATEWAYING",
    "firewall_enforcement": "NETWORK_GATEWAYING",
    "obd_access": "DIAGNOSTIC_AND_SERVICE",
    "ota_management": "DIAGNOSTIC_AND_SERVICE",
    "logging_and_monitoring": "DIAGNOSTIC_AND_SERVICE",
}

SUBDOMAIN_CONFIDENTIALITY_DOMAINS = {
    "occupant_sensing",
}

POWERTRAIN_CONFIDENTIALITY_SUBDOMAINS = {
    "energy_storage",
    "energy_transfer",
}


def infer_consequences(functional_domain, subdomains, cybersecurity_properties):
    domain_data = CONSEQUENCE_DOMAIN_MAP.get(functional_domain, {})
    if not domain_data:
        return [], [], []

    attack_surfaces = list(domain_data.get("attack_surfaces", []))
    subdomain_map = SUBDOMAIN_CONSEQUENCE_MAP.get(functional_domain, {})
    consequences = []

    if subdomains:
        for subdomain in subdomains:
            scoped_domain = SUBDOMAIN_DOMAIN_SCOPE.get(subdomain)
            if scoped_domain != functional_domain:
                continue
            subdomain_consequences = subdomain_map.get(subdomain, [])
            for c in subdomain_consequences:
                if c not in consequences:
                    consequences.append(c)

    if not consequences:
        consequences = list(domain_data.get("consequences", []))

    damage_seeds = []
    if subdomains:
        for subdomain in subdomains:
            scoped_domain = SUBDOMAIN_DOMAIN_SCOPE.get(subdomain)
            if scoped_domain != functional_domain:
                continue
            subdomain_seeds = SUBDOMAIN_DAMAGE_SEED_MAP.get(subdomain, [])
            for s in subdomain_seeds:
                if s not in damage_seeds:
                    damage_seeds.append(s)

    if not damage_seeds:
        damage_seeds = list(domain_data.get("damage_seeds", []))

    primary_props = cybersecurity_properties.get("primary", [])
    secondary_props = cybersecurity_properties.get("secondary", [])
    all_props = set(primary_props) | set(secondary_props)

    if "Integrity" in primary_props:
        integrity_consequence = f"integrity_loss_in_{functional_domain.lower()}"
        if integrity_consequence not in consequences:
            consequences.append(integrity_consequence)

    if "Availability" in primary_props and functional_domain in (
        "VEHICLE_MOTION_CONTROL",
        "OCCUPANT_SAFETY_SYSTEMS",
        "AUTOMATED_DRIVING_CONTROL",
        "POWERTRAIN_MANAGEMENT",
        "PERCEPTION_AND_SENSING",
    ):
        if "safety_function_unavailability" not in consequences:
            consequences.append("safety_function_unavailability")

    if "Authorization" in primary_props and functional_domain in (
        "DIAGNOSTIC_AND_SERVICE",
        "VEHICLE_ACCESS_CONTROL",
        "NETWORK_GATEWAYING",
    ):
        if "unauthorized_privileged_access" not in consequences:
            consequences.append("unauthorized_privileged_access")

    if "Confidentiality" in all_props and functional_domain in (
        "TELEMATICS_AND_CONNECTIVITY",
        "VEHICLE_ACCESS_CONTROL",
    ):
        confidentiality_consequence = f"confidentiality_loss_in_{functional_domain.lower()}"
        if confidentiality_consequence not in consequences:
            consequences.append(confidentiality_consequence)

    if "Confidentiality" in all_props and functional_domain == "PERCEPTION_AND_SENSING":
        active_subdomain_confidentiality = any(
            sd in SUBDOMAIN_CONFIDENTIALITY_DOMAINS for sd in (subdomains or [])
        )
        if active_subdomain_confidentiality:
            conf_consequence = "confidentiality_loss_in_perception_and_sensing"
            if conf_consequence not in consequences:
                consequences.append(conf_consequence)

    if subdomains and any(sd in SUBDOMAIN_CONFIDENTIALITY_DOMAINS for sd in subdomains):
        if "Confidentiality" not in all_props:
            secondary_props_list = cybersecurity_properties.get("secondary", [])
            if "Confidentiality" not in secondary_props_list:
                secondary_props_list.append("Confidentiality")
                cybersecurity_properties["secondary"] = secondary_props_list
            if "confidentiality_loss_in_perception_and_sensing" not in consequences:
                consequences.append("confidentiality_loss_in_perception_and_sensing")

    if "Confidentiality" in all_props and functional_domain == "POWERTRAIN_MANAGEMENT":
        active_powertrain_conf = any(
            sd in POWERTRAIN_CONFIDENTIALITY_SUBDOMAINS for sd in (subdomains or [])
        )
        if active_powertrain_conf or not subdomains:
            conf_consequence = "confidentiality_loss_in_powertrain_management"
            if conf_consequence not in consequences:
                consequences.append(conf_consequence)

    if functional_domain == "POWERTRAIN_MANAGEMENT" and "Confidentiality" not in all_props:
        if subdomains and any(sd in POWERTRAIN_CONFIDENTIALITY_SUBDOMAINS for sd in subdomains):
            secondary_props_list = cybersecurity_properties.get("secondary", [])
            if "Confidentiality" not in secondary_props_list:
                secondary_props_list.append("Confidentiality")
                cybersecurity_properties["secondary"] = secondary_props_list
            if "confidentiality_loss_in_powertrain_management" not in consequences:
                consequences.append("confidentiality_loss_in_powertrain_management")

    consequences = list(dict.fromkeys(consequences))
    attack_surfaces = list(dict.fromkeys(attack_surfaces))

    return consequences, damage_seeds, attack_surfaces