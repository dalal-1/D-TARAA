SFOP_DOMAIN_MAP: dict[str, dict] = {
    "VEHICLE_MOTION_CONTROL": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O3",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "AUTOMATED_DRIVING_CONTROL": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O3",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "PERCEPTION_AND_SENSING": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "OCCUPANT_SAFETY_SYSTEMS": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "POWERTRAIN_MANAGEMENT": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P1",
        },
    },
    "NETWORK_GATEWAYING": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S2",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O2",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "VEHICLE_ACCESS_CONTROL": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F3",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P1",
            "operational_disruption": "P1",
        },
    },
    "BODY_AND_COMFORT": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S0",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O1",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "DIAGNOSTIC_AND_SERVICE": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O2",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "TELEMATICS_AND_CONNECTIVITY": {
        "sfop_primary_category": "Privacy",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P2",
            "operational_disruption": "P3",
        },
    },
    "CHARGING_AND_ENERGY": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S2",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O2",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P1",
        },
    },
    "BIOMETRIC_MONITORING": {
        "sfop_primary_category": "Privacy",
        "harm_severity": {
            "physical_harm": "S0",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O0",
            "operational_disruption": "O1",
        },
        "privacy_severity": {
            "physical_harm": "P3",
            "operational_disruption": "P3",
        },
    },
    "OVER_THE_AIR_UPDATE": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O3",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "V2X_COMMUNICATION": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P1",
            "operational_disruption": "P1",
        },
    },
    "INFOTAINMENT_AND_CONNECTIVITY": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S0",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O0",
            "operational_disruption": "O1",
        },
        "privacy_severity": {
            "physical_harm": "P2",
            "operational_disruption": "P2",
        },
    },
    "FLEET_MANAGEMENT": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O3",
        },
        "privacy_severity": {
            "physical_harm": "P1",
            "operational_disruption": "P2",
        },
    },
    "HUMAN_MACHINE_INTERFACE": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O1",
        },
        "privacy_severity": {
            "physical_harm": "P1",
            "operational_disruption": "P1",
        },
    },
    "THERMAL_MANAGEMENT": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "BODY_CONTROL": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O1",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "CHASSIS_CONTROL": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O3",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "ADVANCED_DRIVER_ASSISTANCE": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "PARKING_AND_MANEUVERING": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S2",
            "operational_disruption": "S1",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F1",
        },
        "operational_severity": {
            "physical_harm": "O2",
            "operational_disruption": "O1",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "CRYPTOGRAPHIC_SERVICES": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O2",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P1",
            "operational_disruption": "P2",
        },
    },
    "SECURE_BOOT_AND_UPDATE": {
        "sfop_primary_category": "Safety",
        "harm_severity": {
            "physical_harm": "S3",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F2",
            "operational_disruption": "F3",
        },
        "operational_severity": {
            "physical_harm": "O3",
            "operational_disruption": "O3",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P0",
        },
    },
    "INTRUSION_DETECTION": {
        "sfop_primary_category": "Operational",
        "harm_severity": {
            "physical_harm": "S1",
            "operational_disruption": "S2",
        },
        "financial_severity": {
            "physical_harm": "F1",
            "operational_disruption": "F2",
        },
        "operational_severity": {
            "physical_harm": "O1",
            "operational_disruption": "O2",
        },
        "privacy_severity": {
            "physical_harm": "P0",
            "operational_disruption": "P1",
        },
    },
}

HEAVENS_SAFETY_DESCRIPTIONS: dict[str, str] = {
    "S3": "life-threatening or fatal injury to vehicle occupants or road users",
    "S2": "serious injury to vehicle occupants or road users",
    "S1": "light or moderate injury, or significant operational disruption",
    "S0": "no safety harm; privacy or operational impact only",
}

HEAVENS_FINANCIAL_DESCRIPTIONS: dict[str, str] = {
    "F3": "large-scale financial loss exceeding OEM warranty or regulatory penalty threshold",
    "F2": "moderate financial loss affecting individual vehicle owner or operator",
    "F1": "minor financial loss or recoverable service disruption cost",
    "F0": "negligible financial impact",
}

HEAVENS_OPERATIONAL_DESCRIPTIONS: dict[str, str] = {
    "O3": "complete loss of safety-critical vehicle function with no fallback",
    "O2": "significant degradation of vehicle operational capability",
    "O1": "minor operational disruption; vehicle remains driveable",
    "O0": "negligible operational impact",
}

HEAVENS_PRIVACY_DESCRIPTIONS: dict[str, str] = {
    "P3": "large-scale breach of sensitive personal or biometric data; GDPR Art.9 category",
    "P2": "disclosure of personal data enabling identification or tracking of individuals",
    "P1": "limited personal data exposure with low re-identification risk",
    "P0": "no personal data impact",
}