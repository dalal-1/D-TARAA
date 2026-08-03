"""
Captured NVD record for CVE-2025-2082.

This is a verbatim capture of the published NVD entry, retained as an offline
fixture so the reassessment is reproducible without network access. It is NOT a
mock: every field below is transcribed from https://nvd.nist.gov/vuln/detail/CVE-2025-2082
(captured 2026-08-01). The CNA is the Zero Day Initiative; NVD has not published
its own CVSS assessment for this CVE, so the CNA vector is used and labelled.

Replaces the previous MOCK_CVE in test_multi_ecu.py, which asserted
CVSS 9.8 AV:N/AC:L, vendor "trustedfirmware", product "mbed_tls". None of those
values appear in the published record.
"""

CVE_2025_2082 = {
    "cveId": "CVE-2025-2082",
    "found": True,
    "source": "NVD (CNA: Zero Day Initiative)",
    "captured": "2026-08-01",
    "published": "2025-04-30",
    "lastModified": "2026-06-17",
    "description": (
        "Tesla Model 3 VCSEC Integer Overflow Remote Code Execution Vulnerability. "
        "This vulnerability allows network-adjacent attackers to execute arbitrary "
        "code on affected Tesla Model 3 vehicles. Authentication is not required to "
        "exploit this vulnerability. The specific flaw exists within the VCSEC "
        "module. By manipulating the certificate response sent from the Tire "
        "Pressure Monitoring System (TPMS), an attacker can trigger an integer "
        "overflow before writing to memory. An attacker can leverage this "
        "vulnerability to execute code in the context of the VCSEC module and send "
        "arbitrary messages to the vehicle CAN bus. Was ZDI-CAN-23800."
    ),
    "cvss": {
        "version": "3.0",
        "baseScore": 7.5,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "scoringSource": "Zero Day Initiative (CNA); NVD assessment not provided",
    },
    "cwes": ["CWE-190"],
    "vendors": ["tesla"],
    "products": ["model_3_firmware", "model_3"],
    "cpes": [
        {
            "cpeUri": "cpe:2.3:o:tesla:model_3_firmware:*:*:*:*:*:*:*:*",
            "vendor": "tesla",
            "product": "model_3_firmware",
            "version": "*",
            "versionEndExcluding": "2024.14",
        },
        {
            "cpeUri": "cpe:2.3:h:tesla:model_3:-:*:*:*:*:*:*:*",
            "vendor": "tesla",
            "product": "model_3",
            "version": "-",
        },
    ],
    "references": ["https://www.zerodayinitiative.com/advisories/ZDI-25-265/"],
    "rawCpeCount": 2,
}