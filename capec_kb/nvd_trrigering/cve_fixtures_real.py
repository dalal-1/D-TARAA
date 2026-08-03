"""
Fixtures CVE réelles, transcrites depuis les fiches NVD publiées.

Aucune valeur n'est inventée. Chaque enregistrement est une capture hors ligne
d'une entrée NVD réelle, conservée pour que les tests soient reproductibles sans
accès réseau. Toute vecteur synthétique utilisé pour une analyse de sensibilité
doit être nommé MOCK_SYNTHETIC_* et ne jamais porter d'identifiant CVE réel.
"""

# ---------------------------------------------------------------------------
# CVE-2024-45158 — Mbed TLS, dépassement de tampon de pile dans ECDSA
# Source : https://nvd.nist.gov/vuln/detail/CVE-2024-45158  (capturé 2026-08-02)
# CVSS 3.1 fourni par CISA-ADP ; NVD n'a pas encore publié sa propre évaluation.
# ---------------------------------------------------------------------------
CVE_2024_45158 = {
    "cveId": "CVE-2024-45158",
    "found": True,
    "assessable": True,
    "source": "NVD (CVSS : CISA-ADP ; NVD assessment not yet provided)",
    "captured": "2026-08-02",
    "published": "2024-09-05",
    "lastModified": "2025-05-16",
    "description": (
        "An issue was discovered in Mbed TLS 3.6 before 3.6.1. A stack buffer "
        "overflow in mbedtls_ecdsa_der_to_raw() and mbedtls_ecdsa_raw_to_der() "
        "can occur when the bits parameter is larger than the largest supported "
        "curve. In some configurations with PSA disabled, all values of bits are "
        "affected."
    ),
    "cvss": {
        "version": "3.1",
        "baseScore": 9.8,
        "baseSeverity": "CRITICAL",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "scoringSource": "CISA-ADP",
    },
    "cwes": ["CWE-121"],
    "vendors": ["arm"],
    "products": ["mbed_tls"],
    "cpes": [
        {
            "cpeUri": "cpe:2.3:a:arm:mbed_tls:3.6.0:*:*:*:*:*:*:*",
            "vendor": "arm",
            "product": "mbed_tls",
            "version": "3.6.0",
        },
    ],
    "references": [
        "https://mbed-tls.readthedocs.io/en/latest/security-advisories/"
        "mbedtls-security-advisory-2024-08-2/",
    ],
    "rawCpeCount": 1,
}

# ---------------------------------------------------------------------------
# CVE-2025-2082 — Tesla Model 3 VCSEC, dépassement d'entier via réponse TPMS
# Source : https://nvd.nist.gov/vuln/detail/CVE-2025-2082  (capturé 2026-08-01)
# CVSS 3.0 fourni par le CNA (Zero Day Initiative) ; NVD n'a pas publié la sienne.
#
# Sert de contre-exemple : le CPE est de NIVEAU VÉHICULE
# (cpe:2.3:o:tesla:model_3_firmware) alors que l'architecture est décrite au
# NIVEAU COMPOSANT. L'appariement automatique échoue donc légitimement — c'est
# une limite de couverture CPE, à documenter dans le papier.
# ---------------------------------------------------------------------------
CVE_2025_2082 = {
    "cveId": "CVE-2025-2082",
    "found": True,
    "assessable": True,
    "source": "NVD (CVSS : Zero Day Initiative / CNA)",
    "captured": "2026-08-01",
    "published": "2025-04-30",
    "lastModified": "2026-06-17",
    "description": (
        "Tesla Model 3 VCSEC Integer Overflow Remote Code Execution "
        "Vulnerability. By manipulating the certificate response sent from the "
        "Tire Pressure Monitoring System (TPMS), an attacker can trigger an "
        "integer overflow before writing to memory. Was ZDI-CAN-23800."
    ),
    "cvss": {
        "version": "3.0",
        "baseScore": 7.5,
        "baseSeverity": "HIGH",
        "vectorString": "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "scoringSource": "Zero Day Initiative (CNA)",
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
    ],
    "references": ["https://www.zerodayinitiative.com/advisories/ZDI-25-265/"],
    "rawCpeCount": 1,
}


ALL_FIXTURES = {
    "CVE-2024-45158": CVE_2024_45158,
    "CVE-2025-2082":  CVE_2025_2082,
}