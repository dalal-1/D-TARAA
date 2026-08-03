"""Reassessment smoke test against the REAL published CVE-2025-2082 record.

Replaces the previous MOCK_CVE, which asserted CVSS 9.8 AV:N/AC:L, vendor
"trustedfirmware", product "mbed_tls" and a description about Mbed TLS
certificate reassembly. None of those values appear in the published NVD entry:
the real record is CVSS 7.5 AV:A/AC:H, tesla/model_3_firmware, a VCSEC integer
overflow reached through the TPMS certificate response (CWE-190, ZDI-25-265).

`cve_fixture_2025_2082.py` is an offline capture of the published record so the
test runs without network access. It is a fixture, not a mock: no field is
invented. Any synthetic vector used for sensitivity analysis must be named
MOCK_SYNTHETIC_* and must never carry a real CVE identifier.
"""

import sys

sys.path.insert(0, ".")

import cve_enrichment
from cve_fixture_2025_2082 import CVE_2025_2082

CVE_ID = CVE_2025_2082["cveId"]


def _offline_enrich(cve_id, api_key=None):
    if cve_id != CVE_ID:
        raise ValueError(
            f"Offline fixture covers {CVE_ID} only; {cve_id} requires a live "
            f"NVD query."
        )
    return CVE_2025_2082


cve_enrichment.enrich_cve = _offline_enrich

import dtara_orchestrator
dtara_orchestrator.enrich_cve = _offline_enrich

import dtara_engine
dtara_engine.enrich_cve = _offline_enrich

report = dtara_engine.process_cve(CVE_ID)

print(f"cve                : {CVE_ID}")
print(f"cvss               : {CVE_2025_2082['cvss']['vectorString']} "
      f"({CVE_2025_2082['cvss']['baseScore']} "
      f"{CVE_2025_2082['cvss']['baseSeverity']})")
print(f"impacted_ecus      : {report['verdict'].get('impacted_ecus')}")
print(f"threats_total      : {report['verdict'].get('threats_total')}")
print(f"feasibility_changed: {report['verdict'].get('threats_feasibility_changed')}")
print(f"risk_escalated     : {report['verdict'].get('threats_risk_escalated')}")
print(f"max_risk_delta     : {report['verdict'].get('max_risk_delta')}")
print(f"assessor_action    : {report['summary']['assessor_action']}")