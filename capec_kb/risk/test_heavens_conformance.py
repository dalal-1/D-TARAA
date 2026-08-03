"""Conformance tests: every constant checked against the published source.

Lancer depuis n'importe ou :  python3 capec_kb/risk/test_heavens_conformance.py
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent            # capec_kb/risk
_KB   = _HERE.parent                               # capec_kb
sys.path.insert(0, str(_KB / "nvd_trrigering"))
_OUT  = _KB / "output" / "outputs"

import json
from cve_heavens_mapper_v2 import (
    WOO_TABLE, A_MAX, map_cve_to_heavens_signal, parse_vector,
)
from feasibility_updater import _a_norm_to_rating as rate
from cve_fixture_2025_2082 import CVE_2025_2082

fails = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    if not cond:
        fails.append(name)


print("HEAVENS 2.0 Table 4 — window of opportunity grid (Small=0 Med=1 Large=2 Unl=3)")
# transcribed from HEAVENS 2.0 Table 4; rows = exposure time, cols = access means
TABLE4 = {
    #        P1 P2 P3 R1 R2
    0:      [0, 0, 0, 0, 1],   # Rare
    1:      [0, 0, 0, 1, 2],   # Sporadic
    2:      [0, 0, 1, 2, 3],   # Frequent
    3:      [0, 1, 2, 2, 3],   # Unlimited
}
ok = all(WOO_TABLE[(am, et)] == TABLE4[et][am - 1]
         for et in range(4) for am in range(1, 6))
check("all 20 cells reproduce Table 4", ok)

print("\nHEAVENS 2.0 Table 6 — attack feasibility thresholds")
check("A_norm 0.29 -> Very Low", rate(0.29) == "Very Low")
check("A_norm 0.30 -> Low", rate(0.30) == "Low")
check("A_norm 0.59 -> Low", rate(0.59) == "Low")
check("A_norm 0.60 -> Medium", rate(0.60) == "Medium")
check("A_norm 0.79 -> Medium", rate(0.79) == "Medium")
check("A_norm 0.80 -> High", rate(0.80) == "High")
check("A_norm 1.00 -> High", rate(1.00) == "High")

print("\nHEAVENS 2.0 Eq. (4) — normalisation, n = 4 parameters on 0..3")
check("A_MAX == 3 * n == 12", A_MAX == 12)

print("\nISO/SAE 21434 [RC-08-04] — only AV, AC, PR, UI consulted")
v = parse_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("vector parses", v["AV"] == "A" and v["AC"] == "H" and v["PR"] == "N" and v["UI"] == "N")

print("\nParameter semantics — SE / KoIC / Eq are never revised from CVSS")
sig = map_cve_to_heavens_signal(CVE_2025_2082)
check("revisable parameters == ('WoO',)", sig.revisable_parameters == ("WoO",))

print("\nCVE-2025-2082 real record")
check("vector is the published CNA vector",
      CVE_2025_2082["cvss"]["vectorString"] == "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("base score 7.5", CVE_2025_2082["cvss"]["baseScore"] == 7.5)
check("AV:A -> access means 4 (Remote 1 - proximity)", sig.access_means == 4)
check("PR:N,UI:N -> exposure time 3 (Unlimited)", sig.exposure_time == 3)
check("Table 4 (4,3) -> WoO = 2 (Large)", sig.woo_value == 2, f"got {sig.woo_value}")

print("\nDeferral policy — a CVE without a CVSS vector must not be assessed")
try:
    map_cve_to_heavens_signal({"cveId": "CVE-X", "cvss": {}})
    check("raises on missing vector", False)
except ValueError:
    check("raises on missing vector", True)

print("\nAgregation par threat scenario (attack_feasibility.py v1.5.0)")
feas = json.load(open(_OUT / "attack_feasibility.json"))
paths = json.load(open(_OUT / "attack_paths.json"))
owner = {p["path_id"]: p["threat_id"] for p in paths}
check("un enregistrement par threat scenario (109)", len(feas) == 109, f"obtenu {len(feas)}")
check("aucun enregistrement ne couvre plusieurs threats",
      all(len(r["covered_threat_ids"]) == 1 for r in feas))
bad = [r["threat_id"] for r in feas
       if any(owner.get(p["path_id"]) != r["threat_id"] for p in r["per_path_ratings"])]
check("aucun chemin appartenant a un autre threat", not bad, f"violations: {len(bad)}")
worst_ok = all(r["A_norm_max"] == max(p["A_norm"] for p in r["per_path_ratings"])
               for r in feas if r["per_path_ratings"])
check("A_norm_max = max sur les chemins propres au threat", worst_ok)
ts59 = [r for r in feas if r["threat_id"] == "TS-59"]
if ts59:
    check("TS-59 note Low (chemin unique AP-317, A_norm 0.5)",
          ts59[0]["attack_feasibility_rating"] == "Low",
          f"obtenu {ts59[0]['attack_feasibility_rating']}")

print("\n" + ("ALL CHECKS PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
