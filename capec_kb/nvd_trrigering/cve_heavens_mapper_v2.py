"""
CVSS -> HEAVENS 2.0 attack-potential mapping (corrected).

Standards basis
---------------
ISO/SAE 21434 [RC-08-04] : a CVSS-based approach should use the exploit metrics
                           of the base metric group: AV, AC, PR, UI.
HEAVENS 2.0 Table 2      : "access means" levels (Physical 1..Remote 2).
HEAVENS 2.0 Table 3      : "asset exposure time" levels (Rare..Unlimited).
HEAVENS 2.0 Table 4      : window of opportunity = f(access means, exposure time).
HEAVENS 2.0 Table 5      : parameter value scales (0..3), UPDATE P1 direction.

Design rule
-----------
A CVSS base metric may only revise a HEAVENS parameter it actually measures.

  AV  -> access means           (Table 2: reachability / proximity)
  PR, UI -> asset exposure time (Table 3: how freely the attacker can act)
  (access means, exposure time) -> WoO via Table 4

  Expertise (SE)        : HEAVENS defines this as the level of knowledge required
                          to carry out the attack. No CVSS base metric measures it.
                          NOT revised.
  Knowledge of item     : HEAVENS defines this as the *distribution* of information
  (KoIC)                  about the target (Public..Critical). AC measures conditions
                          outside the attacker's control, not information
                          distribution. NOT revised.
  Equipment (Eq)        : HEAVENS defines this as the hardware/software needed.
                          No CVSS base metric measures it. NOT revised.

The previous implementation mapped AV->SE and UI->Eq. Both assign a CVSS metric
to a HEAVENS parameter whose published definition it does not describe, and
together they were the sole cause of the reported risk escalations.

Exposure-time calibration (declared engineering decision, not from a standard)
-----------------------------------------------------------------------------
HEAVENS Table 3 levels are qualitative. The mapping below is our calibration and
must be reported as such:

  PR:N + UI:N -> Unlimited  (attacker can trigger the exposure at will)
  PR:N + UI:R -> Frequent   (needs a victim action that occurs often)
  PR:L + UI:N -> Frequent   (needs a foothold that is commonly available)
  PR:L + UI:R -> Sporadic
  PR:H + *    -> Rare       (needs privileged state that is rarely available)
"""

from __future__ import annotations

from dataclasses import dataclass

# --- HEAVENS 2.0 Table 5: all parameters on 0..3, higher = more feasible -----
SE_MAX = 3
KOIC_MAX = 3
WOO_MAX = 3
EQ_MAX = 3
A_MAX = SE_MAX + KOIC_MAX + WOO_MAX + EQ_MAX  # = 12, HEAVENS 2.0 Eq. (4), n=4

# --- HEAVENS 2.0 Table 2: access means, ascending criticality ----------------
ACCESS_MEANS = {
    1: "Physical 1 - component disassembly",
    2: "Physical 2 - component access",
    3: "Physical 3 - no disassembly",
    4: "Remote 1 - vehicle proximity",
    5: "Remote 2 - anywhere",
}

# --- HEAVENS 2.0 Table 3: asset exposure time --------------------------------
EXPOSURE_TIME = {0: "Rare", 1: "Sporadic", 2: "Frequent", 3: "Unlimited"}

# --- HEAVENS 2.0 Table 4: WoO = f(access means, exposure time) ---------------
# Small=0, Medium=1, Large=2, Unlimited=3
WOO_TABLE: dict[tuple[int, int], int] = {
    (1, 0): 0, (1, 1): 0, (1, 2): 0, (1, 3): 0,
    (2, 0): 0, (2, 1): 0, (2, 2): 0, (2, 3): 1,
    (3, 0): 0, (3, 1): 0, (3, 2): 1, (3, 3): 2,
    (4, 0): 0, (4, 1): 1, (4, 2): 2, (4, 3): 2,
    (5, 0): 1, (5, 1): 2, (5, 2): 3, (5, 3): 3,
}

# --- CVSS AV -> HEAVENS Table 2 access means ---------------------------------
_AV_TO_ACCESS_MEANS: dict[str, int] = {
    "N": 5, "NETWORK": 5,      # Remote 2 - anywhere
    "A": 4, "ADJACENT": 4,     # Remote 1 - vehicle proximity (BLE, Wi-Fi, V2X)
    "L": 3, "LOCAL": 3,        # Physical 3 - no disassembly (OBD-II, USB)
    "P": 2, "PHYSICAL": 2,     # Physical 2 - component access
}

# --- CVSS (PR, UI) -> HEAVENS Table 3 exposure time (declared calibration) ---
def _exposure_time(pr: str, ui: str) -> int:
    pr_n = pr in ("N", "NONE")
    pr_l = pr in ("L", "LOW")
    ui_n = ui in ("N", "NONE")
    if pr_n and ui_n:
        return 3  # Unlimited
    if pr_n or (pr_l and ui_n):
        return 2  # Frequent
    if pr_l:
        return 1  # Sporadic
    return 0      # Rare


@dataclass(frozen=True)
class CveSignal:
    """A CVSS-derived revision proposal for HEAVENS window of opportunity only."""
    cve_id: str
    woo_value: int
    access_means: int
    exposure_time: int
    cvss_vector: str
    cvss_av: str
    cvss_ac: str
    cvss_pr: str
    cvss_ui: str
    cvss_score: float | None
    revisable_parameters: tuple[str, ...] = ("WoO",)
    rationale: str = ""


def parse_vector(vector_string: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in (vector_string or "").split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip().upper()] = v.strip().upper()
    return metrics


def map_cve_to_heavens_signal(cve_enriched: dict) -> CveSignal:
    cve_id = cve_enriched.get("cveId", "UNKNOWN")
    cvss = cve_enriched.get("cvss", {}) or {}
    vector_string = cvss.get("vectorString", "") or ""
    parsed = parse_vector(vector_string)

    if not parsed.get("AV"):
        raise ValueError(
            f"{cve_id}: no CVSS base vector available. Per the deferral policy this "
            f"CVE must be queued, not assessed with default metric values."
        )

    av = parsed.get("AV", "")
    ac = parsed.get("AC", "")
    pr = parsed.get("PR", "H")
    ui = parsed.get("UI", "R")

    am = _AV_TO_ACCESS_MEANS.get(av)
    if am is None:
        raise ValueError(f"{cve_id}: unrecognised CVSS AV value {av!r}")

    et = _exposure_time(pr, ui)
    woo = WOO_TABLE[(am, et)]

    rationale = (
        f"AV:{av} -> access means '{ACCESS_MEANS[am]}' (HEAVENS 2.0 Table 2); "
        f"PR:{pr}/UI:{ui} -> exposure time '{EXPOSURE_TIME[et]}' (Table 3); "
        f"Table 4 -> WoO={woo}. SE, KoIC and Eq are not revised: no CVSS base "
        f"metric measures expertise, information distribution, or equipment."
    )

    return CveSignal(
        cve_id=cve_id,
        woo_value=woo,
        access_means=am,
        exposure_time=et,
        cvss_vector=vector_string,
        cvss_av=av,
        cvss_ac=ac,
        cvss_pr=pr,
        cvss_ui=ui,
        cvss_score=cvss.get("baseScore"),
        rationale=rationale,
    )