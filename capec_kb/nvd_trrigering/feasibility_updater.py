"""CVE-driven attack feasibility revision (v2.0.0 - corrected).

Standards basis
---------------
ISO/SAE 21434 [RC-07-01] : attack paths should be analysed per 8.6 to map
                           discovered vulnerabilities to specific attack paths.
ISO/SAE 21434 [RC-07-02] : an attack feasibility rating should be determined for
                           the discovered vulnerabilities.
ISO/SAE 21434 [RC-08-04] : a CVSS-based approach uses AV, AC, PR, UI.
ISO/SAE 21434 8.1 NOTE 3 : the impact of a damage scenario is the same
                           regardless of the attack path or the threat agent,
                           so impact is never revised here.
HEAVENS 2.0 Tables 2/3/4 : window of opportunity from access means and exposure
                           time.
HEAVENS 2.0 Table 5      : parameter definitions.
HEAVENS 2.0 Table 6      : A_norm thresholds.

What changed from v1
--------------------
v1 blended CVSS-derived values into all four HEAVENS parameters using
AV -> Specialist Expertise and UI -> Equipment. HEAVENS 2.0 Table 5 defines
Expertise as the level of knowledge required to carry out the attack, and
Equipment as the hardware or software needed to exploit. Attack Vector measures
reachability and User Interaction measures whether a victim must act; neither
measures the parameter it was assigned to. Those two mappings were the sole
cause of the risk escalations previously reported.

v2 revises ONLY window of opportunity, via the HEAVENS Table 4 grid.

Also removed: the dead `_compute_path_relevance` surface/technology matching,
whose match branch and fall-through branch both returned 1.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cve_heavens_mapper_v2 import CveSignal, A_MAX

UPDATER_VERSION = "2.0.0"

# HEAVENS 2.0 Table 6
FEASIBILITY_THRESHOLDS: list[tuple[float, float, str]] = [
    (0.00, 0.30, "Very Low"),
    (0.30, 0.60, "Low"),
    (0.60, 0.80, "Medium"),
    (0.80, 1.01, "High"),
]


def _a_norm_to_rating(a_norm: float) -> str:
    for lo, hi, label in FEASIBILITY_THRESHOLDS:
        if lo <= a_norm < hi:
            return label
    return "High"


def _value(param) -> int:
    """per_path_ratings entries store either {'value': n, ...} or a bare int."""
    return param["value"] if isinstance(param, dict) else param


@dataclass
class UpdatedPathRating:
    path_id: str
    threat_id: str
    path_type: str
    relevance: str                # "target" | "transit" | "none"
    se: int                       # unchanged
    koic: int                     # unchanged
    eq: int                       # unchanged
    woo_baseline: int
    woo_updated: int
    a_sum_baseline: int
    a_sum_updated: int
    a_norm_baseline: float
    a_norm_updated: float
    rating_baseline: str
    rating_updated: str
    changed: bool
    provenance: dict = field(default_factory=dict)


@dataclass
class UpdatedFeasibilityRecord:
    feasibility_id: str
    threat_id: str
    tree_id: str
    target_asset_id: str
    target_asset_name: str
    a_norm_max_baseline: float
    a_norm_max_updated: float
    feasibility_rating_baseline: str
    feasibility_rating_updated: str
    feasibility_changed: bool
    worst_path_id_updated: str
    updated_path_ratings: list[UpdatedPathRating]
    cve_id: str
    affected_technology: str
    affected_ecu: str
    revised_parameters: tuple[str, ...] = ("WoO",)
    updater_version: str = UPDATER_VERSION
    signal_rationale: str = ""


def _path_relevance(path: dict | None, affected_ecu: str) -> str:
    """Classify a path by its structural relation to the CVE-affected component."""
    if path is None:
        return "none"
    if path.get("target_ecu", "") == affected_ecu:
        return "target"
    nodes: set[str] = set()
    for step in path.get("steps", []):
        nodes.add(step.get("src_node", ""))
        nodes.add(step.get("dst_node", ""))
    return "transit" if affected_ecu in nodes else "none"


def update_feasibility_record(
    feasibility_record: dict,
    signal: CveSignal,
    path_index: dict[str, dict],
    affected_ecu: str,
    matched_technologies: list[str],
) -> UpdatedFeasibilityRecord:
    baseline_a_norm_max = feasibility_record["A_norm_max"]
    baseline_rating = feasibility_record["attack_feasibility_rating"]

    updated: list[UpdatedPathRating] = []
    best_norm = 0.0
    best_pid = feasibility_record.get("worst_path_id", "")

    for pr in feasibility_record.get("per_path_ratings", []):
        path = path_index.get(pr["path_id"])
        relevance = _path_relevance(path, affected_ecu)

        se = _value(pr["SE"])
        koic = _value(pr["KoIC"])
        eq = _value(pr["Eq"])
        woo_base = _value(pr["WoO"])

        if relevance == "target":
            # Monotone: a disclosure may widen the window toward the CVSS-implied
            # value but never narrow it below the architecture-derived baseline.
            # Declared conservative assumption, not a HEAVENS/ISO requirement.
            woo_new = max(woo_base, signal.woo_value)
            reason = (
                f"target of the CVE-affected component; WoO = max(baseline "
                f"{woo_base}, CVE-implied {signal.woo_value})"
            )
        else:
            # A vulnerability in an intermediate hop does not alter the window of
            # opportunity on the target asset.
            woo_new = woo_base
            reason = (
                f"path does not terminate at {affected_ecu} "
                f"(relevance={relevance}); WoO unchanged"
            )

        a_sum_base = pr["A_sum"]
        a_sum_new = se + koic + woo_new + eq
        a_norm_base = round(a_sum_base / A_MAX, 6)
        a_norm_new = round(a_sum_new / A_MAX, 6)

        if a_norm_new > best_norm:
            best_norm = a_norm_new
            best_pid = pr["path_id"]

        updated.append(UpdatedPathRating(
            path_id=pr["path_id"],
            threat_id=pr.get("threat_id", feasibility_record["threat_id"]),
            path_type=pr.get("path_type", ""),
            relevance=relevance,
            se=se, koic=koic, eq=eq,
            woo_baseline=woo_base,
            woo_updated=woo_new,
            a_sum_baseline=a_sum_base,
            a_sum_updated=a_sum_new,
            a_norm_baseline=a_norm_base,
            a_norm_updated=a_norm_new,
            rating_baseline=pr.get("rating", _a_norm_to_rating(a_norm_base)),
            rating_updated=_a_norm_to_rating(a_norm_new),
            changed=a_sum_new != a_sum_base,
            provenance={
                "revised_parameter": "WoO",
                "unrevised": ["SE", "KoIC", "Eq"],
                "unrevised_reason": (
                    "no CVSS base metric measures expertise, information "
                    "distribution, or equipment (HEAVENS 2.0 Table 5)"
                ),
                "cvss_av": signal.cvss_av,
                "cvss_pr": signal.cvss_pr,
                "cvss_ui": signal.cvss_ui,
                "access_means": signal.access_means,
                "exposure_time": signal.exposure_time,
                "woo_from_table4": signal.woo_value,
                "relevance_reason": reason,
                "delta": woo_new - woo_base,
            },
        ))

    return UpdatedFeasibilityRecord(
        feasibility_id=feasibility_record["feasibility_id"],
        threat_id=feasibility_record["threat_id"],
        tree_id=feasibility_record.get("tree_id", ""),
        target_asset_id=feasibility_record.get("target_asset_id", ""),
        target_asset_name=feasibility_record.get("target_asset_name", ""),
        a_norm_max_baseline=baseline_a_norm_max,
        a_norm_max_updated=round(best_norm, 6),
        feasibility_rating_baseline=baseline_rating,
        feasibility_rating_updated=_a_norm_to_rating(best_norm),
        feasibility_changed=_a_norm_to_rating(best_norm) != baseline_rating,
        worst_path_id_updated=best_pid,
        updated_path_ratings=updated,
        cve_id=signal.cve_id,
        affected_technology=", ".join(matched_technologies),
        affected_ecu=affected_ecu,
        signal_rationale=signal.rationale,
    )