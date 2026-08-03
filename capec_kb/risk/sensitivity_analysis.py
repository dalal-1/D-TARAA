#!/usr/bin/env python3
"""
Analyse de sensibilité des notes de risque D-TARA.

Mesure la part des notes de risque qui change lorsqu'on perturbe les paramètres
libres du modèle. NE MODIFIE AUCUN ARTEFACT : recalcule en mémoire à partir de
damage_scenarios.json, threat_scenarios.json et attack_feasibility.json.

Motivation normative
--------------------
ISO/SAE 21434 [RQ-05-06] fait de la matrice de risque et de ses valeurs une
définition ORGANISATIONNELLE. Les seuils sont donc légitimement paramétrables --
mais cela impose de publier la sensibilité du résultat à ces paramètres.
HEAVENS 2.0 §3.2 et UPDATE P2/P3 (normalisation) rendent le modèle explicitement
customisable, pour la même raison.

Paramètres balayés
------------------
  seuils d'impact       HEAVENS 2.0 Table 7   (0.01 / 0.05 / 0.45)
  seuils de feasibility HEAVENS 2.0 Table 6   (0.30 / 0.60 / 0.80)
  poids d'impact        HEAVENS 2.0 Éq. (5)   (w_s, w_f, w_o, w_p)

Usage
-----
    python3 capec_kb/risk/sensitivity_analysis.py
    python3 capec_kb/risk/sensitivity_analysis.py --json out.json
    python3 capec_kb/risk/sensitivity_analysis.py --latex        # table pour le papier
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_OUT = _HERE.parent / "output" / "outputs"
sys.path.insert(0, str(_HERE))

import impact as I  # noqa: E402

# HEAVENS 2.0 Table 8
RISK_VALUE = {
    ("Negligible", "Very Low"): 1, ("Negligible", "Low"): 1,
    ("Negligible", "Medium"): 2,   ("Negligible", "High"): 2,
    ("Moderate", "Very Low"): 1,   ("Moderate", "Low"): 2,
    ("Moderate", "Medium"): 3,     ("Moderate", "High"): 4,
    ("Major", "Very Low"): 2,      ("Major", "Low"): 3,
    ("Major", "Medium"): 4,        ("Major", "High"): 5,
    ("Severe", "Very Low"): 3,     ("Severe", "Low"): 4,
    ("Severe", "Medium"): 5,       ("Severe", "High"): 5,
}
LEVEL = {1: "Negligible", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

BASE_IMPACT_TH = (0.01, 0.05, 0.45)      # Table 7
BASE_FEAS_TH = (0.30, 0.60, 0.80)        # Table 6
BASE_WEIGHTS = dict(I.DEFAULT_DIMENSION_WEIGHTS)   # source unique : impact.py


def _feasibility_rating(a_norm: float, th: tuple) -> str:
    lo, mid, hi = th
    if a_norm < lo:
        return "Very Low"
    if a_norm < mid:
        return "Low"
    if a_norm < hi:
        return "Medium"
    return "High"


def compute(ds, ts, feas, impact_th, feas_th, weights) -> dict[str, str]:
    """Recalcule toutes les notes de risque sous une configuration donnée."""
    I._IMPACT_THRESHOLDS[:] = [
        (0.0, impact_th[0], "Negligible"),
        (impact_th[0], impact_th[1], "Moderate"),
        (impact_th[1], impact_th[2], "Major"),
        (impact_th[2], float("inf"), "Severe"),
    ]
    I._reset_counter()
    ds_impact = {d["damage_id"]: I.compute_ds_impact(d, weights) for d in ds}

    # HEAVENS 2.0 §4.2.5 : plus haute valeur parmi les damage scenarios associés
    threat_impact = {}
    for t in ts:
        ids = t.get("damage_scenario_ids") or (
            [t["damage_scenario_id"]] if t.get("damage_scenario_id") else []
        )
        recs = [ds_impact[i] for i in ids if i in ds_impact]
        if recs:
            threat_impact[t["threat_id"]] = max(recs, key=lambda r: r.I_nsum).impact_rating

    out = {}
    for f in feas:
        tid = f["threat_id"]
        if tid in threat_impact:
            fr = _feasibility_rating(f["A_norm_max"], feas_th)
            out[tid] = LEVEL[RISK_VALUE[(threat_impact[tid], fr)]]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", metavar="FICHIER")
    ap.add_argument("--latex", action="store_true")
    args = ap.parse_args()

    need = ["damage_scenarios.json", "threat_scenarios.json", "attack_feasibility.json"]
    missing = [n for n in need if not (_OUT / n).exists()]
    if missing:
        sys.exit(f"Artefacts absents : {missing}\nLancez d'abord : python3 corrected_run.py")

    raw = json.loads((_OUT / "damage_scenarios.json").read_text(encoding="utf-8"))
    ds = raw.get("scenarios", raw) if isinstance(raw, dict) else raw
    ts = json.loads((_OUT / "threat_scenarios.json").read_text(encoding="utf-8"))
    feas = json.loads((_OUT / "attack_feasibility.json").read_text(encoding="utf-8"))

    stale = [r for r in feas if len(r.get("covered_threat_ids", [])) > 1]
    if stale:
        sys.exit(f"{len(stale)} enregistrements pré-v1.5.0. Relancez corrected_run.py")

    ref = compute(ds, ts, feas, BASE_IMPACT_TH, BASE_FEAS_TH, BASE_WEIGHTS)
    n = len(ref)

    print(f"\nANALYSE DE SENSIBILITÉ  (n = {n} threat scenarios)")
    print(f"Référence : {dict(Counter(ref.values()))}\n")

    configs = [
        ("Seuils impact  -50 %", tuple(x * 0.5 for x in BASE_IMPACT_TH), BASE_FEAS_TH, BASE_WEIGHTS),
        ("Seuils impact  -25 %", tuple(x * 0.75 for x in BASE_IMPACT_TH), BASE_FEAS_TH, BASE_WEIGHTS),
        ("Seuils impact  +25 %", tuple(x * 1.25 for x in BASE_IMPACT_TH), BASE_FEAS_TH, BASE_WEIGHTS),
        ("Seuils impact  +50 %", tuple(x * 1.5 for x in BASE_IMPACT_TH), BASE_FEAS_TH, BASE_WEIGHTS),
        ("Seuils feasib. -20 %", BASE_IMPACT_TH, tuple(x * 0.8 for x in BASE_FEAS_TH), BASE_WEIGHTS),
        ("Seuils feasib. -10 %", BASE_IMPACT_TH, tuple(x * 0.9 for x in BASE_FEAS_TH), BASE_WEIGHTS),
        ("Seuils feasib. +10 %", BASE_IMPACT_TH, tuple(min(x * 1.1, 1.0) for x in BASE_FEAS_TH), BASE_WEIGHTS),
        ("Seuils feasib. +20 %", BASE_IMPACT_TH, tuple(min(x * 1.2, 1.0) for x in BASE_FEAS_TH), BASE_WEIGHTS),
        ("Poids uniformes w = 1", BASE_IMPACT_TH, BASE_FEAS_TH, {k: 1.0 for k in BASE_WEIGHTS}),
        ("Poids w_s = 5", BASE_IMPACT_TH, BASE_FEAS_TH, {**BASE_WEIGHTS, "safety": 5}),
        ("Poids w_s = 10  (HEAVENS)", BASE_IMPACT_TH, BASE_FEAS_TH, {**BASE_WEIGHTS, "safety": 10}),
        ("Poids w_s = w_f = 10", BASE_IMPACT_TH, BASE_FEAS_TH, {**BASE_WEIGHTS, "safety": 10, "financial": 10}),
    ]

    print(f"{'Configuration':<28}{'Distribution du risque':<48}{'Changées':>12}")
    print("-" * 90)
    results = []
    for label, ith, fth, w in configs:
        r = compute(ds, ts, feas, ith, fth, w)
        changed = sum(1 for k in ref if r.get(k) != ref[k])
        pct = 100 * changed / n
        results.append({"config": label, "distribution": dict(Counter(r.values())),
                        "changed": changed, "pct": round(pct, 1)})
        print(f"{label:<28}{str(dict(Counter(r.values()))):<48}{changed:>4}/{n} ({pct:>4.0f} %)")

    # --- diagnostic : pouvoir discriminant --------------------------------
    vals = sorted(f["A_norm_max"] for f in feas)
    dist = Counter(vals)
    print(f"\nPOUVOIR DISCRIMINANT DE LA FEASIBILITY")
    print(f"  valeurs distinctes de A_norm : {len(dist)} pour {len(vals)} menaces")
    print(f"  étendue : {min(vals):.4f} – {max(vals):.4f}")
    for v, c in sorted(dist.items()):
        print(f"    {v:.4f}  {'#' * max(1, c // 2):<46} {c}")
    print(f"  seuils HEAVENS Table 6 : 0.30 · 0.60 · 0.80")
    mode, mode_n = dist.most_common(1)[0]
    print(f"  mode : {mode:.4f} ({mode_n} menaces, {100*mode_n/len(vals):.0f} %)")

    worst = max(results, key=lambda r: r["changed"])
    print(f"\nSensibilité maximale : {worst['config']} → "
          f"{worst['changed']}/{n} ({worst['pct']} %)")

    if args.latex:
        print("\n% --- table LaTeX ---")
        print("\\begin{tabular}{lrr}\n\\toprule")
        print("Configuration & Notes changées & \\% \\\\\n\\midrule")
        for r in results:
            print(f"{r['config']} & {r['changed']}/{n} & {r['pct']:.0f} \\\\")
        print("\\bottomrule\n\\end{tabular}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "n": n,
            "reference": dict(Counter(ref.values())),
            "baseline_parameters": {
                "impact_thresholds": list(BASE_IMPACT_TH),
                "feasibility_thresholds": list(BASE_FEAS_TH),
                "weights": BASE_WEIGHTS,
            },
            "a_norm_distribution": {str(k): v for k, v in sorted(dist.items())},
            "distinct_a_norm_values": len(dist),
            "results": results,
        }, indent=2), encoding="utf-8")
        print(f"\nÉcrit : {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())