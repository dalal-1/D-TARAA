#!/usr/bin/env python3
"""
Génération de [WP-08-08] et [WP-09-05]  —  issue M6.

Deux work products manquants au pipeline :

  [WP-08-08]  Risk treatment decision per threat scenario   (ISO/SAE 21434 8.9.3)
  [WP-09-05]  Cybersecurity claims                          (ISO/SAE 21434 9.4.3)

Base normative — sources vérifiées uniquement
---------------------------------------------
ISO/SAE 21434 DIS:2020

  [RQ-08-12]  « A risk treatment option shall be determined, considering impact
              categories, attack paths and the results from risk determination. »
  8.9.2 NOTE 1  options : (a) éviter, (b) réduire, (c) partager/transférer,
              (d) accepter/conserver.
  8.9.2 NOTE 2  « Risk treatment options are not mutually exclusive or
              appropriate in all circumstances. »
  [PM-08-01]  « For threat scenarios of risk value 1 [...] compliance with 9.5,
              and with Clauses 10 and 11 of this document may be omitted. »
  8.9.2 NOTE 5  « For risk acceptance and risk transfer, the corresponding
              rationales are recorded as cybersecurity claims. »
  [RQ-09-07]  si le traitement est la réduction, un ou plusieurs cybersecurity
              goals doivent être spécifiés.
  [RQ-09-08]  cybersecurity claims obligatoires si (a) une hypothèse sur
              l'environnement opérationnel rend le risque acceptable, ou (b) le
              risque est partagé ou transféré.
  3.1.10      « CYBERSECURITY CLAIM : statement on a risk that is accepted.
              Note : includes a description of why the risk is acceptable and a
              specification under which conditions the risk needs to be
              re-evaluated. »
  9.4.2 NOTE 12  « Cybersecurity claims are subject to monitoring. »

HEAVENS 2.0 (Lautenbach, Almgren, Olovsson, CSCS '21)

  UPDATE G11  ajout de la décision de traitement du risque.
  UPDATE G12  ajout des cybersecurity claims et des cybersecurity goals.
  §4.2.5      « we would argue that risk values of 1 or 2 represent acceptable
              levels of risk in most cases. »
  §4.2.6      définitions de risk avoidance / sharing / acceptance / reduction ;
              « any assumptions which lead to the acceptability of the risk need
              to be documented ».
  §4.3        « claims must be documented for all accepted risks ».

Politique organisationnelle déclarée
------------------------------------
[RQ-05-06] fait des valeurs de risque une définition organisationnelle ; la
règle ci-dessous est donc une POLITIQUE, à déclarer dans la section Méthodologie
du papier, et non une prescription normative :

  valeur 1  -> ACCEPT   ancré sur [PM-08-01] + HEAVENS §4.2.5 ; claim requis
  valeur 2  -> ACCEPT   ancré sur HEAVENS §4.2.5 ; claim requis
  valeur 3+ -> REDUCE   [RQ-09-07] : cybersecurity goals requis

AVOID et SHARE/TRANSFER ne sont PAS attribués automatiquement. 8.9.2 NOTE 1(a)
définit l'évitement comme la suppression de la source de risque ou l'arrêt de
l'activité, et NOTE 1(c) le partage comme un acte contractuel : ce sont des
décisions d'organisation, hors de portée d'une dérivation automatique. Elles sont
listées comme options disponibles pour l'assesseur, conformément à 8.9.2 NOTE 2.

Usage
-----
    python3 capec_kb/risk/risk_treatment.py
    python3 capec_kb/risk/risk_treatment.py --outputs chemin/vers/outputs
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

GENERATOR_VERSION = "1.0.0"

_HERE = Path(__file__).resolve().parent
_DEFAULT_OUT = _HERE.parent / "output" / "outputs"

# Politique organisationnelle — voir en-tête. À déclarer dans le papier.
ACCEPTANCE_MAX_RISK_VALUE = 2

_OPTIONS = ["avoid", "reduce", "share_or_transfer", "accept"]


def _decide(risk_value: int) -> tuple[str, str, str]:
    """Renvoie (option, justification, ancrage normatif)."""
    if risk_value <= ACCEPTANCE_MAX_RISK_VALUE:
        anchor = "HEAVENS 2.0 sec. 4.2.5"
        if risk_value == 1:
            anchor += " ; ISO/SAE 21434 [PM-08-01]"
        return (
            "accept",
            f"Valeur de risque {risk_value} <= seuil d'acceptation "
            f"{ACCEPTANCE_MAX_RISK_VALUE} défini par l'organisation.",
            anchor,
        )
    return (
        "reduce",
        f"Valeur de risque {risk_value} > seuil d'acceptation "
        f"{ACCEPTANCE_MAX_RISK_VALUE}. Réduction par cybersecurity goals.",
        "ISO/SAE 21434 [RQ-09-07] ; HEAVENS 2.0 sec. 4.2.6",
    )


def build_treatments(risks: list[dict], goals: list[dict]) -> list[dict]:
    """[WP-08-08] — une décision par threat scenario."""
    goals_by_ts: dict[str, list[str]] = {}
    for g in goals:
        for tid in g.get("linked_ts_ids") or []:
            goals_by_ts.setdefault(tid, []).append(g["goal_id"])

    out: list[dict] = []
    for i, r in enumerate(sorted(risks, key=lambda x: x["threat_id"]), start=1):
        tid = r["threat_id"]
        rv = r["risk_value"]
        option, rationale, anchor = _decide(rv)
        linked = sorted(set(goals_by_ts.get(tid, [])))

        trace = r.get("traceability", {})
        entry = {
            "treatment_id": f"RT-{i:03d}",
            "threat_id": tid,
            "risk_id": r["risk_id"],
            "damage_scenario_id": r["damage_scenario_id"],
            "risk_value": rv,
            "risk_level": r["risk_level"],
            "impact_rating": r["impact_rating"],
            "attack_feasibility_rating": r["attack_feasibility_rating"],
            # [RQ-08-12] impose de considérer les catégories d'impact et les
            # attack paths, pas seulement la valeur de risque.
            "impact_categories_considered": {
                k: trace.get("impact", {}).get(k, {}).get("code")
                for k in ("safety", "financial", "operational", "privacy")
            },
            "attack_paths_considered": {
                "tree_id": trace.get("feasibility", {}).get("tree_id"),
                "worst_path_id": trace.get("feasibility", {}).get("worst_path_id"),
                "path_count": len(trace.get("feasibility", {}).get("per_path_ratings", [])),
            },
            "treatment_option": option,
            "options_available_to_assessor": _OPTIONS,
            "rationale": rationale,
            "normative_anchor": anchor,
            "linked_cybersecurity_goals": linked,
            "claim_required": option == "accept",
            "requires_assessor_review": option != "accept" and not linked,
            "generator_version": GENERATOR_VERSION,
        }

        # [RQ-09-07] : la réduction exige un ou plusieurs goals.
        if option == "reduce" and not linked:
            entry["conformance_warning"] = (
                "Traitement = réduction mais aucun cybersecurity goal rattaché. "
                "[RQ-09-07] exige au moins un goal. Revue assesseur requise."
            )
        out.append(entry)
    return out


def build_claims(treatments: list[dict], risks: list[dict]) -> list[dict]:
    """[WP-09-05] — un claim par risque accepté.

    3.1.10 impose deux éléments : pourquoi le risque est acceptable, et sous
    quelles conditions il doit être réévalué.
    """
    by_tid = {r["threat_id"]: r for r in risks}
    out: list[dict] = []
    n = 0
    for t in treatments:
        if t["treatment_option"] != "accept":
            continue
        n += 1
        r = by_tid[t["threat_id"]]
        trace = r.get("traceability", {})
        threat = trace.get("threat", {})

        out.append({
            "claim_id": f"CC-{n:03d}",
            "treatment_id": t["treatment_id"],
            "threat_id": t["threat_id"],
            "risk_id": t["risk_id"],
            "damage_scenario_id": t["damage_scenario_id"],
            "risk_value": t["risk_value"],
            "risk_level": t["risk_level"],
            "target_asset": threat.get("target_asset_name", ""),
            "compromised_property": threat.get("compromised_property", ""),

            # 3.1.10 — pourquoi acceptable
            "acceptability_statement": (
                f"Le risque associé au threat scenario {t['threat_id']} "
                f"({threat.get('title', '')}) est évalué à la valeur {t['risk_value']} "
                f"({t['risk_level']}), issue d'un impact {t['impact_rating']} et d'une "
                f"attack feasibility {t['attack_feasibility_rating']}. Cette valeur est "
                f"au niveau ou en dessous du seuil d'acceptation "
                f"{ACCEPTANCE_MAX_RISK_VALUE} défini par l'organisation."
            ),

            # §4.2.6 — hypothèses à documenter
            "assumptions": [
                "Le modèle d'architecture (item definition) reflète la configuration "
                "déployée sur le véhicule.",
                "L'attack feasibility est dérivée de la position structurelle et des "
                "descripteurs CAPEC ; aucune vulnérabilité connue n'est prise en compte "
                "au moment de l'évaluation baseline.",
                "L'impact est invariant sous divulgation (ISO/SAE 21434 8.1 NOTE 3).",
            ],

            # 3.1.10 — conditions de réévaluation
            "re_evaluation_conditions": [
                "Une divulgation apparie ce composant lors du triage [RQ-07-02].",
                "L'attack feasibility franchit un seuil HEAVENS 2.0 Table 6 "
                "(0.30 / 0.60 / 0.80).",
                "La valeur de risque dépasse le seuil d'acceptation "
                f"{ACCEPTANCE_MAX_RISK_VALUE}.",
                "L'architecture de l'item est modifiée (ajout d'ECU, d'interface, "
                "ou changement de technologie).",
            ],

            # 9.4.2 NOTE 12
            "monitoring": {
                "subject_to_monitoring": True,
                "mechanism": "Surveillance NVD continue [RQ-07-01] ; triage [RQ-07-02]",
                "reference": "ISO/SAE 21434 9.4.2 NOTE 12",
            },

            "normative_basis": [
                "ISO/SAE 21434 [RQ-09-08]",
                "ISO/SAE 21434 3.1.10",
                "ISO/SAE 21434 8.9.2 NOTE 5",
                "HEAVENS 2.0 UPDATE G12, sec. 4.3",
            ],
            "generator_version": GENERATOR_VERSION,
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Génère [WP-08-08] et [WP-09-05]")
    ap.add_argument("--outputs", default=str(_DEFAULT_OUT))
    args = ap.parse_args()
    out = Path(args.outputs)

    for name in ("risk.json", "cybersecurity_goals.json"):
        if not (out / name).exists():
            sys.exit(f"{name} absent de {out}\nLancez d'abord : python3 corrected_run.py")

    risks = json.loads((out / "risk.json").read_text(encoding="utf-8"))
    raw = json.loads((out / "cybersecurity_goals.json").read_text(encoding="utf-8"))
    goals = raw if isinstance(raw, list) else raw.get("goals", [])

    treatments = build_treatments(risks, goals)
    claims = build_claims(treatments, risks)

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator_version": GENERATOR_VERSION,
        "acceptance_threshold_risk_value": ACCEPTANCE_MAX_RISK_VALUE,
        "policy_note": (
            "Le seuil d'acceptation est une politique organisationnelle "
            "([RQ-05-06]), ancrée sur ISO/SAE 21434 [PM-08-01] et HEAVENS 2.0 "
            "sec. 4.2.5. À déclarer dans la section Méthodologie."
        ),
    }

    (out / "risk_treatment.json").write_text(
        json.dumps({"work_product": "WP-08-08", **meta, "treatments": treatments},
                   indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "cybersecurity_claims.json").write_text(
        json.dumps({"work_product": "WP-09-05", **meta, "claims": claims},
                   indent=2, ensure_ascii=False), encoding="utf-8")

    opt = Counter(t["treatment_option"] for t in treatments)
    warn = [t for t in treatments if "conformance_warning" in t]
    no_goal = [t for t in treatments if t["requires_assessor_review"]]

    print(f"[risk_treatment v{GENERATOR_VERSION}]")
    print(f"  [WP-08-08] {len(treatments):>3} décisions -> risk_treatment.json")
    print(f"             options : {dict(opt)}")
    print(f"  [WP-09-05] {len(claims):>3} claims     -> cybersecurity_claims.json")
    print(f"  seuil d'acceptation : valeur de risque <= {ACCEPTANCE_MAX_RISK_VALUE}")
    if warn:
        print(f"\n  ATTENTION {len(warn)} traitement(s) 'reduce' sans cybersecurity goal.")
        print(f"  [RQ-09-07] en exige au moins un. Revue assesseur requise :")
        for t in warn[:5]:
            print(f"     {t['threat_id']}  risque {t['risk_value']} ({t['risk_level']})")
        if len(warn) > 5:
            print(f"     ... et {len(warn)-5} autres")
    elif no_goal:
        print(f"\n  {len(no_goal)} traitement(s) nécessitent une revue assesseur.")
    else:
        print(f"\n  Tous les traitements 'reduce' sont rattachés à au moins un goal "
              f"([RQ-09-07] satisfait).")
    return 0


if __name__ == "__main__":
    sys.exit(main())