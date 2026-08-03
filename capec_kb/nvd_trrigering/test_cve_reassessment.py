#!/usr/bin/env python3
"""
Test de réévaluation D-TARA sur un CVE.

Deux modes :

  HORS LIGNE (par défaut) — utilise une capture NVD vérifiée, aucun réseau requis
      python3 test_cve_reassessment.py
      python3 test_cve_reassessment.py --cve CVE-2024-45158

  EN LIGNE — interroge directement l'API NVD
      python3 test_cve_reassessment.py --live --cve CVE-2024-45158
      python3 test_cve_reassessment.py --live --cve CVE-2025-59438
      python3 test_cve_reassessment.py --live --cve CVE-2024-45158 --api-key VOTRE_CLE

Prérequis : la baseline doit avoir été générée (python3 corrected_run.py).
Le test refuse de tourner sur des artefacts produits par une version < 1.5.0.

Chaîne exécutée (ISO/SAE 21434) :
  enrichissement          -> cve_enrichment.enrich_cve
  pertinence  [RQ-07-03]  -> arch_matcher.match_cve_to_architecture
  chemins     [RC-07-01]  -> intersection avec les attack paths
  feasibility [RC-07-02]  -> cve_heavens_mapper_v2 + feasibility_updater
  risque                  -> matrice HEAVENS 2.0 Table 8
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent          # capec_kb/nvd_trrigering
_KB = _HERE.parent                               # capec_kb
_ROOT = _KB.parent                               # racine du projet
_OUT = _KB / "output" / "outputs"
_ARCH = _ROOT / "data" / "architecture.json"

sys.path.insert(0, str(_HERE))

from arch_matcher import match_cve_to_architecture, MATCH_THRESHOLD   # noqa: E402
from cve_heavens_mapper_v2 import map_cve_to_heavens_signal           # noqa: E402
from feasibility_updater import update_feasibility_record             # noqa: E402

# HEAVENS 2.0 Table 8 — (impact, feasibility) -> (valeur, niveau)
RISK_MATRIX = {
    ("Negligible", "Very Low"): (1, "Negligible"), ("Negligible", "Low"): (1, "Negligible"),
    ("Negligible", "Medium"): (2, "Low"),          ("Negligible", "High"): (2, "Low"),
    ("Moderate", "Very Low"): (1, "Negligible"),   ("Moderate", "Low"): (2, "Low"),
    ("Moderate", "Medium"): (3, "Medium"),         ("Moderate", "High"): (4, "High"),
    ("Major", "Very Low"): (2, "Low"),             ("Major", "Low"): (3, "Medium"),
    ("Major", "Medium"): (4, "High"),              ("Major", "High"): (5, "Critical"),
    ("Severe", "Very Low"): (3, "Medium"),         ("Severe", "Low"): (4, "High"),
    ("Severe", "Medium"): (5, "Critical"),         ("Severe", "High"): (5, "Critical"),
}

GREEN, RED, YELLOW, BOLD, OFF = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[0m"


def load_baseline() -> dict:
    """Charge les artefacts baseline et refuse ceux d'une version périmée."""
    needed = ["attack_feasibility.json", "attack_paths.json", "risk.json",
              "threat_scenarios.json"]
    missing = [n for n in needed if not (_OUT / n).exists()]
    if missing:
        sys.exit(
            f"{RED}Artefacts baseline absents : {missing}{OFF}\n"
            f"Lancez d'abord :  python3 corrected_run.py"
        )

    feas = json.loads((_OUT / "attack_feasibility.json").read_text(encoding="utf-8"))
    stale = [r for r in feas if len(r.get("covered_threat_ids", [])) > 1]
    if stale:
        sys.exit(
            f"{RED}{len(stale)} enregistrements de feasibility couvrent plusieurs "
            f"threat scenarios.{OFF}\n"
            f"Cet artefact vient d'attack_feasibility.py < v1.5.0 et ses notes ne "
            f"sont pas valides par threat scenario.\n"
            f"Régénérez :  python3 corrected_run.py"
        )

    return {
        "feas": {r["threat_id"]: r for r in feas},
        "paths": {p["path_id"]: p for p in
                  json.loads((_OUT / "attack_paths.json").read_text(encoding="utf-8"))},
        "risk": {r["threat_id"]: r for r in
                 json.loads((_OUT / "risk.json").read_text(encoding="utf-8"))},
        "threats": json.loads((_OUT / "threat_scenarios.json").read_text(encoding="utf-8")),
    }


def get_cve(cve_id: str, live: bool, api_key: str | None) -> dict:
    if live:
        from cve_enrichment import enrich_cve
        print(f"  interrogation de NVD pour {cve_id} ...")
        rec = enrich_cve(cve_id, api_key)
        if not rec.get("found"):
            sys.exit(f"{RED}{cve_id} introuvable dans NVD{OFF}")
        if not rec.get("cvss", {}).get("vectorString"):
            sys.exit(
                f"{YELLOW}{cve_id} est publié sans vecteur CVSS v3.x.{OFF}\n"
                f"Conformément à la politique de report, il n'est pas évalué : "
                f"l'évaluer reviendrait à inventer un profil de métriques.\n"
                f"Ré-interrogez plus tard (NVD complète souvent le score après "
                f"quelques jours)."
            )
        return rec

    from cve_fixtures_real import ALL_FIXTURES
    if cve_id not in ALL_FIXTURES:
        sys.exit(
            f"{RED}Pas de capture hors ligne pour {cve_id}.{OFF}\n"
            f"Disponibles : {', '.join(sorted(ALL_FIXTURES))}\n"
            f"Utilisez --live pour interroger NVD."
        )
    return ALL_FIXTURES[cve_id]


def main() -> int:
    ap = argparse.ArgumentParser(description="Test de réévaluation D-TARA sur un CVE")
    ap.add_argument("--cve", default="CVE-2024-45158")
    ap.add_argument("--live", action="store_true", help="interroger NVD au lieu de la capture")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--save", action="store_true", help="écrire le rapport JSON dans results/")
    args = ap.parse_args()

    print(f"\n{BOLD}{'='*78}{OFF}")
    print(f"{BOLD}  TEST DE RÉÉVALUATION D-TARA — {args.cve}{OFF}")
    print(f"{BOLD}{'='*78}{OFF}\n")

    base = load_baseline()
    print(f"  baseline : {len(base['feas'])} threat scenarios, "
          f"{len(base['paths'])} attack paths\n")

    # ---- étape 1 : enrichissement -----------------------------------------
    print(f"{BOLD}[1/4] Enrichissement CVE{OFF}")
    cve = get_cve(args.cve, args.live, args.api_key)
    c = cve["cvss"]
    print(f"  source        : {'NVD (live)' if args.live else cve.get('source','capture')}")
    print(f"  vecteur       : {c['vectorString']}")
    print(f"  score         : {c['baseScore']} {c['baseSeverity']}")
    print(f"  CWE           : {', '.join(cve.get('cwes', [])) or '-'}")
    print(f"  vendeur       : {', '.join(cve.get('vendors', [])) or '-'}")
    print(f"  produit       : {', '.join(cve.get('products', [])) or '-'}\n")

    # ---- étape 2 : pertinence architecture [RQ-07-03] ----------------------
    print(f"{BOLD}[2/4] Pertinence vis-à-vis de l'architecture  [RQ-07-03]{OFF}")
    m = match_cve_to_architecture(cve, _ARCH, MATCH_THRESHOLD)
    if not m.get("impacted"):
        print(f"  {GREEN}NON PERTINENT{OFF} — aucune correspondance avec l'architecture")
        print(f"  ISO/SAE 21434 7.4.2 NOTE 1 : l'item n'étant pas affecté, "
              f"l'organisation peut cesser les activités.")
        print(f"\n  {BOLD}VERDICT : NO ACTION{OFF}\n")
        return 0
    ecus = m["impactedComponents"]
    print(f"  {YELLOW}PERTINENT{OFF}")
    print(f"  ECU impactés  : {', '.join(ecus)}")
    print(f"  technologies  : {', '.join(m['matchedTechnologies'])}")
    print(f"  scores        : {m['componentScores']}\n")

    # ---- étape 3 : signal HEAVENS [RC-07-02] -------------------------------
    print(f"{BOLD}[3/4] Signal CVSS -> HEAVENS  [RC-07-02]{OFF}")
    sig = map_cve_to_heavens_signal(cve)
    print(f"  AV:{sig.cvss_av} -> moyen d'accès {sig.access_means} (Table 2)")
    print(f"  PR:{sig.cvss_pr}/UI:{sig.cvss_ui} -> exposition {sig.exposure_time} (Table 3)")
    print(f"  Table 4       -> {BOLD}WoO = {sig.woo_value}{OFF}")
    print(f"  non révisés   : SE, KoIC, Eq (aucune métrique CVSS ne les mesure)\n")

    # ---- étape 4 : réévaluation du risque ----------------------------------
    print(f"{BOLD}[4/4] Réévaluation du risque  [RC-07-01] + HEAVENS Table 8{OFF}")
    impacted = [t["threat_id"] for t in base["threats"]
                if set(t.get("mapped_ecus") or []) & set(ecus)]

    print(f"\n  {'Threat':<8}{'Impact':<10}{'Feasibility':<22}{'A_norm':<20}"
          f"{'Risque':<24}{'Δ'}")
    print(f"  {'-'*82}")

    rows, esc, chg = [], 0, 0
    for tid in sorted(impacted):
        rec, rk = base["feas"].get(tid), base["risk"].get(tid)
        if not rec or not rk:
            continue
        u = update_feasibility_record(rec, sig, base["paths"], ecus[0],
                                      m["matchedTechnologies"])
        ir = rk["impact_rating"]
        bv, bl = RISK_MATRIX[(ir, u.feasibility_rating_baseline)]
        av, al = RISK_MATRIX[(ir, u.feasibility_rating_updated)]
        chg += int(u.feasibility_changed)
        esc += int(av > bv)
        mark = f"{RED} <<<{OFF}" if av > bv else ""
        print(f"  {tid:<8}{ir:<10}"
              f"{u.feasibility_rating_baseline + ' -> ' + u.feasibility_rating_updated:<22}"
              f"{f'{u.a_norm_max_baseline:.4f} -> {u.a_norm_max_updated:.4f}':<20}"
              f"{bl + ' -> ' + al:<24}{av - bv:+d}{mark}")
        rows.append({
            "threat_id": tid, "impact_rating": ir,
            "feasibility_before": u.feasibility_rating_baseline,
            "feasibility_after": u.feasibility_rating_updated,
            "a_norm_before": u.a_norm_max_baseline,
            "a_norm_after": u.a_norm_max_updated,
            "risk_before": bl, "risk_after": al, "risk_delta": av - bv,
        })

    print(f"\n{BOLD}  RÉSULTAT{OFF}")
    print(f"    menaces impactées      : {len(rows)}")
    print(f"    feasibility modifiée   : {chg}")
    print(f"    escalades de risque    : {esc}")
    action = "REVIEW REQUIRED" if esc else "NO ESCALATION"
    col = RED if esc else GREEN
    print(f"    action assesseur       : {col}{action}{OFF}\n")

    if not esc and rows:
        deltas = {round(r["a_norm_after"] - r["a_norm_before"], 4) for r in rows}
        if deltas != {0.0}:
            print(f"  {YELLOW}Note :{OFF} A_norm a augmenté sur toutes les menaces "
                  f"(delta {sorted(deltas)}), mais aucune n'a franchi de seuil")
            print(f"  HEAVENS Table 6 (0.30 / 0.60 / 0.80). C'est le comportement "
                  f"attendu : une révision\n  mesurable qui ne change pas le rating.\n")

    if args.save:
        out = _HERE / "results" / f"{args.cve.replace('-', '_')}_test_report.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "cve": {k: cve[k] for k in ("cveId", "cvss", "cwes", "vendors", "products")},
            "match": m,
            "signal": {"woo": sig.woo_value, "access_means": sig.access_means,
                       "exposure_time": sig.exposure_time, "rationale": sig.rationale},
            "reassessment": rows,
            "summary": {"threats": len(rows), "feasibility_changed": chg,
                        "risk_escalated": esc, "assessor_action": action},
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  rapport écrit : {out}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())