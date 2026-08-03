#!/usr/bin/env python3
"""
D-TARA Continuous Monitoring Daemon
===================================

Chaîne complète et automatisée :

    NVD  ->  triage  ->  pertinence architecture  ->  reassessment  ->  rapport

Ancrage normatif (ISO/SAE 21434) :

  [RQ-07-01]  surveiller des sources internes et externes           -> poll_nvd()
  [RQ-07-02]  triage sur des déclencheurs définis -> cybersecurity   -> triage()
              event
  [RQ-07-03]  analyser si l'événement affecte l'item, via 7.5        -> assess_relevance()
  [RC-07-01]  rattacher la vulnérabilité aux attack paths (8.6)      -> reassess()
  [RC-07-02]  déterminer la feasibility pour la vulnérabilité        -> reassess()
  [WP-07-02]  résultats du triage                                    -> triage_log.jsonl
  [WP-07-03]  cybersecurity event assessment                         -> results/*.json
  [WP-07-04]  vulnerability analysis                                 -> results/*.json
  7.4.2 NOTE 1  si l'item n'est pas affecté, l'organisation peut     -> verdict NOT_RELEVANT
              cesser les activités

Corrections opérationnelles par rapport à nvd_trigger.py :
  * pagination NVD (startIndex) — l'ancien code perdait tout au-delà de 100 CVE
  * garde sur cve_id vide — a produit CVE_2026__dtara_report.json
  * empreinte sur lastModified — un CVE re-scoré est retraité
  * file d'attente pour les CVE publiés sans vecteur CVSS (majorité des cas)
  * mode ciblé par fournisseur, pas seulement par fenêtre de publication

Usage
-----
    python3 dtara_daemon.py --once                  un cycle, puis sortie
    python3 dtara_daemon.py --daemon                boucle continue
    python3 dtara_daemon.py --cve CVE-2025-2082     un CVE précis
    python3 dtara_daemon.py --corpus                balayage ciblé automobile
    python3 dtara_daemon.py --backfill 2024-01-01   rattrapage historique
"""

from __future__ import annotations

import argparse
import json
import re
import logging
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_NVD_DIR = _ROOT / "capec_kb" / "nvd_trrigering"
_RISK_DIR = _ROOT / "capec_kb" / "risk"
_OUT_DIR = _ROOT / "capec_kb" / "output" / "outputs"
_DATA_DIR = _ROOT / "data"

for _d in (_NVD_DIR, _RISK_DIR):
    sys.path.insert(0, str(_d))

from cve_enrichment import enrich_cve                      # noqa: E402
from arch_matcher import match_cve_to_architecture         # noqa: E402
from cve_heavens_mapper_v2 import map_cve_to_heavens_signal  # noqa: E402
from feasibility_updater import update_feasibility_record  # noqa: E402

# ---------------------------------------------------------------- configuration

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY: str | None = None          # une clé NVD relève la limite à 50 req / 30 s
PAGE_SIZE = 2000                    # maximum autorisé par l'API
POLL_INTERVAL_S = 900
LOOKBACK_MIN = 60
MATCH_THRESHOLD = 0.6

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

STATE_PATH = _NVD_DIR / "daemon_state.json"
PENDING_PATH = _NVD_DIR / "pending_unscored.json"
TRIAGE_LOG = _NVD_DIR / "triage_log.jsonl"        # [WP-07-02]
RESULTS_DIR = _NVD_DIR / "results"                # [WP-07-03] / [WP-07-04]

# Fournisseurs et composants réellement présents dans architecture.json.
# Le balayage par fenêtre de publication ne rencontre presque jamais
# d'automobile ; le balayage ciblé, si.
TARGET_VENDORS = [
    "tesla", "bosch", "continental", "denso", "aptiv", "harman",
    "blackberry", "nvidia", "renesas", "nxp", "infineon", "st",
]
TARGET_PRODUCTS = [
    "mbedtls", "mbed_tls", "freertos", "linux_kernel", "nanopb",
    "qnx", "autosar", "can", "uds",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dtara")


# ---------------------------------------------------------------- état persistant

@dataclass
class Verdict:
    cve_id: str
    stage: str                    # TRIAGED | NOT_RELEVANT | REASSESSED | DEFERRED | ERROR
    relevant: bool = False
    matched_technologies: list = field(default_factory=list)
    impacted_ecus: list = field(default_factory=list)
    threats_total: int = 0
    feasibility_changed: int = 0
    risk_escalated: int = 0
    max_risk_delta: int = 0
    assessor_action: str = "NONE"
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _load(path: Path, default):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("état illisible (%s), réinitialisation", path.name)
    return default


def _save(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _append_triage(v: Verdict) -> None:
    """[WP-07-02] — journal d'audit append-only du triage."""
    TRIAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with TRIAGE_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(v), ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- [RQ-07-01] NVD

def _nvd_get(params: dict) -> dict:
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if API_KEY:
        req.add_header("apiKey", API_KEY)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (403, 503) and attempt < 3:
                wait = 6 * (attempt + 1)
                log.warning("NVD %s — nouvelle tentative dans %ds", e.code, wait)
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError:
            if attempt < 3:
                time.sleep(6 * (attempt + 1))
                continue
            raise
    return {}


def _paginate(base: dict) -> list[dict]:
    """Pagination complète. L'ancien code demandait 100 résultats sans startIndex
    et perdait silencieusement tout le reste."""
    out, start = [], 0
    while True:
        page = _nvd_get({**base, "resultsPerPage": PAGE_SIZE, "startIndex": start})
        vulns = page.get("vulnerabilities", [])
        out.extend(vulns)
        total = page.get("totalResults", 0)
        start += len(vulns)
        if start >= total or not vulns:
            break
        time.sleep(0.8 if API_KEY else 6.5)   # respect de la limite de débit
    return out


def poll_recent(lookback_minutes: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    return _paginate({
        "lastModStartDate": (now - timedelta(minutes=lookback_minutes)).strftime(fmt),
        "lastModEndDate": now.strftime(fmt),
    })


def poll_targeted() -> list[dict]:
    """Balayage par fournisseur et par composant. C'est ce mode qui permet de
    démontrer un vrai positif : une fenêtre de publication générique ne contient
    pratiquement jamais de CVE automobile."""
    seen, out = set(), []
    for kw in TARGET_VENDORS + TARGET_PRODUCTS:
        log.info("  balayage ciblé : %s", kw)
        try:
            for v in _paginate({"keywordSearch": kw}):
                cid = v.get("cve", {}).get("id", "")
                if cid and cid not in seen:
                    seen.add(cid)
                    out.append(v)
        except Exception as e:                      # noqa: BLE001
            log.warning("  échec du balayage %s : %s", kw, e)
        time.sleep(0.8 if API_KEY else 6.5)
    return out


# ---------------------------------------------------------------- [RQ-07-02] triage

def triage(vuln: dict, state: dict) -> tuple[str, str] | None:
    """Renvoie (cve_id, last_modified) si le CVE doit être analysé, sinon None."""
    meta = vuln.get("cve", {})
    cve_id = (meta.get("id") or "").strip()

    # Garde d'entrée. Un identifiant tronqué ("CVE-2026-") a traversé toute la
    # chaîne et produit un rapport d'escalade à 9 menaces
    # (CVE_2026__dtara_report.json). Le format CVE impose 4 chiffres d'année
    # puis au moins 4 chiffres de séquence.
    if not _CVE_RE.fullmatch(cve_id.upper()):
        log.debug("identifiant CVE rejeté : %r", cve_id)
        return None

    last_mod = meta.get("lastModified", "")
    # Empreinte sur lastModified : un CVE re-scoré après publication doit être
    # retraité. L'ancienne empreinte (id + published) l'interdisait.
    if state.get(cve_id) == last_mod:
        return None
    return cve_id, last_mod


# ---------------------------------------------- [RQ-07-03] pertinence architecture

def assess_relevance(enriched: dict) -> dict:
    return match_cve_to_architecture(
        enriched, _DATA_DIR / "architecture.json", MATCH_THRESHOLD
    )


# ------------------------------------------- [RC-07-01] / [RC-07-02] reassessment

_RISK_MATRIX = {   # HEAVENS 2.0 Table 8
    ("Negligible", "Very Low"): (1, "Negligible"), ("Negligible", "Low"): (1, "Negligible"),
    ("Negligible", "Medium"): (2, "Low"), ("Negligible", "High"): (2, "Low"),
    ("Moderate", "Very Low"): (1, "Negligible"), ("Moderate", "Low"): (2, "Low"),
    ("Moderate", "Medium"): (3, "Medium"), ("Moderate", "High"): (4, "High"),
    ("Major", "Very Low"): (2, "Low"), ("Major", "Low"): (3, "Medium"),
    ("Major", "Medium"): (4, "High"), ("Major", "High"): (5, "Critical"),
    ("Severe", "Very Low"): (3, "Medium"), ("Severe", "Low"): (4, "High"),
    ("Severe", "Medium"): (5, "Critical"), ("Severe", "High"): (5, "Critical"),
}


def _load_baseline() -> dict:
    need = ["attack_feasibility.json", "attack_paths.json", "risk.json",
            "threat_scenarios.json", "assets.json"]
    missing = [n for n in need if not (_OUT_DIR / n).exists()]
    if missing:
        raise FileNotFoundError(
            f"Artefacts baseline absents : {missing}. Lancez d'abord "
            f"`python3 corrected_run.py`."
        )
    feas = json.loads((_OUT_DIR / "attack_feasibility.json").read_text())

    # Refus des artefacts pré-v1.5.0 : leurs notes de feasibility ne sont pas
    # valides par threat scenario (contamination inter-menaces).
    stale = [r for r in feas if len(r.get("covered_threat_ids", [])) > 1]
    if stale:
        raise ValueError(
            f"{len(stale)} enregistrements de feasibility couvrent plusieurs threat "
            f"scenarios : artefact produit par attack_feasibility.py < v1.5.0. "
            f"Régénérez avec `python3 corrected_run.py`."
        )
    return {
        "feas": {r["threat_id"]: r for r in feas},
        "paths": {p["path_id"]: p for p in
                  json.loads((_OUT_DIR / "attack_paths.json").read_text())},
        "risk": {r["threat_id"]: r for r in
                 json.loads((_OUT_DIR / "risk.json").read_text())},
        "threats": json.loads((_OUT_DIR / "threat_scenarios.json").read_text()),
    }


def reassess(enriched: dict, match: dict, base: dict) -> dict:
    signal = map_cve_to_heavens_signal(enriched)     # lève si pas de vecteur CVSS
    ecus = set(match["impactedComponents"])
    techs = match.get("matchedTechnologies", [])

    impacted = [t["threat_id"] for t in base["threats"]
                if set(t.get("mapped_ecus") or []) & ecus]

    deltas, escalated, changed = [], 0, 0
    for tid in impacted:
        rec = base["feas"].get(tid)
        risk = base["risk"].get(tid)
        if not rec or not risk:
            continue
        ecu = next((e for e in ecus), "")
        upd = update_feasibility_record(rec, signal, base["paths"], ecu, techs)

        imp = risk["impact_rating"]
        bv, bl = _RISK_MATRIX[(imp, upd.feasibility_rating_baseline)]
        av, al = _RISK_MATRIX[(imp, upd.feasibility_rating_updated)]
        changed += int(upd.feasibility_changed)
        escalated += int(av > bv)

        deltas.append({
            "threat_id": tid,
            "impact_rating": imp,
            "feasibility_before": upd.feasibility_rating_baseline,
            "feasibility_after": upd.feasibility_rating_updated,
            "a_norm_before": upd.a_norm_max_baseline,
            "a_norm_after": upd.a_norm_max_updated,
            "risk_before": bl, "risk_after": al,
            "risk_delta": av - bv,
            "paths_changed": sum(1 for p in upd.updated_path_ratings if p.changed),
            "paths_total": len(upd.updated_path_ratings),
        })

    return {
        "cve": {
            "id": enriched["cveId"],
            "cvss_vector": enriched.get("cvss", {}).get("vectorString"),
            "cvss_score": enriched.get("cvss", {}).get("baseScore"),
            "published": enriched.get("published"),
            "cwes": enriched.get("cwes", []),
            "vendors": enriched.get("vendors", []),
            "products": enriched.get("products", []),
        },
        "signal": {
            "revised_parameters": list(signal.revisable_parameters),
            "woo_value": signal.woo_value,
            "access_means": signal.access_means,
            "exposure_time": signal.exposure_time,
            "rationale": signal.rationale,
        },
        "traceability": {
            "matched_technologies": techs,
            "impacted_ecus": sorted(ecus),
            "impacted_threats": impacted,
        },
        "reassessment": deltas,
        "summary": {
            "threats_total": len(deltas),
            "feasibility_changed": changed,
            "risk_escalated": escalated,
            "max_risk_delta": max((d["risk_delta"] for d in deltas), default=0),
            "assessor_action": "REVIEW REQUIRED" if escalated else "NO ESCALATION",
        },
        "standards_basis": {
            "trigger": "ISO/SAE 21434 [RQ-07-01], [RQ-07-02]",
            "event_assessment": "[RQ-07-03]",
            "path_mapping": "[RC-07-01]",
            "feasibility": "[RC-07-02], HEAVENS 2.0 Tables 2/3/4/6",
            "risk": "HEAVENS 2.0 Table 8",
            "impact_invariance": "ISO/SAE 21434 8.1 NOTE 3",
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------- pipeline unitaire

def process_cve(cve_id: str, base: dict, pending: dict) -> Verdict:
    try:
        enriched = enrich_cve(cve_id, API_KEY)
    except Exception as e:                                    # noqa: BLE001
        return Verdict(cve_id, "ERROR", detail=f"enrichissement : {e}")

    if not enriched.get("found"):
        return Verdict(cve_id, "ERROR", detail="absent de NVD")

    # CVE publié sans métriques CVSS : mise en file, jamais d'évaluation avec
    # des valeurs par défaut inventées.
    if not enriched.get("assessable", True) or not enriched.get("cvss", {}).get("vectorString"):
        pending[cve_id] = {"queued": datetime.now(timezone.utc).isoformat(),
                           "reason": enriched.get("deferred_reason", "no_cvss_vector")}
        return Verdict(cve_id, "DEFERRED", detail="publié sans vecteur CVSS v3.x")

    pending.pop(cve_id, None)

    match = assess_relevance(enriched)
    if not match.get("impacted"):
        # ISO/SAE 21434 7.4.2 NOTE 1 — item non affecté, arrêt des activités.
        return Verdict(cve_id, "NOT_RELEVANT", detail="aucune correspondance architecture")

    report = reassess(enriched, match, base)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _save(RESULTS_DIR / f"{cve_id.replace('-', '_')}_dtara_report.json", report)

    s = report["summary"]
    return Verdict(
        cve_id, "REASSESSED", relevant=True,
        matched_technologies=report["traceability"]["matched_technologies"],
        impacted_ecus=report["traceability"]["impacted_ecus"],
        threats_total=s["threats_total"],
        feasibility_changed=s["feasibility_changed"],
        risk_escalated=s["risk_escalated"],
        max_risk_delta=s["max_risk_delta"],
        assessor_action=s["assessor_action"],
    )


# ---------------------------------------------------------------- cycle

def run_cycle(vulns: list[dict], base: dict) -> dict:
    state = _load(STATE_PATH, {})
    pending = _load(PENDING_PATH, {})
    tally = {"triaged": 0, "not_relevant": 0, "reassessed": 0,
             "deferred": 0, "escalated": 0, "errors": 0, "skipped": 0}

    for v in vulns:
        t = triage(v, state)
        if t is None:
            tally["skipped"] += 1
            continue
        cve_id, last_mod = t
        tally["triaged"] += 1

        verdict = process_cve(cve_id, base, pending)
        _append_triage(verdict)
        state[cve_id] = last_mod

        if verdict.stage == "NOT_RELEVANT":
            tally["not_relevant"] += 1
        elif verdict.stage == "DEFERRED":
            tally["deferred"] += 1
        elif verdict.stage == "ERROR":
            tally["errors"] += 1
            log.warning("  %s : %s", cve_id, verdict.detail)
        elif verdict.stage == "REASSESSED":
            tally["reassessed"] += 1
            if verdict.risk_escalated:
                tally["escalated"] += 1
                log.warning("  *** %s : %d escalade(s) sur %s — %s",
                            cve_id, verdict.risk_escalated,
                            ", ".join(verdict.impacted_ecus), verdict.assessor_action)
            else:
                log.info("  %s : pertinent, %d menaces, aucune escalade",
                         cve_id, verdict.threats_total)

    _save(STATE_PATH, state)
    _save(PENDING_PATH, pending)
    return tally


def _report(tally: dict) -> None:
    log.info("── cycle terminé ──────────────────────────────")
    log.info("  triés            : %d", tally["triaged"])
    log.info("  non pertinents   : %d   [7.4.2 NOTE 1]", tally["not_relevant"])
    log.info("  réévalués        : %d", tally["reassessed"])
    log.info("  escalades        : %d", tally["escalated"])
    log.info("  différés (no CVSS): %d", tally["deferred"])
    log.info("  erreurs          : %d", tally["errors"])
    log.info("  déjà connus      : %d", tally["skipped"])


# ---------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description="D-TARA — surveillance continue NVD")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true", help="un cycle sur la fenêtre récente")
    g.add_argument("--daemon", action="store_true", help="boucle continue")
    g.add_argument("--cve", metavar="CVE-ID", help="traiter un CVE précis")
    g.add_argument("--corpus", action="store_true", help="balayage ciblé automobile")
    g.add_argument("--backfill", metavar="YYYY-MM-DD", help="rattrapage depuis une date")
    ap.add_argument("--lookback", type=int, default=LOOKBACK_MIN)
    ap.add_argument("--interval", type=int, default=POLL_INTERVAL_S)
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()

    global API_KEY
    API_KEY = args.api_key

    try:
        base = _load_baseline()
    except (FileNotFoundError, ValueError) as e:
        log.error("%s", e)
        return 2
    log.info("baseline chargée : %d threat scenarios", len(base["feas"]))

    if args.cve:
        v = process_cve(args.cve, base, _load(PENDING_PATH, {}))
        _append_triage(v)
        print(json.dumps(asdict(v), indent=2, ensure_ascii=False))
        return 0

    if args.corpus:
        log.info("balayage ciblé : %d fournisseurs, %d composants",
                 len(TARGET_VENDORS), len(TARGET_PRODUCTS))
        try:
            _report(run_cycle(poll_targeted(), base))
        except Exception as e:                                # noqa: BLE001
            log.error("balayage impossible : %s", e)
            return 3
        return 0

    if args.backfill:
        start = datetime.strptime(args.backfill, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        minutes = int((datetime.now(timezone.utc) - start).total_seconds() // 60)
        log.info("rattrapage depuis %s (%d jours)", args.backfill, minutes // 1440)
        try:
            _report(run_cycle(poll_recent(minutes), base))
        except Exception as e:                                # noqa: BLE001
            log.error("rattrapage impossible : %s", e)
            return 3
        return 0

    if args.once:
        try:
            _report(run_cycle(poll_recent(args.lookback), base))
        except Exception as e:                                # noqa: BLE001
            log.error("cycle impossible : %s", e)
            return 3
        return 0

    log.info("démon démarré — intervalle %ds, fenêtre %dmin",
             args.interval, args.lookback)
    while True:
        try:
            _report(run_cycle(poll_recent(args.lookback), base))
        except KeyboardInterrupt:
            log.info("arrêt demandé")
            return 0
        except Exception as e:                                # noqa: BLE001
            log.error("cycle en échec : %s", e)
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())