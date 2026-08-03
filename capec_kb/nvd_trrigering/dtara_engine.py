from __future__ import annotations
import argparse
import json
import logging
import os
import subprocess
import sys
import time
import traceback
from dataclasses import asdict
from pathlib import Path
from dtara_orchestrator import run_dtara, DtaraResult
from risk_delta_engine import run_risk_delta, RiskDeltaResult
from cve_enrichment import enrich_cve
from nvd_trigger import (
    run_polling_loop,
    poll_once,
    DEFAULT_POLL_INTERVAL_SECONDS,
    DEFAULT_LOOKBACK_MINUTES,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("dtara_engine")
_SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUTS_DIR = Path(
    os.environ.get("DTARA_OUTPUTS_DIR", _SCRIPT_DIR.parent / "output" / "outputs")
)
ARCH_PATH = Path(
    os.environ.get(
        "DTARA_ARCH_PATH", _SCRIPT_DIR.parent.parent / "data" / "architecture.json"
    )
)
ASSETS_PATH = OUTPUTS_DIR / "assets.json"
THREATS_PATH = OUTPUTS_DIR / "threat_scenarios.json"
PATHS_PATH = OUTPUTS_DIR / "attack_paths.json"
TREES_PATH = OUTPUTS_DIR / "attack_trees.json"
FEASIBILITY_PATH = OUTPUTS_DIR / "attack_feasibility.json"
RISK_PATH = OUTPUTS_DIR / "risk.json"
DAMAGE_PATH = OUTPUTS_DIR / "damage_scenarios.json"
GOALS_PATH = OUTPUTS_DIR / "cybersecurity_goals.json"
IMPACT_RATINGS_PATH = OUTPUTS_DIR / "impact_ratings.json"
CAPEC_NODES_PATH = Path(
    os.environ.get("DTARA_CAPEC_NODES_PATH", OUTPUTS_DIR / "capec_nodes.json")
)
PARSED_THREATS_PATH = Path(
    os.environ.get(
        "DTARA_PARSED_THREATS_PATH", ARCH_PATH.parent / "parsed_threats.json"
    )
)
RESULTS_DIR = Path(os.environ.get("DTARA_RESULTS_DIR", _SCRIPT_DIR / "results"))
GENERATE_DTARA_SCRIPT = Path(
    os.environ.get("DTARA_GENERATE_BASELINE_SCRIPT", OUTPUTS_DIR / "generate-dtara.py")
)
GENERATE_REASSESSMENT_SCRIPT = Path(
    os.environ.get(
        "DTARA_GENERATE_REASSESSMENT_SCRIPT", _SCRIPT_DIR / "generate-reassessment.py"
    )
)
BASELINE_REPORT_PATH = Path(
    os.environ.get(
        "DTARA_BASELINE_REPORT_PATH", OUTPUTS_DIR / "DTARA_Baseline_Report.pdf"
    )
)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DTARA_NO_LLM = os.environ.get("DTARA_NO_LLM", "1" if not OPENAI_API_KEY else "0") == "1"
STATE_PATH = Path(
    os.environ.get("DTARA_STATE_PATH", _SCRIPT_DIR / ".nvd_poll_state.json")
)
NVD_API_KEY = os.environ.get("NVD_API_KEY") or None
SCORE_THRESHOLD = float(os.environ.get("DTARA_SCORE_THRESHOLD", "0.6"))


def _load(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(
            f"Required engine output not found: {path}\nRun the static TARA pipeline (corrected_run.py) first to generate this file, or set the relevant DTARA_*_PATH env var."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _save(data: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("[output] %s", path)


def _build_report_no_impact(trace: DtaraResult) -> dict:
    return {
        "cve": trace.cve_summary,
        "verdict": {
            "architecture_impacted": False,
            "reassessment_required": False,
            "matched_technologies": [],
            "impacted_ecus": [],
        },
        "summary": {
            "escalated_risks": [],
            "assessor_action": "NO ACTION — CVE does not concern monitored architecture",
        },
    }


def _build_report_error(cve_id: str, stage: str, error: str) -> dict:
    return {
        "cve": {"cve_id": cve_id},
        "verdict": {"architecture_impacted": None, "reassessment_required": None},
        "error": {"stage": stage, "message": error},
        "summary": {
            "escalated_risks": [],
            "assessor_action": "PIPELINE ERROR — REVIEW REQUIRED",
        },
    }


def _build_report_with_impact(trace: DtaraResult, delta: RiskDeltaResult) -> dict:
    signal = delta.signal
    threat_assessments = []
    for td in delta.threat_deltas:
        risk_entries = []
        for rr in td.risk_records:
            risk_entries.append(
                {
                    "risk_id": rr.risk_id,
                    "damage_scenario_id": rr.damage_scenario_id,
                    "impact_rating": rr.impact_rating,
                    "risk_before": {
                        "level": rr.risk_level_baseline,
                        "value": rr.risk_value_baseline,
                        "feasibility_rating": rr.feasibility_rating_baseline,
                    },
                    "risk_after": {
                        "level": rr.risk_level_updated,
                        "value": rr.risk_value_updated,
                        "feasibility_rating": rr.feasibility_rating_updated,
                    },
                    "risk_delta": rr.risk_delta,
                    "escalated": rr.risk_escalated,
                }
            )
        changed_paths = []
        for pr in td.updated_feasibility.updated_path_ratings:
            if not pr.changed:
                continue
            # v2.0.0 : seule la window of opportunity est révisable depuis CVSS.
            # SE, KoIC et Eq ne sont jamais modifiés (HEAVENS 2.0 Table 5 :
            # aucune métrique de base CVSS ne mesure l'expertise, la distribution
            # de l'information, ni l'équipement).
            factors_changed = {}
            pv = pr.provenance
            if pv.get("delta", 0) != 0:
                factors_changed["WoO"] = {
                    "before": pr.woo_baseline,
                    "after": pr.woo_updated,
                    "cve_signal": pv["woo_from_table4"],
                    "access_means": pv["access_means"],
                    "exposure_time": pv["exposure_time"],
                    "source": f"AV={pv['cvss_av']}, PR={pv['cvss_pr']}, UI={pv['cvss_ui']}",
                }
            if factors_changed:
                changed_paths.append(
                    {
                        "path_id": pr.path_id,
                        "relevance": pr.relevance,
                        "a_norm_before": pr.a_norm_baseline,
                        "a_norm_after": pr.a_norm_updated,
                        "rating_before": pr.rating_baseline,
                        "rating_after": pr.rating_updated,
                        "factors_changed": factors_changed,
                    }
                )
        threat_obj = {
            "threat_id": td.threat_id,
            "title": next(
                (
                    t["title"]
                    for t in trace.impacted_threats
                    if t["threat_id"] == td.threat_id
                ),
                "",
            ),
            "feasibility_before": td.feasibility_rating_baseline,
            "feasibility_after": td.feasibility_rating_updated,
            "feasibility_changed": td.feasibility_changed,
            "a_norm_max_before": round(td.a_norm_max_baseline, 4),
            "a_norm_max_after": round(td.a_norm_max_updated, 4),
            "paths_changed": td.paths_changed,
            "paths_total": td.paths_total,
            "risk_assessment": risk_entries,
        }
        if changed_paths:
            threat_obj["path_detail"] = changed_paths[:5]
        threat_assessments.append(threat_obj)
    escalated_risks = [
        rr for td in delta.threat_deltas for rr in td.risk_records if rr.risk_escalated
    ]
    return {
        "cve": trace.cve_summary,
        "verdict": {
            "architecture_impacted": True,
            "reassessment_required": True,
            "matched_technologies": trace.matched_technologies,
            "impacted_ecus": trace.impacted_ecus,
            "threats_total": delta.threats_total,
            "threats_feasibility_changed": delta.threats_feasibility_changed,
            "threats_risk_escalated": delta.threats_risk_escalated,
            "max_risk_delta": delta.max_risk_delta,
        },
        "cve_signal": {
            "cvss_vector": signal.cvss_vector,
            "cvss_score": signal.cvss_score,
            "revised_parameters": list(signal.revisable_parameters),
            "rationale": signal.rationale,
            "mapping": {
                "WoO": {
                    "value": signal.woo_value,
                    "access_means": signal.access_means,
                    "exposure_time": signal.exposure_time,
                    "source": (
                        f"AV={signal.cvss_av} -> moyen d'acces "
                        f"(HEAVENS 2.0 Table 2) ; PR={signal.cvss_pr}/"
                        f"UI={signal.cvss_ui} -> temps d'exposition (Table 3) ; "
                        f"Table 4 -> WoO"
                    ),
                },
            },
            "not_revised": {
                "SE": "aucune metrique de base CVSS ne mesure l'expertise",
                "KoIC": "aucune metrique ne mesure la distribution de l'information",
                "Eq": "aucune metrique ne mesure l'equipement requis",
            },
        },
        "traceability": {
            "impacted_assets": trace.impacted_assets,
            "impacted_threats": trace.impacted_threats,
            "impacted_attack_paths_count": len(trace.impacted_attack_paths),
            "impacted_attack_trees": trace.impacted_attack_trees,
        },
        "threat_reassessment": threat_assessments,
        "summary": {
            "escalated_risks": [
                {
                    "risk_id": rr.risk_id,
                    "threat_id": rr.threat_id,
                    "before": f"{rr.risk_level_baseline} ({rr.risk_value_baseline})",
                    "after": f"{rr.risk_level_updated} ({rr.risk_value_updated})",
                    "delta": rr.risk_delta,
                }
                for rr in escalated_risks
            ],
            "assessor_action": (
                "REVIEW REQUIRED"
                if escalated_risks
                else "NO ESCALATION — auto-archived"
            ),
        },
    }


def process_cve(cve_id: str) -> dict:
    logger.info("[d-TARA] Processing %s", cve_id)
    report_path = RESULTS_DIR / f"{cve_id.replace('-', '_')}_dtara_report.json"
    try:
        traceability = run_dtara(
            cve_id=cve_id,
            arch_path=ARCH_PATH,
            assets=_load(ASSETS_PATH),
            threats=_load(THREATS_PATH),
            attack_paths=_load(PATHS_PATH),
            attack_trees=_load(TREES_PATH),
            api_key=NVD_API_KEY,
            score_threshold=SCORE_THRESHOLD,
        )
    except ValueError as exc:
        logger.warning("[d-TARA] %s", exc)
        report = _build_report_error(cve_id, "enrichment", str(exc))
        _save(report, report_path)
        return report
    except Exception as exc:
        logger.error(
            "[d-TARA] Unexpected failure during enrichment/matching for %s: %s",
            cve_id,
            exc,
        )
        logger.debug(traceback.format_exc())
        report = _build_report_error(cve_id, "enrichment_or_matching", str(exc))
        _save(report, report_path)
        return report
    if not traceability.impacted:
        logger.info(
            "[d-TARA] %s does NOT impact the monitored architecture — done.", cve_id
        )
        report = _build_report_no_impact(traceability)
        _save(report, report_path)
        return report
    logger.info(
        "[d-TARA] %s IMPACTS architecture — ECUs=%s, technologies=%s",
        cve_id,
        traceability.impacted_ecus,
        traceability.matched_technologies,
    )
    logger.info(
        "[d-TARA] Impacted assets=%d threats=%d attack_paths=%d attack_trees=%d",
        len(traceability.impacted_assets),
        len(traceability.impacted_threats),
        len(traceability.impacted_attack_paths),
        len(traceability.impacted_attack_trees),
    )
    try:
        cve_enriched = enrich_cve(cve_id, NVD_API_KEY)
        if not cve_enriched.get("found"):
            raise ValueError(f"CVE {cve_id} enrichment lookup failed on second pass")
    except Exception as exc:
        logger.error("[d-TARA] CVE enrichment (pass 2) failed for %s: %s", cve_id, exc)
        report = _build_report_error(cve_id, "cve_enrichment_pass2", str(exc))
        _save(report, report_path)
        return report
    try:
        delta = run_risk_delta(
            dtara_result=traceability,
            cve_enriched=cve_enriched,
            feasibility_records=_load(FEASIBILITY_PATH),
            risk_records=_load(RISK_PATH),
            attack_paths=_load(PATHS_PATH),
        )
    except Exception as exc:
        logger.error("[d-TARA] Risk delta computation failed for %s: %s", cve_id, exc)
        logger.debug(traceback.format_exc())
        report = _build_report_error(cve_id, "risk_delta", str(exc))
        _save(report, report_path)
        return report
    report = _build_report_with_impact(traceability, delta)
    _save(report, report_path)
    action = report["summary"]["assessor_action"]
    if action == "REVIEW REQUIRED":
        logger.warning(
            "[d-TARA] %s -> %d risk(s) ESCALATED. Report flagged: %s",
            cve_id,
            len(report["summary"]["escalated_risks"]),
            action,
        )
    else:
        logger.info("[d-TARA] %s -> no risk escalation. Report: %s", cve_id, action)
    try:
        generate_reassessment_report(report_path)
    except Exception:
        logger.error("[d-TARA] PDF generation failed for %s", cve_id)
        logger.error(traceback.format_exc())
    return report


def _run_subprocess(cmd: list[str], label: str) -> bool:
    logger.info("[pdf] %s — running: %s", label, " ".join((str(c) for c in cmd)))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        logger.error("[pdf] %s — failed to launch: %s", label, exc)
        return False
    for line in (proc.stdout or "").splitlines():
        logger.info("[pdf] %s | %s", label, line)
    for line in (proc.stderr or "").splitlines():
        logger.warning("[pdf] %s | %s", label, line)
    if proc.returncode != 0:
        logger.error("[pdf] %s — exited with code %d", label, proc.returncode)
        return False
    logger.info("[pdf] %s — done", label)
    return True


def _derive_ds_ids() -> str:
    try:
        raw = _load(DAMAGE_PATH)
    except FileNotFoundError:
        return ""
    ds_ids = [d.get("damage_id", "") for d in raw if d.get("damage_id")]
    if not ds_ids:
        return ""
    import re as _re

    def _key(d: str) -> int:
        m = _re.search("\\d+", d)
        return int(m.group()) if m else 0

    return ",".join(sorted(set(ds_ids), key=_key))


def generate_baseline_report(
    output_path: Path | None = None, ds_ids: str | None = None
) -> bool:
    output_path = Path(output_path) if output_path else BASELINE_REPORT_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not GENERATE_DTARA_SCRIPT.exists():
        logger.error(
            "[baseline] generate-dtara.py not found at %s", GENERATE_DTARA_SCRIPT
        )
        return False
    if ds_ids is None:
        ds_ids = _derive_ds_ids()
    cmd = [
        sys.executable,
        str(GENERATE_DTARA_SCRIPT),
        "--assets",
        str(ASSETS_PATH),
        "--damage",
        str(DAMAGE_PATH),
        "--threats",
        str(THREATS_PATH),
        "--goals",
        str(GOALS_PATH),
        "--attack_paths",
        str(PATHS_PATH),
        "--attack_trees",
        str(TREES_PATH),
        "--architecture",
        str(ARCH_PATH),
        "--capec_nodes",
        str(CAPEC_NODES_PATH),
        "--parsed_threats",
        str(PARSED_THREATS_PATH),
        "--risk",
        str(RISK_PATH),
        "--feasibility",
        str(FEASIBILITY_PATH),
        "--impact_ratings",
        str(IMPACT_RATINGS_PATH),
        "--output",
        str(output_path),
    ]
    if ds_ids:
        cmd += ["--ds_ids", ds_ids]
    if DTARA_NO_LLM:
        cmd += ["--no_llm"]
    elif OPENAI_API_KEY:
        cmd += ["--openai_key", OPENAI_API_KEY]
    ok = _run_subprocess(cmd, "baseline")
    if ok:
        logger.info("[baseline] Report written: %s", output_path)
    return ok


def generate_reassessment_report(report_path: Path) -> bool:
    if not GENERATE_REASSESSMENT_SCRIPT.exists():
        logger.error(
            "[reassessment] generate-reassessment.py not found at %s",
            GENERATE_REASSESSMENT_SCRIPT,
        )
        return False
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("[reassessment] Cannot read %s: %s", report_path, exc)
        return False
    if not report.get("verdict", {}).get("architecture_impacted"):
        logger.info(
            "[reassessment] %s — no architecture impact, skipping PDF.",
            report_path.name,
        )
        return True
    cve_id = report.get("cve", {}).get("cve_id", "UNKNOWN")
    out_pdf = RESULTS_DIR / f"DTARA_CVE_Reassessment_{cve_id.replace('-', '_')}.pdf"
    cmd = [
        sys.executable,
        str(GENERATE_REASSESSMENT_SCRIPT),
        str(report_path),
        "--output",
        str(out_pdf),
    ]
    if DTARA_NO_LLM:
        cmd += ["--no_llm"]
    elif OPENAI_API_KEY:
        cmd += ["--openai_key", OPENAI_API_KEY]
    ok = _run_subprocess(cmd, f"reassessment[{cve_id}]")
    if ok:
        logger.info("[reassessment] Report written: %s", out_pdf)
    return ok


def _on_new_cve(event: dict) -> None:
    cve_id = event.get("cveId", "")
    if not cve_id:
        return
    try:
        process_cve(cve_id)
    except Exception:
        logger.error("[d-TARA] Unhandled exception while processing %s", cve_id)
        logger.error(traceback.format_exc())


def _replay(replay_path: Path) -> None:
    data = json.loads(replay_path.read_text(encoding="utf-8"))
    cve_ids: list[str] = []
    for item in data:
        if isinstance(item, str):
            cve_ids.append(item)
        elif isinstance(item, dict) and item.get("cveId"):
            cve_ids.append(item["cveId"])
    logger.info("[d-TARA] Replay mode — %d CVE(s) from %s", len(cve_ids), replay_path)
    for cve_id in cve_ids:
        process_cve(cve_id)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="D-TARA Orchestrator — autonomous baseline reporting and CVE-triggered dynamic threat/risk reassessment. Runs without human interaction."
    )
    ap.add_argument(
        "cve_id",
        nargs="?",
        default=None,
        help="Process a single CVE immediately and exit (e.g. CVE-2024-12345).",
    )
    ap.add_argument(
        "--baseline",
        action="store_true",
        help="Generate the full baseline D-TARA PDF report from the static TARA artifacts (no CVE required). Can be combined with --watch.",
    )
    ap.add_argument(
        "--ds_ids",
        default=None,
        help="Comma-separated damage-scenario IDs for --baseline (default: every DS found in damage_scenarios.json).",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"Output path for the --baseline PDF report (default: {BASELINE_REPORT_PATH}).",
    )
    ap.add_argument(
        "--watch",
        action="store_true",
        help="After --baseline (or on its own), start autonomous NVD polling for CVE-triggered reassessment.",
    )
    ap.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help=f"NVD polling interval in seconds (default: {DEFAULT_POLL_INTERVAL_SECONDS}).",
    )
    ap.add_argument(
        "--lookback",
        type=int,
        default=DEFAULT_LOOKBACK_MINUTES,
        help=f"NVD lookback window in minutes (default: {DEFAULT_LOOKBACK_MINUTES}).",
    )
    ap.add_argument(
        "--replay",
        type=Path,
        default=None,
        help="Path to a JSON file of CVE IDs to process offline (no NVD polling).",
    )
    args = ap.parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.baseline:
        generate_baseline_report(output_path=args.out, ds_ids=args.ds_ids)
        if not args.watch and (not args.replay) and (not args.cve_id):
            return
    if args.replay:
        _replay(args.replay)
        return
    if args.cve_id:
        process_cve(args.cve_id)
        return
    logger.info("[d-TARA] Starting autonomous CVE-triggered D-TARA engine")
    logger.info("[d-TARA]   Poll interval : %ds", args.interval)
    logger.info("[d-TARA]   Lookback      : %dmin", args.lookback)
    logger.info("[d-TARA]   Architecture  : %s", ARCH_PATH)
    logger.info("[d-TARA]   Outputs dir   : %s", OUTPUTS_DIR)
    logger.info("[d-TARA]   Results dir   : %s", RESULTS_DIR)
    run_polling_loop(
        callback=_on_new_cve,
        state_path=STATE_PATH,
        poll_interval=args.interval,
        lookback_minutes=args.lookback,
        api_key=NVD_API_KEY,
    )


if __name__ == "__main__":
    main()