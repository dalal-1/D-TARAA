from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "capec_kb" / "nvd_trrigering"))

from nvd_trigger import poll_once, run_polling_loop
from cve_enrichment import enrich_cve
from arch_matcher import match_cve_to_architecture

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nvd_test")

ARCH_PATH = Path(__file__).parent / "data" / "architecture.json"
STATE_PATH = Path(__file__).parent / "nvd_seen_state.json"


def print_summary(enriched: dict, match_result: dict) -> None:
    print()
    
    print("NEW CVE DETECTED")
  
    print()

    print(f"CVE ID: {enriched.get('cveId', 'N/A')}")
    print()

    cvss = enriched.get("cvss", {})
    if cvss:
        print("CVSS:")
        print(f"  Score:    {cvss.get('baseScore', 'N/A')}")
        print(f"  Severity: {cvss.get('baseSeverity', 'N/A')}")
        print()

    products = enriched.get("products", [])
    if products:
        print("Products:")
        for p in products:
            print(f"  - {p}")
        print()

    cwes = enriched.get("cwes", [])
    if cwes:
        print("CWEs:")
        for c in cwes:
            print(f"  - {c}")
        print()

    impacted = match_result.get("impacted", False)
    print("Architecture Match:")
    print(f"  Impacted: {'TRUE' if impacted else 'FALSE'}")
    print()

    components = match_result.get("impactedComponents", [])
    if components:
        print("Impacted Components:")
        for comp in components:
            score = match_result.get("componentScores", {}).get(comp, 0.0)
            print(f"  - {comp}  (score: {score})")
        print()

    technologies = match_result.get("matchedTechnologies", [])
    if technologies:
        print("Matched Technologies:")
        for t in technologies:
            print(f"  - {t}")
        print()

   
    print()


def handle_event(event: dict) -> None:
    cve_id = event.get("cveId", "")
    logger.info("Callback received event for %s", cve_id)

    try:
        enriched = enrich_cve(cve_id)
    except Exception as exc:
        logger.error("Enrichment failed for %s: %s", cve_id, exc)
        return

    if not enriched.get("found"):
        logger.warning("CVE %s not found in NVD", cve_id)
        return

    try:
        match_result = match_cve_to_architecture(enriched, ARCH_PATH)
    except Exception as exc:
        logger.error("Architecture matching failed for %s: %s", cve_id, exc)
        return

    print_summary(enriched, match_result)


def run_manual(cve_id: str) -> None:
    logger.info("Manual mode: testing CVE %s", cve_id)

    try:
        enriched = enrich_cve(cve_id)
    except Exception as exc:
        logger.error("Enrichment failed: %s", exc)
        sys.exit(1)

    if not enriched.get("found"):
        logger.warning("CVE %s not found in NVD", cve_id)
        sys.exit(1)

    try:
        match_result = match_cve_to_architecture(enriched, ARCH_PATH)
    except Exception as exc:
        logger.error("Architecture matching failed: %s", exc)
        sys.exit(1)

    print_summary(enriched, match_result)


def run_poll_loop() -> None:
    logger.info("Polling mode: starting continuous loop")
    try:
        run_polling_loop(
            callback=handle_event,
            state_path=STATE_PATH,
        )
    except KeyboardInterrupt:
        logger.info("Polling loop stopped by user")


def run_single_poll() -> None:
    logger.info("Single poll mode: fetching recent CVEs once")
    try:
        count = poll_once(
            callback=handle_event,
            state_path=STATE_PATH,
        )
        logger.info("Single poll complete. New CVEs processed: %d", count)
    except Exception as exc:
        logger.error("Single poll failed: %s", exc)
        sys.exit(1)


def main() -> None:
    args = sys.argv[1:]

    if not ARCH_PATH.exists():
        logger.error("architecture.json not found at %s", ARCH_PATH)
        sys.exit(1)

    if len(args) == 1 and args[0].upper().startswith("CVE-"):
        run_manual(args[0].upper())
    elif len(args) == 1 and args[0] == "--poll":
        run_poll_loop()
    elif len(args) == 0:
        run_single_poll()
    else:
        print("Usage:")
        print("  python run_nvd_test.py CVE-2024-3094   # manual mode")
        print("  python run_nvd_test.py --poll          # continuous polling")
        print("  python run_nvd_test.py                 # single poll snapshot")
        sys.exit(1)


if __name__ == "__main__":
    main()
