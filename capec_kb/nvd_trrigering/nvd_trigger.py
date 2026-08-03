from __future__ import annotations

import json
import time
import hashlib
import logging
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_POLL_INTERVAL_SECONDS = 900
DEFAULT_LOOKBACK_MINUTES = 30


def _nvd_request(params: dict, api_key: str | None = None) -> dict:
    query = urllib.parse.urlencode(params)
    url = f"{NVD_API_BASE}?{query}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _cve_fingerprint(cve_id: str, published: str) -> str:
    raw = f"{cve_id}:{published}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _load_seen(state_path: Path) -> dict:
    if state_path.exists():
        return json.loads(state_path.read_text())
    return {}


def _save_seen(state_path: Path, seen: dict) -> None:
    state_path.write_text(json.dumps(seen, indent=2))


def _fetch_recent_cves(lookback_minutes: int, api_key: str | None) -> list[dict]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=lookback_minutes)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": now.strftime(fmt),
        "resultsPerPage": 100,
    }
    data = _nvd_request(params, api_key)
    return data.get("vulnerabilities", [])


def _emit_event(cve_id: str, callback: Callable[[dict], None]) -> None:
    event = {
        "event": "NEW_CVE",
        "cveId": cve_id,
        "detectedAt": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("Emitting event: %s", event)
    callback(event)


def poll_once(
    callback: Callable[[dict], None],
    state_path: Path,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    api_key: str | None = None,
) -> int:
    seen = _load_seen(state_path)
    try:
        vulnerabilities = _fetch_recent_cves(lookback_minutes, api_key)
    except Exception as exc:
        logger.error("NVD fetch failed: %s", exc)
        return 0

    new_count = 0
    for vuln in vulnerabilities:
        cve_meta = vuln.get("cve", {})
        cve_id = cve_meta.get("id", "")
        published = cve_meta.get("published", "")
        if not cve_id:
            continue
        fingerprint = _cve_fingerprint(cve_id, published)
        if fingerprint not in seen:
            seen[fingerprint] = {"cveId": cve_id, "seenAt": datetime.now(timezone.utc).isoformat()}
            _emit_event(cve_id, callback)
            new_count += 1

    _save_seen(state_path, seen)
    return new_count


def run_polling_loop(
    callback: Callable[[dict], None],
    state_path: Path,
    poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    api_key: str | None = None,
) -> None:
    logger.info("NVD trigger service started. Poll interval: %ds", poll_interval)
    while True:
        n = poll_once(callback, state_path, lookback_minutes, api_key)
        logger.info("Poll complete. New CVEs detected: %d", n)
        time.sleep(poll_interval)