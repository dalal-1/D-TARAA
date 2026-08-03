from __future__ import annotations

import json
import logging
import urllib.request
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_fetch_cve(cve_id: str, api_key: str | None = None) -> dict:
    params = {"cveId": cve_id}
    query = urllib.parse.urlencode(params)
    url = f"{NVD_CVE_API}?{query}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    if api_key:
        req.add_header("apiKey", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _extract_cvss(cve_meta: dict) -> dict:
    """Extract a CVSS v3.x base vector.

    CORRECTED. CVSS v2 is no longer accepted. A v2 vector carries no
    PrivilegesRequired or UserInteraction metric and uses AC:{L,M,H}; the
    previous implementation accepted it and the downstream mapper then silently
    substituted hardcoded defaults (PR=HIGH, UI=REQUIRED), fabricating a metric
    profile the record never had. ISO/SAE 21434 [RC-08-04] requires the exploit
    metrics AV, AC, PR and UI, which only v3.x provides.

    Returns {} when no usable v3.x vector exists. Callers must DEFER such a CVE
    (see enrich_cve), never assess it with default metric values.
    """
    metrics = cve_meta.get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version_key, [])
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            vector = data.get("vectorString")
            if not vector:
                continue
            return {
                "version": data.get("version"),
                "baseScore": data.get("baseScore"),
                "baseSeverity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vectorString": vector,
                "exploitabilityScore": entry.get("exploitabilityScore"),
                "impactScore": entry.get("impactScore"),
                "scoringSource": entry.get("source", "unknown"),
            }
    if metrics.get("cvssMetricV2"):
        logger.warning(
            "Only a CVSS v2 vector is available; v2 lacks PR and UI and cannot "
            "be mapped under [RC-08-04]. Treating as unscored."
        )
    return {}


def _extract_cwes(cve_meta: dict) -> list[str]:
    cwes = []
    for weakness in cve_meta.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)
    return list(set(cwes))


def _extract_cpes(cve_meta: dict) -> list[dict]:
    cpes = []
    for config in cve_meta.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    cpe_uri = match.get("criteria", "")
                    parts = cpe_uri.split(":")
                    vendor = parts[3] if len(parts) > 3 else ""
                    product = parts[4] if len(parts) > 4 else ""
                    version = parts[5] if len(parts) > 5 else ""
                    cpes.append({
                        "cpeUri": cpe_uri,
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    })
    return cpes


def _extract_description(cve_meta: dict) -> str:
    for desc in cve_meta.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def enrich_cve(cve_id: str, api_key: str | None = None) -> dict:
    raw = _nvd_fetch_cve(cve_id, api_key)
    vulnerabilities = raw.get("vulnerabilities", [])
    if not vulnerabilities:
        logger.warning("No data found for %s", cve_id)
        return {"cveId": cve_id, "found": False}

    cve_meta = vulnerabilities[0].get("cve", {})
    cpes = _extract_cpes(cve_meta)

    vendors = list({c["vendor"] for c in cpes if c["vendor"]})
    products = list({c["product"] for c in cpes if c["product"]})

    affected_versions = []
    for cpe in cpes:
        entry: dict[str, Any] = {"vendor": cpe["vendor"], "product": cpe["product"]}
        if cpe.get("version") and cpe["version"] != "*":
            entry["version"] = cpe["version"]
        if cpe.get("versionStartIncluding"):
            entry["versionStartIncluding"] = cpe["versionStartIncluding"]
        if cpe.get("versionEndExcluding"):
            entry["versionEndExcluding"] = cpe["versionEndExcluding"]
        if cpe.get("versionEndIncluding"):
            entry["versionEndIncluding"] = cpe["versionEndIncluding"]
        affected_versions.append(entry)

    cvss = _extract_cvss(cve_meta)

    # Deferral policy: NVD publishes many CVEs in "Awaiting Analysis" with no
    # CVSS metrics. Assessing them would mean inventing a metric profile, so we
    # mark them pending. The caller must re-poll on lastModified.
    if not cvss.get("vectorString"):
        logger.info("%s has no usable CVSS v3.x base vector - deferring", cve_id)
        return {
            "cveId": cve_id,
            "found": True,
            "assessable": False,
            "deferred_reason": "no_cvss_v3_base_vector",
            "published": cve_meta.get("published"),
            "lastModified": cve_meta.get("lastModified"),
            "description": _extract_description(cve_meta),
            "cvss": {},
            "cwes": _extract_cwes(cve_meta),
            "vendors": vendors,
            "products": products,
            "cpes": cpes,
        }

    return {
        "cveId": cve_id,
        "found": True,
        "assessable": True,
        "published": cve_meta.get("published"),
        "lastModified": cve_meta.get("lastModified"),
        "description": _extract_description(cve_meta),
        "cvss": cvss,
        "cwes": _extract_cwes(cve_meta),
        "vendors": vendors,
        "products": products,
        "affectedVersions": affected_versions,
        "cpes": cpes,
        "rawCpeCount": len(cpes),
    }