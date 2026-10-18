from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


MATCH_THRESHOLD   = 0.6
P1_GATE_THRESHOLD = 0.0
MIN_KEY_LENGTH    = 4

P2_ALIAS_BOOST    = 0.20
P3_DESC_BOOST     = 0.15


_DISTRO_VENDOR_PRODUCTS: set[str] = {
    "debian", "debian_linux",
    "redhat", "red_hat", "enterprise_linux", "rhel",
    "centos", "centos_linux", "rocky", "rockylinux", "almalinux",
    "fedora", "fedoraproject",
    "suse", "opensuse", "sles", "leap",
    "ubuntu", "canonical", "ubuntu_linux",
    "archlinux", "gentoo", "alpine", "void",
    "synology", "diskstation_manager", "diskstation_manager_unified_controller",
    "skynas_firmware", "vs960hd_firmware",
    "qnap",
    "oracle", "micros_workstation_5a_firmware", "micros_workstation_6_firmware",
    "micros_compact_workstation_3_firmware", "micros_kitchen_display_system_firmware",
    "micros_es400_firmware",
    "netapp", "solidfire", "ontap_select_deploy_administration_utility",
    "ontap_tools", "hci_management_node", "oncommand_unified_manager_core_package",
    "active_iq_unified_manager", "cloud_backup",
    "beyondtrust", "privilege_management_for_mac",
    "privilege_management_for_unix/linux",
    "privilege_management_for_unix\\/linux",
    "privilege_management_for_unix_linux",
    "mcafee", "trellix", "web_gateway",
    "tekelec", "tekelec_platform_distribution",
    "communications_performance_intelligence_center",
}


_VENDOR_PRODUCT_ALIASES: dict[str, list[str]] = {
    "linux":               ["linux_kernel", "kernel", "linux"],
    "linux_kernel":        ["linux_kernel", "kernel"],
    "kernel":              ["linux_kernel"],
    "torvalds":            ["linux_kernel"],

    "openssl":             ["openssl", "tls", "ssl"],
    "wolfssl":             ["wolfssl", "tls"],
    "mbedtls":             ["mbedtls", "tls"],
    "botan":               ["botan", "tls"],

    "openssh":             ["openssh", "ssh"],
    "ssh":                 ["openssh", "ssh"],

    "autosar":             ["autosar", "classic_autosar", "adaptive_autosar"],
    "vector":              ["autosar", "candb"],
    "elektrobit":          ["autosar"],
    "etas":                ["autosar"],
    "qnx":                 ["qnx", "qnx_neutrino"],
    "blackberry":          ["qnx", "qnx_neutrino"],
    "integrity":           ["integrity_rtos"],
    "green_hills":         ["integrity_rtos"],
    "vxworks":             ["vxworks"],
    "windriver":           ["vxworks"],
    "freertos":            ["freertos"],

    "can_stack":           ["can_bus", "can"],
    "canoe":               ["can_bus"],
    "peak":                ["can_bus"],
    "kvaser":              ["can_bus"],

    "lwip":                ["lwip", "ethernet", "tcp_ip"],
    "cyclone_tcp":         ["cyclone_tcp", "ethernet"],
    "open1722":            ["ieee1722", "avb"],

    "uptane":              ["uptane", "ota"],
    "aktualizr":           ["uptane", "ota"],
    "swupdate":            ["swupdate", "ota"],

    "optiga":              ["hsm", "tpm"],
    "infineon":            ["hsm", "she"],
    "nxp":                 ["hsm", "cse"],

    "xen":                 ["xen_hypervisor", "hypervisor"],
    "kvm":                 ["kvm_hypervisor", "hypervisor"],
    "bhyve":               ["hypervisor"],

    "android":             ["android", "aosp"],
    "trustzone":           ["trustzone", "tee"],
    "optee":               ["optee", "tee"],
}

_ARCH_KEY_TO_VALID_CPE_TOKENS: dict[str, set[str]] = {}
for _cpe_tok, _arch_keys in _VENDOR_PRODUCT_ALIASES.items():
    for _ak in _arch_keys:
        _ARCH_KEY_TO_VALID_CPE_TOKENS.setdefault(_ak, set()).add(_cpe_tok)


# Threshold for localising a vehicle-scoped disclosure to a component by
# description evidence. Higher than MATCH_THRESHOLD because the evidence is
# weaker: it is applied only after the disclosure has been established as
# concerning this item.
DESC_LOCALISATION_THRESHOLD = 0.30

# Terms that appear in almost any automotive advisory and therefore carry no
# localising power. A description mentioning the CAN bus does not identify which
# component carries the flaw, so such tokens are excluded from the evidence used
# to localise a vehicle-scoped disclosure.
NON_LOCALISING_TOKENS = {
    "can", "bus", "vehicle", "vehicles", "module", "modules", "system",
    "systems", "network", "networked", "adjacent", "attacker", "attackers",
    "code", "memory", "data", "message", "messages", "arbitrary", "remote",
    "execute", "execution", "firmware", "software", "hardware", "interface",
    "controller", "ecu", "protocol", "authentication", "required", "affected",
    "specific", "flaw", "exists", "within", "sent", "response", "trigger",
}


def _tokenize(text: str) -> list[str]:
    text = text.lower()
    tokens = re.findall(r"[a-z0-9]+", text)
    return [t for t in tokens if len(t) >= 3]


def _token_set(text: str) -> set[str]:
    return set(_tokenize(text))


def _load_architecture(arch_path: str | Path) -> dict:
    return json.loads(Path(arch_path).read_text())


def _build_tech_index(arch: dict) -> dict[str, list[str]]:
    """Map each declared technology to the architectural elements carrying it.

    The index covers every technology-bearing element type, not only control
    units. The elements that determine how an attacker reaches a system are
    frequently external interfaces and communication buses, and a disclosure
    naming a bus or interface technology must be localisable to them.
    """
    index: dict[str, list[str]] = {}

    CATEGORIES = (
        "software_technologies",
        "hardware_technologies",
        "update_technologies",
        "communication_technologies",
    )

    def _add(raw_component: str, element_id: str) -> None:
        key = (raw_component or "").lower().strip()
        if not key:
            return
        index.setdefault(key, [])
        if element_id not in index[key]:
            index[key].append(element_id)

    def _index_element(element: dict, id_field: str = "id") -> None:
        element_id = element.get(id_field)
        if not element_id:
            return
        tc = element.get("technology_context", {}) or {}
        for category in CATEGORIES:
            for item in tc.get(category, []) or []:
                _add(item.get("component", ""), element_id)

    for collection in ("ecus", "external_interfaces", "communication_buses"):
        for element in arch.get(collection, []) or []:
            _index_element(element)

    for node in arch.get("supplemental_technology_nodes", []) or []:
        node_id = node.get("id", "SUPPLEMENTAL")
        for category in CATEGORIES:
            for item in node.get(category, []) or []:
                _add(item.get("component", ""), node_id)

    for group in arch.get("technology_groups", []) or []:
        group_id = group.get("logical_grouping_id", "GROUP")
        for item in group.get("technologies", []) or []:
            _add(item.get("component", ""), group_id)

    return {k: sorted(v) for k, v in sorted(index.items())}


def _item_identity_match(cve_enriched: dict, arch: dict) -> dict[str, Any] | None:
    """Decide whether the disclosure's CPE data names the item itself.

    Automotive advisories are frequently registered against the vehicle rather
    than against the component that carries the flaw: the CPE product string
    identifies a model and its firmware, not the module. Such a record cannot be
    localised by CPE token overlap against a component technology index, because
    the tokens describe a different level of the system. This function
    establishes only that the disclosure is in scope for the item; localisation
    to a component is performed separately from the description.
    """
    identity = (arch.get("item_definition") or {}).get("vehicle_identity")
    if not identity:
        return None

    vendor = str(identity.get("vendor", "")).lower()
    models = {str(m).lower() for m in identity.get("models", [])}
    if not vendor or not models:
        return None

    for entry in cve_enriched.get("cpes", []) or []:
        if str(entry.get("vendor", "")).lower() != vendor:
            continue
        # Compare normalised product strings rather than tokens, so that a model
        # discriminator such as "3" or "y" is not dropped by the tokeniser's
        # minimum length. Matching "model_y" against a "model_3" record would
        # place a disclosure on the wrong vehicle.
        product = str(entry.get("product", "")).lower()
        product_norm = re.sub(r"[^a-z0-9]+", "_", product).strip("_")
        for model in models:
            model_norm = re.sub(r"[^a-z0-9]+", "_", model.lower()).strip("_")
            if product_norm == model_norm or product_norm.startswith(model_norm + "_"):
                return {"vendor": vendor, "product": product,
                        "model": model, "cpeUri": entry.get("cpeUri")}
    return None


def _localise_by_description(
    desc_tokens: set[str],
    tech_index: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Localise an item-scoped disclosure to components by description evidence.

    Applied only once the disclosure has been established as concerning the
    item. Each technology key is scored by the share of its own tokens that the
    description mentions, so that a description naming a specific module
    localises to the elements carrying it without a generic term matching
    broadly.
    """
    results: list[dict[str, Any]] = []
    localising = desc_tokens - NON_LOCALISING_TOKENS
    if not localising:
        return results

    for tech_key, element_ids in tech_index.items():
        arch_tokens = _token_set(tech_key) - NON_LOCALISING_TOKENS
        if not arch_tokens:
            continue
        overlap = localising & arch_tokens
        if not overlap:
            continue
        coverage = len(overlap) / len(arch_tokens)
        if coverage < DESC_LOCALISATION_THRESHOLD:
            continue
        results.append({
            "technology":    tech_key,
            "components":    element_ids,
            "score":         round(coverage, 3),
            "matchedVia":    "item_scope_description",
            "matchedTokens": sorted(overlap),
        })
    return results


def _cpe_token_set(cve_enriched: dict) -> set[str]:
    tokens: set[str] = set()
    for cpe in cve_enriched.get("cpes", []):
        vendor_raw  = cpe.get("vendor", "").lower().strip()
        product_raw = cpe.get("product", "").lower().strip()
        if vendor_raw in _DISTRO_VENDOR_PRODUCTS:
            continue
        if product_raw not in _DISTRO_VENDOR_PRODUCTS:
            tokens.update(_tokenize(product_raw))
        tokens.update(_tokenize(vendor_raw))
    for v in cve_enriched.get("vendors", []):
        v_lower = v.lower().strip()
        if v_lower not in _DISTRO_VENDOR_PRODUCTS:
            tokens.update(_tokenize(v))
    for p in cve_enriched.get("products", []):
        p_lower = p.lower().strip()
        if p_lower not in _DISTRO_VENDOR_PRODUCTS:
            tokens.update(_tokenize(p))
    return tokens


def _desc_token_set(cve_enriched: dict) -> set[str]:
    desc = cve_enriched.get("description", "")
    return _token_set(desc)


def _p1_cpe_score(cpe_tokens: set[str], tech_key: str) -> float:
    if len(tech_key) < MIN_KEY_LENGTH:
        valid_cpe = _ARCH_KEY_TO_VALID_CPE_TOKENS.get(tech_key, set())
        if cpe_tokens & valid_cpe:
            return 0.8
        return 0.0

    arch_tokens = _token_set(tech_key)
    if not arch_tokens:
        return 0.0

    overlap = cpe_tokens & arch_tokens
    if not overlap:
        return 0.0

    direct_score = len(overlap) / len(arch_tokens)

    valid_cpe = _ARCH_KEY_TO_VALID_CPE_TOKENS.get(tech_key, set())
    alias_hit = bool(cpe_tokens & valid_cpe)

    if alias_hit and direct_score > 0:
        return min(1.0, direct_score + 0.2)
    if alias_hit:
        return 0.7

    return direct_score


def _p2_alias_boost(cpe_tokens: set[str], tech_key: str) -> float:
    valid_cpe = _ARCH_KEY_TO_VALID_CPE_TOKENS.get(tech_key, set())
    if cpe_tokens & valid_cpe:
        return P2_ALIAS_BOOST
    return 0.0


def _p3_desc_boost(
    desc_tokens: set[str],
    tech_key: str,
    p1_score: float,
) -> float:
    if p1_score <= P1_GATE_THRESHOLD:
        return 0.0

    arch_tokens = _token_set(tech_key)
    if not arch_tokens or not desc_tokens:
        return 0.0

    intersection = desc_tokens & arch_tokens
    if not intersection:
        return 0.0

    union = desc_tokens | arch_tokens
    jaccard = len(intersection) / len(union)

    return min(P3_DESC_BOOST, jaccard * P3_DESC_BOOST * 3)


def match_cve_to_architecture(
    cve_enriched: dict,
    arch_path: str | Path,
    score_threshold: float = MATCH_THRESHOLD,
) -> dict:
    arch       = _load_architecture(arch_path)
    tech_index = _build_tech_index(arch)

    cpe_tokens  = _cpe_token_set(cve_enriched)
    desc_tokens = _desc_token_set(cve_enriched)

    logger.debug(
        "[arch_matcher] CVE=%s  cpe_tokens=%s",
        cve_enriched.get("cveId"),
        sorted(cpe_tokens),
    )

    if not cpe_tokens:
        logger.warning(
            "[arch_matcher] CVE %s has no CPE data — no match possible",
            cve_enriched.get("cveId"),
        )
        return {
            "cveId":               cve_enriched.get("cveId"),
            "impacted":            False,
            "impactedComponents":  [],
            "componentScores":     {},
            "matchedTechnologies": [],
            "matchDetails":        [],
            "scoreThreshold":      score_threshold,
            "itemScoped":          False,
        }

    matches: list[dict[str, Any]] = []

    for tech_key, ecu_ids in tech_index.items():
        p1 = _p1_cpe_score(cpe_tokens, tech_key)
        if p1 <= P1_GATE_THRESHOLD:
            continue

        p2_boost = _p2_alias_boost(cpe_tokens, tech_key)

        p3_boost = _p3_desc_boost(desc_tokens, tech_key, p1)

        final_score = min(1.0, p1 + p2_boost + p3_boost)

        if final_score < score_threshold:
            logger.debug(
                "[arch_matcher] tech_key=%s  p1=%.3f  p2=%.3f  p3=%.3f  final=%.3f  BELOW_THRESHOLD",
                tech_key, p1, p2_boost, p3_boost, final_score,
            )
            continue

        matched_via = "cpe_exact" if p1 >= 0.9 else "cpe_token" if p1 >= 0.6 else "cpe_alias"

        logger.info(
            "[arch_matcher] MATCH tech_key=%-30s  p1=%.3f  p2=%.3f  p3=%.3f  final=%.3f  ecus=%s",
            tech_key, p1, p2_boost, p3_boost, final_score, ecu_ids,
        )

        matches.append({
            "techKey":    tech_key,
            "ecuIds":     ecu_ids,
            "score":      round(final_score, 4),
            "p1_score":   round(p1, 4),
            "p2_boost":   round(p2_boost, 4),
            "p3_boost":   round(p3_boost, 4),
            "matchedVia": matched_via,
        })

    # Second stage. Where CPE token overlap localised nothing, the disclosure may
    # still concern this item: automotive advisories are commonly registered
    # against a vehicle rather than against the component carrying the flaw. If
    # the CPE data names the item itself, localise to components from the
    # description instead, and record that the weaker evidence was used.
    item_scope = None
    if not matches:
        item_scope = _item_identity_match(cve_enriched, arch)
        if item_scope is not None:
            logger.info(
                "[arch_matcher] CVE %s is vehicle-scoped (%s); localising by description",
                cve_enriched.get("cveId"), item_scope.get("product"),
            )
            for hit in _localise_by_description(desc_tokens, tech_index):
                logger.info(
                    "[arch_matcher] MATCH tech_key=%-30s  coverage=%.3f  via=%s  ecus=%s",
                    hit["technology"], hit["score"], hit["matchedVia"], hit["components"],
                )
                matches.append({
                    "techKey":    hit["technology"],
                    "ecuIds":     hit["components"],
                    "score":      hit["score"],
                    "p1_score":   0.0,
                    "p2_boost":   0.0,
                    "p3_boost":   0.0,
                    "matchedVia": hit["matchedVia"],
                    "matchedTokens": hit["matchedTokens"],
                })

    impacted_ecus: dict[str, float] = {}
    for match in matches:
        for ecu_id in match["ecuIds"]:
            current = impacted_ecus.get(ecu_id, 0.0)
            if match["score"] > current:
                impacted_ecus[ecu_id] = match["score"]

    impacted = len(impacted_ecus) > 0

    return {
        "cveId":               cve_enriched.get("cveId"),
        "impacted":            impacted,
        "impactedComponents":  list(impacted_ecus.keys()),
        "componentScores":     impacted_ecus,
        "matchedTechnologies": [m["techKey"] for m in matches],
        "matchDetails":        matches,
        "scoreThreshold":      score_threshold,
        "itemScoped":          item_scope is not None,
        "itemScopeEvidence":   item_scope,
    }