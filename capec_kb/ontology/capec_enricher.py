from __future__ import annotations

import json
import sys
import re
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Optional

_NS = {"capec": "http://capec.mitre.org/capec-3"}

_RULES_PATH = Path(__file__).resolve().parent / "capec_projection_rules.json"

def _load_rules(rules_path: Path) -> dict:
    with open(rules_path) as f:
        return json.load(f)

def _text_lower(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    parts = []
    for text in element.itertext():
        if text:
            parts.append(text.strip())
    return " ".join(parts).lower()

def _score_se(attack_pattern: ET.Element, rules: dict) -> tuple[int, list[str]]:
    skills = attack_pattern.findall(".//capec:Skills_Required/capec:Skill", _NS)
    if not skills:
        return rules["fallback_defaults"]["SE"], []

    level_map: dict[str, int] = rules["skills_required_level_map"]
    min_se = 6
    sources: list[str] = []

    for skill in skills:
        level_attr = skill.get("Level", "Unknown")
        se = level_map.get(level_attr, level_map.get("Unknown", 3))
        if se < min_se:
            min_se = se
        sources.append(f"Skills_Required[Level={level_attr}]→SE={se}")

    return min_se, sources

def _score_eq(attack_pattern: ET.Element, rules: dict) -> tuple[int, list[str]]:
    resources_el = attack_pattern.find(".//capec:Resources_Required", _NS)
    text = _text_lower(resources_el)

    if not text:
        return rules["fallback_defaults"]["Eq"], []

    kw_map: dict[str, list[str]] = rules["resources_required_keywords"]
    score_key_order = ["Eq_6", "Eq_3", "Eq_1", "Eq_0"]

    for key in score_key_order:
        score_val = int(key.split("_")[1])
        for kw in kw_map.get(key, []):
            if kw.lower() in text:
                return score_val, [f"Resources_Required keyword '{kw}'→Eq={score_val}"]

    return rules["fallback_defaults"]["Eq"], ["Resources_Required: no keyword match, fallback"]

def _score_et(attack_pattern: ET.Element, rules: dict) -> tuple[int, list[str]]:
    phase_weights: dict[str, int] = rules["execution_flow_phase_weights"]
    thresholds: list[dict] = rules["elapsed_time_step_thresholds"]

    steps = attack_pattern.findall(".//capec:Execution_Flow/capec:Attack_Step", _NS)
    weighted_total = 0
    sources: list[str] = []

    for step_el in steps:
        phase_el = step_el.find("capec:Phase", _NS)
        phase = phase_el.text.strip() if phase_el is not None and phase_el.text else "Exploit"
        weight = phase_weights.get(phase, phase_weights.get("Exploit", 2))
        weighted_total += weight
        sources.append(f"Execution_Flow step phase={phase} weight={weight}")

    if not steps:
        likelihood_el = attack_pattern.find(".//capec:Typical_Likelihood_of_Exploit", _NS)
        if likelihood_el is not None and likelihood_el.text:
            likelihood = likelihood_el.text.strip()
            signal_map: dict[str, Optional[int]] = rules["likelihood_et_signal"]
            et_from_likelihood = signal_map.get(likelihood)
            if et_from_likelihood is not None:
                return et_from_likelihood, [f"Typical_Likelihood_of_Exploit={likelihood}→ET={et_from_likelihood}"]

        return rules["fallback_defaults"]["ET"], ["Execution_Flow: empty, fallback"]

    for threshold in thresholds:
        if weighted_total <= threshold["max_weighted_steps"]:
            et = threshold["ET"]
            sources.append(f"weighted_steps={weighted_total}→ET={et}")
            return et, sources

    last_et = thresholds[-1]["ET"]
    sources.append(f"weighted_steps={weighted_total}→ET={last_et} (ceiling)")
    return last_et, sources

def _score_koic(attack_pattern: ET.Element, rules: dict) -> tuple[int, list[str]]:
    prereqs = attack_pattern.findall(".//capec:Prerequisites/capec:Prerequisite", _NS)
    combined_text = " ".join(_text_lower(p) for p in prereqs)

    if not combined_text.strip():
        return rules["fallback_defaults"]["KoIC"], []

    kw_map: dict[str, list[str]] = rules["prerequisites_koic_keywords"]
    order = ["KoIC_6", "KoIC_3", "KoIC_1", "KoIC_0"]

    for key in order:
        score_val = int(key.split("_")[1])
        for kw in kw_map.get(key, []):
            if kw.lower() in combined_text:
                return score_val, [f"Prerequisites keyword '{kw}'→KoIC={score_val}"]

    return rules["fallback_defaults"]["KoIC"], ["Prerequisites: no keyword match, fallback"]

def _score_woo(attack_pattern: ET.Element, rules: dict) -> tuple[int, list[str]]:
    channel_map: dict[str, int] = rules["channel_woo_map"]

    channel_el = attack_pattern.find(".//capec:Channel", _NS)
    if channel_el is not None and channel_el.text:
        channel = channel_el.text.strip()
        woo = channel_map.get(channel, channel_map.get("Unknown", 2))
        return woo, [f"Channel={channel}→WoO={woo}"]

    related_weaknesses = attack_pattern.findall(".//capec:Related_Weaknesses/capec:Related_Weakness", _NS)
    cwe_ids = {
        rw.get("CWE_ID", "")
        for rw in related_weaknesses
        if rw.get("Nature", "") != "CanPrecede"
    }

    _CWE_REMOTE   = {"89", "79", "352", "601", "918", "611", "400", "20"}
    _CWE_ADJACENT = {"284", "285", "287", "306", "732"}
    _CWE_LOCAL    = {"269", "250", "276"}
    _CWE_PHYSICAL = {"1233", "1240", "1244", "1299"}

    if cwe_ids & _CWE_REMOTE:
        return 1, [f"CWE={cwe_ids & _CWE_REMOTE}→WoO=1 (remote-reachable surface)"]
    if cwe_ids & _CWE_ADJACENT:
        return 2, [f"CWE={cwe_ids & _CWE_ADJACENT}→WoO=2 (adjacent network)"]
    if cwe_ids & _CWE_LOCAL:
        return 3, [f"CWE={cwe_ids & _CWE_LOCAL}→WoO=3 (local access)"]
    if cwe_ids & _CWE_PHYSICAL:
        return 4, [f"CWE={cwe_ids & _CWE_PHYSICAL}→WoO=4 (physical access)"]

    name = (attack_pattern.get("Name") or "").lower()
    desc_el = attack_pattern.find(".//capec:Description", _NS)
    desc = _text_lower(desc_el)
    signal_text = name + " " + desc

    _PHYSICAL_SIGNALS = {"physical", "hardware", "jtag", "uart", "obd", "chip-off", "usb", "serial port"}
    _LOCAL_SIGNALS    = {"local", "process memory", "file system", "environment variable", "installed", "executable"}
    _REMOTE_SIGNALS   = {"remote", "network", "internet", "http", "web", "dns", "smtp", "api", "over the network"}

    if any(s in signal_text for s in _PHYSICAL_SIGNALS):
        return 4, ["text_signal→WoO=4 (physical keyword in name/description)"]
    if any(s in signal_text for s in _LOCAL_SIGNALS):
        return 3, ["text_signal→WoO=3 (local keyword in name/description)"]
    if any(s in signal_text for s in _REMOTE_SIGNALS):
        return 1, ["text_signal→WoO=1 (remote keyword in name/description)"]

    return rules["fallback_defaults"]["WoO"], ["WoO: no Channel, no CWE signal, no text signal, fallback"]

def _process_attack_pattern(
    attack_pattern: ET.Element,
    rules: dict,
    capec_version: str,
    generated_at: str,
) -> Optional[tuple[str, dict]]:
    capec_id = attack_pattern.get("ID")
    if not capec_id:
        return None

    status = attack_pattern.get("Status", "")
    if status in ("Deprecated", "Obsolete"):
        return None

    se, se_sources = _score_se(attack_pattern, rules)
    eq, eq_sources = _score_eq(attack_pattern, rules)
    et, et_sources = _score_et(attack_pattern, rules)
    koic, koic_sources = _score_koic(attack_pattern, rules)
    woo, woo_sources = _score_woo(attack_pattern, rules)

    source_fields: list[str] = []
    if se_sources:
        source_fields.append("Skills_Required")
    if eq_sources:
        source_fields.append("Resources_Required")
    if et_sources:
        source_fields.append("Execution_Flow")
    if koic_sources:
        source_fields.append("Prerequisites")
    if woo_sources:
        source_fields.append("Channel")

    source_fields = list(dict.fromkeys(source_fields))

    entry = {
        "ET": et,
        "SE": se,
        "KoIC": koic,
        "WoO": woo,
        "Eq": eq,
        "source_fields": source_fields,
        "derivation_trace": {
            "ET": et_sources,
            "SE": se_sources,
            "KoIC": koic_sources,
            "WoO": woo_sources,
            "Eq": eq_sources,
        },
        "capec_version": capec_version,
        "generated_at": generated_at,
    }

    return capec_id, entry

def enrich_from_xml(
    xml_path: str | Path,
    rules_path: str | Path = _RULES_PATH,
    output_path: Optional[str | Path] = None,
) -> dict[str, dict]:
    rules = _load_rules(Path(rules_path))
    generated_at = date.today().isoformat()

    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    version_attr = root.get("Version", "unknown")
    capec_version = version_attr

    patterns = root.findall(".//capec:Attack_Pattern", _NS)
    if not patterns:
        patterns = root.findall(".//Attack_Pattern")

    enrichment: dict[str, dict] = {}
    skipped = 0

    for pattern in patterns:
        result = _process_attack_pattern(pattern, rules, capec_version, generated_at)
        if result is None:
            skipped += 1
            continue
        capec_id, entry = result
        enrichment[capec_id] = entry

    print(f"[capec_enricher] Processed {len(enrichment)} patterns, skipped {skipped} (deprecated/obsolete)")
    print(f"  CAPEC corpus version : {capec_version}")
    print(f"  Generated at         : {generated_at}")

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(enrichment, f, indent=2)
        print(f"  Output               : {out}")

    return enrichment

def enrich_from_ids(
    capec_ids: list[str],
    xml_path: str | Path,
    rules_path: str | Path = _RULES_PATH,
    output_path: Optional[str | Path] = None,
) -> dict[str, dict]:
    full = enrich_from_xml(xml_path, rules_path)
    filtered = {cid: full[cid] for cid in capec_ids if cid in full}
    missing = [cid for cid in capec_ids if cid not in full]
    if missing:
        print(f"  Warning: {len(missing)} CAPEC IDs not found in corpus: {missing[:10]}")

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(filtered, f, indent=2)
        print(f"  Filtered output ({len(filtered)} entries) → {out}")

    return filtered

def lookup(
    capec_id: str,
    enrichment: dict[str, dict],
    rules_path: str | Path = _RULES_PATH,
) -> dict:
    entry = enrichment.get(str(capec_id))
    if entry:
        return entry
    rules = _load_rules(Path(rules_path))
    return dict(rules["fallback_defaults"])

if __name__ == "__main__":
    xml_path = sys.argv[1] if len(sys.argv) > 1 else "capec.xml"
    rules_path = sys.argv[2] if len(sys.argv) > 2 else str(_RULES_PATH)
    output_path = sys.argv[3] if len(sys.argv) > 3 else "capec_enrichment.json"
    enrich_from_xml(xml_path, rules_path, output_path)