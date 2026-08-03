from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Optional

NS = {"capec": "http://capec.mitre.org/capec-3"}

HEAVENS_SKILLS_MAP = {
    "Low": 6,
    "Medium": 3,
    "High": 0,
    "Unknown": 3,
}

HEAVENS_CHANNEL_MAP = {
    "Remote": 1,
    "Network": 1,
    "Internet": 1,
    "Adjacent": 2,
    "Local": 3,
    "Physical": 4,
    "Unknown": 2,
}

HEAVENS_LIKELIHOOD_ET = {
    "High": 1,
    "Medium": 3,
    "Low": 5,
    "Unknown": None,
}

EXECUTION_PHASE_WEIGHTS = {
    "Exploit": 2,
    "Experiment": 1,
    "Explore": 0,
}

ET_THRESHOLDS = [
    {"max_weighted_steps": 2,   "ET": 1},
    {"max_weighted_steps": 5,   "ET": 2},
    {"max_weighted_steps": 10,  "ET": 3},
    {"max_weighted_steps": 18,  "ET": 4},
    {"max_weighted_steps": 30,  "ET": 5},
    {"max_weighted_steps": 999, "ET": 6},
]

INTERFACE_ASSESSMENT_POLICY = {
    "assessed": {
        "woo_modifier": 0.0,
        "rationale": "security_properties are verified; apply WoO score as computed from channel",
    },
    "unassessed": {
        "woo_modifier": -1,
        "rationale": "security_properties unknown; reduce WoO by 1 step to reflect epistemic uncertainty without assuming worst-case",
    },
    "explicitly_insecure": {
        "woo_modifier": 0.0,
        "rationale": "confirmed no authentication or encryption; apply WoO score as computed from channel without modifier",
    },
}

KOIC_LEVEL_ORDER = ["KoIC_6", "KoIC_3", "KoIC_1", "KoIC_0"]
EQ_LEVEL_ORDER   = ["Eq_6", "Eq_3", "Eq_1", "Eq_0"]

KOIC_SEED = {
    "KoIC_6": [
        "knowledge of target system",
        "access to source code",
        "internal knowledge",
        "insider knowledge",
        "detailed knowledge of implementation",
        "knowledge of proprietary protocol",
        "knowledge of encryption key",
        "access to signing key",
    ],
    "KoIC_3": [
        "knowledge of the target",
        "knowledge of vulnerability",
        "familiarity with",
        "understanding of",
        "knowledge of network topology",
        "knowledge of authentication mechanism",
    ],
    "KoIC_1": [
        "publicly available information",
        "basic knowledge",
        "general knowledge",
        "common knowledge",
        "standard knowledge",
    ],
    "KoIC_0": [
        "no prior knowledge",
        "no knowledge required",
        "no specific knowledge",
    ],
}

EQ_SEED = {
    "Eq_6": [
        "specialized hardware",
        "custom hardware",
        "hardware implant",
        "hardware modification",
        "proprietary equipment",
        "oscilloscope",
        "logic analyzer",
        "jtag debugger",
        "soldering",
        "chip-off",
    ],
    "Eq_3": [
        "commercial tool",
        "commercial software",
        "specialized software",
        "vulnerability scanner",
        "fuzzer",
        "debugger",
        "disassembler",
        "network sniffer",
        "hardware tool",
        "bus analyzer",
    ],
    "Eq_1": [
        "standard tool",
        "publicly available tool",
        "free tool",
        "open source tool",
        "common tool",
        "internet access",
        "web browser",
    ],
    "Eq_0": [
        "no specialized equipment",
        "no equipment",
        "no special",
        "none required",
        "any device",
    ],
}

FALLBACK_DEFAULTS = {
    "ET":   3,
    "SE":   3,
    "KoIC": 2,
    "WoO":  2,
    "Eq":   1,
}

STOPWORDS = {
    "the","a","an","of","in","to","and","or","is","are","be","that","this",
    "for","on","with","not","by","as","it","at","from","which","can","has",
    "have","been","its","their","if","into","was","were","will","would",
    "should","could","may","must","do","does","so","but","also","such",
    "when","where","how","what","who","then","than","these","those","both",
    "each","some","any","all","one","two","more","other","only","very",
    "well","just","even","much","many","own","same","about","after","before",
    "between","through","during","against","without","because","while","use",
}

MIN_NGRAM_FREQ   = 4
MIN_NGRAM_LENGTH = 3
MAX_NGRAMS_PER_LEVEL = 20
NGRAM_SIZES = [2, 3]


def _itertext(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    return " ".join(t.strip() for t in element.itertext() if t.strip()).lower()


def _ngrams(text: str, n: int) -> list[str]:
    words = re.findall(r"\b[a-z]\w*\b", text)
    return [" ".join(words[i : i + n]) for i in range(len(words) - n + 1)]


def _is_informative(ngram: str) -> bool:
    parts = ngram.split()
    if len(ngram) < MIN_NGRAM_LENGTH:
        return False
    if all(p in STOPWORDS for p in parts):
        return False
    return True


def _load_patterns(xml_path: Path) -> list[ET.Element]:
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    patterns = root.findall(".//capec:Attack_Pattern", NS)
    if not patterns:
        patterns = root.findall(".//Attack_Pattern")
    return [
        p for p in patterns
        if p.get("Status", "") not in ("Deprecated", "Obsolete")
    ]


def _collect_field_texts(patterns: list[ET.Element], tag: str) -> list[str]:
    texts = []
    for p in patterns:
        el = p.find(f".//capec:{tag}", NS)
        if el is not None:
            text = _itertext(el)
            if text.strip():
                texts.append(text)
    return texts


def _collect_prerequisite_texts(patterns: list[ET.Element]) -> list[str]:
    texts = []
    for p in patterns:
        prereqs = p.findall(".//capec:Prerequisites/capec:Prerequisite", NS)
        combined = " ".join(_itertext(pr) for pr in prereqs).strip()
        if combined:
            texts.append(combined)
    return texts


def _extract_candidate_ngrams(
    texts: list[str],
    seed_keywords: dict[str, list[str]],
) -> Counter:
    seed_flat = {kw.lower() for kws in seed_keywords.values() for kw in kws}
    freq: Counter = Counter()
    for text in texts:
        for n in NGRAM_SIZES:
            for ng in _ngrams(text, n):
                if _is_informative(ng) and ng not in seed_flat:
                    freq[ng] += 1
    return freq


def _assign_ngram_to_level(
    ngram: str,
    seed: dict[str, list[str]],
    level_signals: dict[str, list[str]],
) -> Optional[str]:
    for level, signals in level_signals.items():
        if any(sig in ngram for sig in signals):
            return level
    return None


def _derive_koic_keywords(patterns: list[ET.Element]) -> dict[str, list[str]]:
    prereq_texts = _collect_prerequisite_texts(patterns)
    freq = _extract_candidate_ngrams(prereq_texts, KOIC_SEED)

    level_signals = {
        "KoIC_6": [
            "proprietary", "source code", "encryption", "signing", "insider",
            "internal", "secret", "private key", "firmware",
        ],
        "KoIC_3": [
            "adversary must", "attacker must", "must have", "must be able",
            "requires access", "ability to", "prior access", "knowledge of",
            "familiarity", "understanding", "advanced knowledge", "physical access",
            "the adversary requires", "attacker requires", "adversary requires",
        ],
        "KoIC_1": [
            "publicly", "basic", "general", "common", "standard", "no prior",
            "minimal", "easily", "widely", "open source", "application does not",
            "target must", "target application", "no special",
        ],
        "KoIC_0": [
            "no prior knowledge", "no knowledge", "no specific",
        ],
    }

    result = {level: list(kws) for level, kws in KOIC_SEED.items()}

    assigned_to_level: dict[str, list[str]] = {k: [] for k in KOIC_LEVEL_ORDER}
    for ng, count in freq.most_common():
        if count < MIN_NGRAM_FREQ:
            break
        level = _assign_ngram_to_level(ng, KOIC_SEED, level_signals)
        if level and len(assigned_to_level[level]) < MAX_NGRAMS_PER_LEVEL:
            already_covered = any(ng in existing or existing in ng for existing in result[level])
            if not already_covered:
                result[level].append(ng)
                assigned_to_level[level].append(ng)

    return result


def _derive_eq_keywords(patterns: list[ET.Element]) -> dict[str, list[str]]:
    resource_texts = _collect_field_texts(patterns, "Resources_Required")
    freq = _extract_candidate_ngrams(resource_texts, EQ_SEED)

    level_signals = {
        "Eq_6": [
            "hardware", "oscilloscope", "logic analyzer", "jtag", "soldering",
            "chip", "probe", "implant", "proprietary equipment", "custom device",
        ],
        "Eq_3": [
            "tool capable", "specialized tool", "commercial", "scanner",
            "fuzzer", "debugger", "disassembler", "sniffer", "analyzer",
            "intercept", "packet", "proxy", "exploit framework",
        ],
        "Eq_1": [
            "standard tool", "publicly available", "free", "open source",
            "browser", "internet", "common tool", "web browser", "script",
            "basic tool",
        ],
        "Eq_0": [
            "none", "no specialized", "no equipment", "no special", "not required",
            "no resources", "any device",
        ],
    }

    result = {level: list(kws) for level, kws in EQ_SEED.items()}

    assigned_to_level: dict[str, list[str]] = {k: [] for k in EQ_LEVEL_ORDER}
    for ng, count in freq.most_common():
        if count < MIN_NGRAM_FREQ:
            break
        level = _assign_ngram_to_level(ng, EQ_SEED, level_signals)
        if level and len(assigned_to_level[level]) < MAX_NGRAMS_PER_LEVEL:
            already_covered = any(ng in existing or existing in ng for existing in result[level])
            if not already_covered:
                result[level].append(ng)
                assigned_to_level[level].append(ng)

    return result


def _measure_coverage(
    patterns: list[ET.Element],
    koic_keywords: dict[str, list[str]],
    eq_keywords: dict[str, list[str]],
) -> dict:
    prereq_texts = _collect_prerequisite_texts(patterns)
    resource_texts = _collect_field_texts(patterns, "Resources_Required")

    all_koic_kws = [kw for kws in koic_keywords.values() for kw in kws]
    all_eq_kws   = [kw for kws in eq_keywords.values()   for kw in kws]

    koic_matched = sum(1 for t in prereq_texts if any(kw in t for kw in all_koic_kws))
    eq_matched   = sum(1 for t in resource_texts if any(kw in t for kw in all_eq_kws))

    koic_by_level = {}
    for level, kws in koic_keywords.items():
        koic_by_level[level] = sum(1 for t in prereq_texts if any(kw in t for kw in kws))

    eq_by_level = {}
    for level, kws in eq_keywords.items():
        eq_by_level[level] = sum(1 for t in resource_texts if any(kw in t for kw in kws))

    skills_present = sum(
        1 for p in patterns
        if p.findall(".//capec:Skills_Required/capec:Skill", NS)
    )
    execution_present = sum(
        1 for p in patterns
        if p.findall(".//capec:Execution_Flow/capec:Attack_Step", NS)
    )

    return {
        "corpus_size": len(patterns),
        "KoIC": {
            "field_present": len(prereq_texts),
            "field_coverage_pct": round(len(prereq_texts) / len(patterns) * 100, 1),
            "keyword_match": koic_matched,
            "keyword_coverage_pct": round(koic_matched / len(prereq_texts) * 100, 1) if prereq_texts else 0,
            "by_level": koic_by_level,
        },
        "Eq": {
            "field_present": len(resource_texts),
            "field_coverage_pct": round(len(resource_texts) / len(patterns) * 100, 1),
            "keyword_match": eq_matched,
            "keyword_coverage_pct": round(eq_matched / len(resource_texts) * 100, 1) if resource_texts else 0,
            "by_level": eq_by_level,
        },
        "SE": {
            "field_present": skills_present,
            "field_coverage_pct": round(skills_present / len(patterns) * 100, 1),
            "derivation": "direct_xml_attribute",
        },
        "ET": {
            "field_present": execution_present,
            "field_coverage_pct": round(execution_present / len(patterns) * 100, 1),
            "derivation": "weighted_phase_count",
        },
        "WoO": {
            "field_present": 0,
            "field_coverage_pct": 0.0,
            "derivation": "channel_field_absent_in_xml_v3.9_cwe_fallback_active",
        },
    }


def generate(
    xml_path: str | Path,
    output_path: Optional[str | Path] = None,
    include_metadata: bool = True,
) -> dict:
    xml_path = Path(xml_path)
    patterns = _load_patterns(xml_path)

    version_attr = ET.parse(str(xml_path)).getroot().get("Version", "unknown")

    koic_keywords = _derive_koic_keywords(patterns)
    eq_keywords   = _derive_eq_keywords(patterns)
    coverage      = _measure_coverage(patterns, koic_keywords, eq_keywords)

    rules = {
        "version": "2.0",
        "description": (
            "Projection rules mapping CAPEC XML fields to ThreatSurf attack feasibility dimensions. "
            "All scoring logic lives here; capec_enricher.py contains no embedded knowledge."
        ),
        "skills_required_level_map": HEAVENS_SKILLS_MAP,
        "resources_required_keywords": eq_keywords,
        "execution_flow_phase_weights": EXECUTION_PHASE_WEIGHTS,
        "elapsed_time_step_thresholds": ET_THRESHOLDS,
        "prerequisites_koic_keywords": koic_keywords,
        "channel_woo_map": HEAVENS_CHANNEL_MAP,
        "likelihood_et_signal": HEAVENS_LIKELIHOOD_ET,
        "fallback_defaults": FALLBACK_DEFAULTS,
        "interface_assessment_woo_policy": INTERFACE_ASSESSMENT_POLICY,
    }

    if include_metadata:
        rules["derivation_metadata"] = {
            "generated_at": date.today().isoformat(),
            "capec_version": version_attr,
            "xml_source": xml_path.name,
            "derivation_method": {
                "skills_required_level_map": "HEAVENS_2.0_table_direct",
                "channel_woo_map": "HEAVENS_2.0_table_direct",
                "execution_flow_phase_weights": "CAPEC_taxonomy_direct",
                "elapsed_time_step_thresholds": "HEAVENS_2.0_ET_grid_direct",
                "likelihood_et_signal": "CAPEC_Typical_Likelihood_Of_Exploit_field",
                "prerequisites_koic_keywords": "empirical_ngram_extraction_from_corpus",
                "resources_required_keywords": "empirical_ngram_extraction_from_corpus",
                "fallback_defaults": "engineering_decision_explicit",
                "interface_assessment_woo_policy": "engineering_decision_explicit",
            },
            "coverage": coverage,
        }

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)
        print(f"[generate_capec_projection_rules] Output → {out}")
        _print_coverage_report(coverage)

    return rules


def _print_coverage_report(coverage: dict) -> None:
    print(f"  Corpus size : {coverage['corpus_size']} patterns")
    for dim in ("KoIC", "Eq", "SE", "ET", "WoO"):
        d = coverage[dim]
        if "keyword_coverage_pct" in d:
            print(
                f"  {dim:5s} : field {d['field_coverage_pct']:5.1f}%  "
                f"| keyword match {d['keyword_coverage_pct']:5.1f}%"
            )
        else:
            print(
                f"  {dim:5s} : field {d['field_coverage_pct']:5.1f}%  "
                f"| derivation = {d['derivation']}"
            )


if __name__ == "__main__":
    import sys
    xml_path    = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("capec_latest.xml")
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("capec_projection_rules.json")
    generate(xml_path, output_path, include_metadata=True)
