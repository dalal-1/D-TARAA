from __future__ import annotations

import json
import sys
from pathlib import Path


AUTHORITATIVE_MAP: dict[str, list[str]] = {
    "M1":  ["1.1", "3.1"],
    "M2":  ["1.2", "3.3"],
    "M3":  ["2.1", "13.1"],
    "M4":  ["3.2"],
    "M5":  ["3.5"],
    "M6":  ["5.1"],
    "M7":  ["5.2", "5.3", "5.4", "5.5",
            "19.1", "20.1", "20.2", "20.3", "20.4", "20.5",
            "21.1", "22.2", "23.1", "25.1", "25.2"],
    "M8":  ["1.3", "3.4", "7.2", "7.3", "19.2"],
    "M9":  ["9.1", "32.1"],
    "M10": ["4.1", "5.1", "6.1", "6.2", "6.3", "11.2", "11.3", "11.4"],
    "M11": ["4.2", "12.4", "19.3"],
    "M12": ["7.1"],
    "M13": ["8.1", "8.2", "24.1"],
    "M14": ["10.1"],
    "M15": ["11.1"],
    "M16": ["12.1", "12.2", "12.3"],
    "M18": ["15.1"],
    "M19": ["15.2"],
    "M20": ["16.1", "16.2"],
    "M21": ["16.3", "17.1"],
    "M22": ["18.1", "18.2", "18.3"],
    "M23": ["26.1", "26.2", "26.3", "27.1", "28.1", "28.2", "29.1", "29.2"],
    "M24": ["30.1", "30.2", "30.3", "31.1"],
}

MITIGATION_CYBER_PROPERTIES: dict[str, list[str]] = {
    "M1":  ["Integrity", "Availability"],
    "M2":  ["Integrity"],
    "M3":  ["Availability"],
    "M4":  ["Confidentiality"],
    "M5":  ["Confidentiality"],
    "M6":  ["Integrity"],
    "M7":  ["Integrity", "Availability"],
    "M8":  ["Authorization", "Confidentiality"],
    "M9":  ["Authorization"],
    "M10": ["Integrity", "Authenticity"],
    "M11": ["Confidentiality", "Integrity"],
    "M12": ["Confidentiality"],
    "M13": ["Availability"],
    "M14": ["Integrity"],
    "M15": ["Integrity", "Authenticity"],
    "M16": ["Integrity", "Availability"],
    "M18": ["Authorization"],
    "M19": ["Authorization"],
    "M20": ["Authenticity", "Authorization"],
    "M21": ["Integrity"],
    "M22": ["Authorization"],
    "M23": ["Integrity", "Availability"],
    "M24": ["Confidentiality"],
}

MITIGATION_R155_REF: dict[str, str] = {
    "M1":  "R155 Annex 5 Part A §1.1, §3.1",
    "M2":  "R155 Annex 5 Part A §1.2, §3.3",
    "M3":  "R155 Annex 5 Part A §2.1, §13.1",
    "M4":  "R155 Annex 5 Part A §3.2",
    "M5":  "R155 Annex 5 Part A §3.5",
    "M6":  "R155 Annex 5 Part B §5.1",
    "M7":  "R155 Annex 5 Part B §5.2–5.5, §19.1–25.2",
    "M8":  "R155 Annex 5 Part B §1.3, §3.4, §7.2–7.3, §19.2",
    "M9":  "R155 Annex 5 Part B §9.1, §32.1",
    "M10": "R155 Annex 5 Part B §4.1–6.3, §11.2–11.4",
    "M11": "R155 Annex 5 Part B §4.2, §12.4, §19.3",
    "M12": "R155 Annex 5 Part B §7.1",
    "M13": "R155 Annex 5 Part B §8.1–8.2, §24.1",
    "M14": "R155 Annex 5 Part B §10.1",
    "M15": "R155 Annex 5 Part B §11.1",
    "M16": "R155 Annex 5 Part B §12.1–12.3",
    "M18": "R155 Annex 5 Part B §15.1",
    "M19": "R155 Annex 5 Part B §15.2",
    "M20": "R155 Annex 5 Part B §16.1–16.2",
    "M21": "R155 Annex 5 Part B §16.3, §17.1",
    "M22": "R155 Annex 5 Part B §18.1–18.3",
    "M23": "R155 Annex 5 Part B §26.1–29.2",
    "M24": "R155 Annex 5 Part C §30.1–31.1",
}

_THREAT_TO_MITS: dict[str, list[str]] | None = None


def threat_to_mitigations() -> dict[str, list[str]]:
    global _THREAT_TO_MITS
    if _THREAT_TO_MITS is None:
        _THREAT_TO_MITS = {}
        for mid, threats in AUTHORITATIVE_MAP.items():
            for tid in threats:
                _THREAT_TO_MITS.setdefault(tid, []).append(mid)
    return _THREAT_TO_MITS


def apply_mitigation_corrections(
    r155_raw_path: str | Path,
    *,
    write_back: bool = True,
    verbose: bool = True,
) -> dict:
    path = Path(r155_raw_path)
    with open(path, encoding="utf-8") as fh:
        data: dict = json.load(fh)

    mitigations: list[dict] = data.get("mitigations", [])
    changed = 0

    for m in mitigations:
        raw_id: str = m.get("mitigation_id", "")
        norm_id = raw_id.replace(" ", "").upper()

        authoritative = AUTHORITATIVE_MAP.get(norm_id)
        if authoritative is None:
            if verbose:
                print(f"  [r155_mitigation_builder] WARNING: no authoritative entry for {raw_id!r}")
            continue

        updated = False

        old_pa = m.get("protects_against", [])
        if old_pa != authoritative:
            if verbose:
                added   = set(authoritative) - set(old_pa)
                removed = set(old_pa) - set(authoritative)
                parts = []
                if added:
                    parts.append(f"+{sorted(added)}")
                if removed:
                    parts.append(f"-{sorted(removed)}")
                diff_str = "  ".join(parts) if parts else "(reordered)"
                print(f"  [r155_mitigation_builder] {norm_id} protects_against: {diff_str}")
            m["protects_against"] = list(authoritative)
            updated = True

        if not m.get("cyber_properties"):
            m["cyber_properties"] = MITIGATION_CYBER_PROPERTIES.get(norm_id, [])
            updated = True

        if not m.get("r155_ref"):
            m["r155_ref"] = MITIGATION_R155_REF.get(norm_id, "")
            updated = True

        if updated:
            changed += 1

    data["mitigation_extraction_method"] = "authoritative_table_post_correction"
    data["mitigation_count"] = len(mitigations)

    if write_back:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    if verbose:
        mit_with_ref = sum(1 for m in mitigations if m.get("r155_ref"))
        mit_with_cyber = sum(1 for m in mitigations if m.get("cyber_properties"))
        print(
            f"  [r155_mitigation_builder] Corrected {changed}/{len(mitigations)} mitigations → {path}"
        )
        print(f"  r155_ref populated: {mit_with_ref}/{len(mitigations)}")
        print(f"  cyber_properties populated: {mit_with_cyber}/{len(mitigations)}")

    return data


def build_mitigation_index(r155_raw: dict) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for m in r155_raw.get("mitigations", []):
        mid = m.get("mitigation_id", "")
        norm_id = mid.replace(" ", "").upper()
        entry = {
            "mitigation_id":    mid,
            "description":      m.get("description", ""),
            "scope":            m.get("scope", "vehicle"),
            "cyber_properties": m.get("cyber_properties") or MITIGATION_CYBER_PROPERTIES.get(norm_id, []),
            "r155_ref":         m.get("r155_ref") or MITIGATION_R155_REF.get(norm_id, ""),
        }
        for ref in m.get("protects_against", []):
            index.setdefault(str(ref), []).append(entry)
    return index


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "output/r155_raw.json"
    print(f"[r155_mitigation_builder] Applying corrections to {path}")
    result = apply_mitigation_corrections(path, write_back=True, verbose=True)
    mits = result.get("mitigations", [])
    covered = sum(1 for m in mits if m.get("protects_against"))
    print(f"  Mitigations total        : {len(mits)}")
    print(f"  With protects_against    : {covered}")
    print(f"  With r155_ref            : {sum(1 for m in mits if m.get('r155_ref'))}")
    print(f"  With cyber_properties    : {sum(1 for m in mits if m.get('cyber_properties'))}")
    threat_idx = threat_to_mitigations()
    print(f"  Unique threats covered   : {len(threat_idx)}")