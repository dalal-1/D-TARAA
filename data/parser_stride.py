#!/usr/bin/env python3
"""
html_to_parsed_threats.py
─────────────────────────
Parse a Microsoft Threat Modeling Tool HTML report and produce
parsed_threats.json, the exact format consumed by dfd_to_attack_paths.py.

Usage:
    python html_to_parsed_threats.py                          # defaults
    python html_to_parsed_threats.py -i report.html -o parsed_threats.json
    python html_to_parsed_threats.py --summary                # show stats only

Output schema (one object per threat):
    {
        "id":          "T001",          -- zero-padded sequential ID
        "interaction": "ACCEL_TO_FRONT_INVERTER_TO_DRIVE_INVERTER_FRONT",
        "source":      "ACCEL_SENSOR",  -- extracted from interaction name
        "destination": "DRIVE_INVERTER_FRONT",
        "protocol":    "CAN",           -- transport parsed from interaction label
        "application": "NONE",          -- application layer (UDS, SOMEIP …)
        "category":    "Spoofing",      -- raw STRIDE category from HTML
        "stride":      "Spoofing",      -- normalised STRIDE label
        "title":       "Spoofing the DRIVE_INVERTER_FRONT Process",
        "description": "DRIVE_INVERTER_FRONT may be spoofed …",
        "justification": "<no mitigation provided>",
        "state":       "Not Started",
        "priority":    "High"
    }
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERROR] beautifulsoup4 is required. Run:  pip install beautifulsoup4",
          file=sys.stderr)
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# STRIDE normalisation
# ──────────────────────────────────────────────────────────────────────────────

_STRIDE_NORM: dict[str, str] = {
    "spoofing":               "Spoofing",
    "tampering":              "Tampering",
    "repudiation":            "Repudiation",
    "information disclosure": "Information Disclosure",
    "informationdisclosure":  "Information Disclosure",
    "denial of service":      "DoS",
    "denialofservice":        "DoS",
    "dos":                    "DoS",
    "elevation of privilege": "Elevation of Privilege",
    "elevationofprivilege":   "Elevation of Privilege",
    "elevation_of_privilege": "Elevation of Privilege",
    "eop":                    "Elevation of Privilege",
}

def normalise_stride(raw: str) -> str:
    key = raw.strip().lower().replace("_", " ")
    return _STRIDE_NORM.get(key, raw.strip())


# ──────────────────────────────────────────────────────────────────────────────
# Interaction header parsing
# Handles both forms: "FLOW_ID [PROTO]" and "BUS_NAME (PROTO)"
# ──────────────────────────────────────────────────────────────────────────────

_INTERACTION_RE = re.compile(
    r"^Interaction:\s*(.+?)\s*[\[\(]([^\]\)]+)[\]\)]\s*$",
    re.IGNORECASE,
)

def parse_interaction_header(text: str) -> tuple[str, str, str]:
    """
    Returns (interaction_key, transport, application).
    interaction_key  = upper-cased flow ID, e.g. "ACCEL_TO_FRONT_INVERTER"
    transport        = "CAN", "ETH", "BLE" …
    application      = "NONE", "UDS", "SOMEIP" …
    """
    text = text.strip()
    m = _INTERACTION_RE.match(text)
    if not m:
        # Fallback: strip the "Interaction: " prefix and use the rest as key
        raw = re.sub(r"^Interaction:\s*", "", text, flags=re.IGNORECASE).strip()
        return raw.upper(), "UNKNOWN", "NONE"

    flow_id  = m.group(1).strip()
    proto_raw = m.group(2).strip()           # e.g. "CAN/UDS", "ETH/SOMEIP", "CAN"

    # Split transport / application
    if "/" in proto_raw:
        parts = proto_raw.split("/", 1)
        transport   = parts[0].strip().upper()
        application = parts[1].strip().upper()
    else:
        transport   = proto_raw.upper()
        application = "NONE"

    # Build interaction key: FLOW_ID (already unique, already describes src→dst)
    interaction_key = flow_id.upper()

    return interaction_key, transport, application


# ──────────────────────────────────────────────────────────────────────────────
# Source / destination inference from interaction key + description
# ──────────────────────────────────────────────────────────────────────────────

def _infer_src_dst(interaction_key: str, description: str) -> tuple[str, str]:
    """
    Extract source and destination from the interaction key.
    Keys like ACCEL_SENSOR_TO_DRIVE_INVERTER_FRONT encode src_TO_dst.
    We try every _TO_ occurrence and pick the split that produces the
    longest valid source (heuristic: longer left token = more specific node).
    Falls back to the whole key when no _TO_ exists (bus names etc.).
    """
    upper = interaction_key.upper()

    # Find all positions of the literal substring "_TO_"
    positions: list[int] = []
    start = 0
    while True:
        pos = upper.find("_TO_", start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        # Prefer the rightmost split so the source token is as complete as possible.
        # e.g. "OBD_UDS_TO_AUTOPILOT" → src="OBD_UDS", dst="AUTOPILOT"  ✓
        # e.g. "ACCEL_TO_FRONT_INVERTER" → last _TO_ → src="ACCEL", dst="FRONT_INVERTER"
        #      but we also want "ACCEL_SENSOR_TO_DRIVE_INVERTER_FRONT" to split correctly
        # Strategy: pick the split where neither side is a single short token
        best = positions[-1]            # default: last occurrence
        for pos in positions:
            left  = upper[:pos].strip("_")
            right = upper[pos + 4:].strip("_")
            # Prefer a split where both sides have at least one underscore-segment
            # that looks like a node name (contains letters, not purely numeric)
            if left and right and len(left) >= 3 and len(right) >= 3:
                best = pos              # keep updating → last valid split wins
        src = upper[:best].strip("_")
        dst = upper[best + 4:].strip("_")
        return src, dst

    # No _TO_ found: bus name or symmetric — both equal the key
    return upper, upper


# ──────────────────────────────────────────────────────────────────────────────
# Single-threat extractor
# ──────────────────────────────────────────────────────────────────────────────

_STATE_RE    = re.compile(r"\[State:\s*([^\]]+)\]",    re.IGNORECASE)
_PRIORITY_RE = re.compile(r"\[Priority:\s*([^\]]+)\]", re.IGNORECASE)
_NUM_RE      = re.compile(r"^\s*(\d+)\.\s*(.+)")


def extract_threat(div) -> dict:
    """Extract all fields from a <div class='threat'> element."""
    h4 = div.find("h4")
    h4_text = h4.get_text(" ", strip=True) if h4 else ""

    # Title: text inside the <span> child of h4
    span  = h4.find("span") if h4 else None
    raw_title = span.get_text(strip=True) if span else ""
    m = _NUM_RE.match(raw_title)
    seq_num = int(m.group(1)) if m else 0
    title   = m.group(2).strip() if m else raw_title

    # State & Priority from the h4 text
    state_m    = _STATE_RE.search(h4_text)
    priority_m = _PRIORITY_RE.search(h4_text)
    state    = state_m.group(1).strip()    if state_m    else ""
    priority = priority_m.group(1).strip() if priority_m else ""

    # Fields from the table (Category / Description / Justification)
    fields: dict[str, str] = {}
    for row in div.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) == 2:
            key = cells[0].get_text(strip=True).rstrip(":")
            val = cells[1].get_text(strip=True)
            fields[key] = val

    category = fields.get("Category", "").strip()
    desc     = fields.get("Description", "").strip()
    justif   = fields.get("Justification", "").strip()

    return {
        "_seq":         seq_num,        # internal sort key, removed later
        "category":     category,
        "stride":       normalise_stride(category),
        "title":        title,
        "description":  desc,
        "justification": justif,
        "state":        state,
        "priority":     priority,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main parser
# ──────────────────────────────────────────────────────────────────────────────

def parse_html_report(html_path: str) -> list[dict]:
    with open(html_path, encoding="utf-8-sig") as fh:
        soup = BeautifulSoup(fh.read(), "html.parser")

    # Collect all h3 interaction headers
    interaction_h3s = [
        h for h in soup.find_all("h3")
        if "Interaction:" in h.get_text()
    ]

    records: list[dict] = []
    counter = [0]

    for h3 in interaction_h3s:
        interaction_text = h3.get_text(strip=True)
        interaction_key, transport, application = parse_interaction_header(interaction_text)

        # Gather threat divs that immediately follow this h3 (before the next h3)
        threat_divs: list = []
        sib = h3.next_sibling
        while sib:
            if hasattr(sib, "name") and sib.name:
                if sib.name == "h3":
                    break
                if sib.name == "div" and "threat" in (sib.get("class") or []):
                    threat_divs.append(sib)
            sib = sib.next_sibling

        for div in threat_divs:
            threat = extract_threat(div)
            src, dst = _infer_src_dst(interaction_key, threat["description"])

            counter[0] += 1
            tid = f"T{counter[0]:03d}"

            record = {
                "id":            tid,
                "interaction":   interaction_key,
                "source":        src,
                "destination":   dst,
                "protocol":      transport,
                "application":   application,
                "category":      threat["category"],
                "stride":        threat["stride"],
                "title":         threat["title"],
                "description":   threat["description"],
                "justification": threat["justification"],
                "state":         threat["state"],
                "priority":      threat["priority"],
            }
            records.append(record)

    return records


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def _print_summary(records: list[dict]) -> None:
    from collections import Counter
    print(f"\n{'─'*60}")
    print(f"  Total threats parsed : {len(records)}")

    stride_counts = Counter(r["stride"] for r in records)
    print("\n  STRIDE distribution:")
    for stride, n in sorted(stride_counts.items(), key=lambda x: -x[1]):
        bar = "█" * (n // 3)
        print(f"    {stride:<28s} {n:>4d}  {bar}")

    interactions = Counter(r["interaction"] for r in records)
    print(f"\n  Unique interactions  : {len(interactions)}")
    print(f"  Avg threats/interaction: {len(records)/max(len(interactions),1):.1f}")

    protocols = Counter(r["protocol"] for r in records)
    print("\n  Protocol distribution:")
    for p, n in sorted(protocols.items(), key=lambda x: -x[1]):
        print(f"    {p:<12s} {n:>4d}")
    print(f"{'─'*60}\n")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Parse MTMT HTML threat report → parsed_threats.json"
    )
    ap.add_argument("-i", "--input",   default="report-final.html",
                    help="Input HTML file (default: report-final.html)")
    ap.add_argument("-o", "--output",  default="parsed_threats.json",
                    help="Output JSON file (default: parsed_threats.json)")
    ap.add_argument("--summary",       action="store_true",
                    help="Print statistics after parsing")
    ap.add_argument("--indent",        type=int, default=2,
                    help="JSON indent level (default: 2)")
    args = ap.parse_args()

    if not Path(args.input).exists():
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {args.input} …")
    records = parse_html_report(args.input)

    if not records:
        print("[WARNING] No threats found — check that the HTML has "
              "'Interaction:' headers and <div class='threat'> elements.",
              file=sys.stderr)
        sys.exit(1)

    print(f"[✓] Extracted {len(records)} threat entries")

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=args.indent, ensure_ascii=False)

    size_kb = Path(args.output).stat().st_size / 1024
    print(f"[✓] Written: {args.output}  ({size_kb:.1f} KB)")

    if args.summary:
        _print_summary(records)


if __name__ == "__main__":
    main()