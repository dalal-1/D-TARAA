from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, Image, KeepTogether,
    NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer,
    Table, TableStyle,
)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


C_NAVY       = HexColor("#0F2137")
C_NAVY_MID   = HexColor("#1A3A5C")
C_TEAL       = HexColor("#1A7F8E")
C_TEAL_LIGHT = HexColor("#E8F4F6")
C_SLATE      = HexColor("#4A6070")
C_GOLD       = HexColor("#C8973A")
C_WHITE      = HexColor("#FFFFFF")
C_OFF_WHITE  = HexColor("#F8FAFB")
C_LIGHT      = HexColor("#EDF1F4")
C_BORDER     = HexColor("#D0D9E0")
C_TEXT       = HexColor("#1C2B36")
C_RED        = HexColor("#C0392B")
C_ORANGE     = HexColor("#E65100")
C_GREEN      = HexColor("#1B5E20")
C_AMBER      = HexColor("#C8973A")

SEVERITY_COLORS = {
    "CRITICAL": HexColor("#7B0000"),
    "HIGH":     HexColor("#C0392B"),
    "MEDIUM":   HexColor("#E65100"),
    "LOW":      HexColor("#C8973A"),
    "NONE":     HexColor("#1B5E20"),
}

RISK_COLORS = {
    "Critical": HexColor("#C0392B"),
    "High":     HexColor("#E65100"),
    "Medium":   HexColor("#C8973A"),
    "Low":      HexColor("#1B5E20"),
}

PAGE_W, PAGE_H   = A4
MARGIN_TOP       = 2.5 * cm
MARGIN_BOTTOM    = 2.5 * cm
MARGIN_LEFT      = 2.2 * cm
MARGIN_RIGHT     = 2.2 * cm
CONTENT_W        = PAGE_W - MARGIN_LEFT - MARGIN_RIGHT
LAND_W, LAND_H   = landscape(A4)
LAND_MARGIN      = 1.6 * cm
LAND_CONTENT_W   = LAND_W - 2 * LAND_MARGIN
LAND_CONTENT_H   = LAND_H - (MARGIN_TOP + 1.0*cm) - (MARGIN_BOTTOM + 0.8*cm) - 1.2*cm


def _esc(s: str) -> str:
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _clean(s) -> str:
    if not s:
        return ""
    s = str(s).replace("__", " ").replace("_", " ").replace("--", " ")
    s = re.sub(r'\s+', ' ', s)
    return s.strip()


def _trunc(s: str, n: int = 80) -> str:
    s = _clean(str(s))
    return s[:n] if len(s) > n else s


def _fmt_list(lst, sep=", ") -> str:
    if not lst:
        return "N/A"
    return sep.join(_clean(str(x)) for x in lst if x)


def _risk_color(level: str) -> HexColor:
    return RISK_COLORS.get(level, C_SLATE)


def _risk_hex(level: str) -> str:
    c = _risk_color(level)
    return f"#{int(c.red*255):02x}{int(c.green*255):02x}{int(c.blue*255):02x}"


def _sev_hex(sev: str) -> str:
    c = SEVERITY_COLORS.get(str(sev).upper(), C_SLATE)
    return f"#{int(c.red*255):02x}{int(c.green*255):02x}{int(c.blue*255):02x}"


def _delta_symbol(before: str, after: str) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "N/A": 0}
    b, a = order.get(before, 0), order.get(after, 0)
    if a > b:   return "▲ ESCALATED"
    if a < b:   return "▼ REDUCED"
    return "= UNCHANGED"


def _delta_color(before: str, after: str) -> str:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "N/A": 0}
    b, a = order.get(before, 0), order.get(after, 0)
    if a > b:   return "#C0392B"
    if a < b:   return "#1B5E20"
    return "#4A6070"


def build_styles() -> Dict:
    S = {}
    def add(name, **kw):
        S[name] = ParagraphStyle(name=name, **kw)
    add("body",        fontName="Helvetica",         fontSize=9,  textColor=C_TEXT,    leading=13, spaceAfter=4)
    add("body_small",  fontName="Helvetica",         fontSize=8,  textColor=C_SLATE,   leading=11, spaceAfter=2)
    add("body_italic", fontName="Helvetica-Oblique", fontSize=8,  textColor=C_SLATE,   leading=11, spaceAfter=2)
    add("th",          fontName="Helvetica-Bold",    fontSize=8,  textColor=C_WHITE,   leading=11, alignment=TA_LEFT)
    add("td",          fontName="Helvetica",         fontSize=8,  textColor=C_TEXT,    leading=11)
    add("td_label",    fontName="Helvetica-Bold",    fontSize=8,  textColor=C_SLATE,   leading=11)
    add("section",     fontName="Helvetica-Bold",    fontSize=16, textColor=C_NAVY,    spaceAfter=8, spaceBefore=14)
    add("subsection",  fontName="Helvetica-Bold",    fontSize=12, textColor=C_NAVY_MID, spaceAfter=6, spaceBefore=10)
    add("card_title",  fontName="Helvetica-Bold",    fontSize=11, textColor=C_WHITE,   leading=14)
    add("badge",       fontName="Helvetica-Bold",    fontSize=9,  textColor=C_WHITE,   leading=11)
    add("note",        fontName="Helvetica-Oblique", fontSize=8,  textColor=C_SLATE,   leading=11, spaceAfter=4)
    add("alert",       fontName="Helvetica-Bold",    fontSize=9,  textColor=C_RED,     leading=13, spaceAfter=4)
    add("toc_h1",      fontName="Helvetica-Bold",    fontSize=10, textColor=C_NAVY,    leading=18)
    add("toc_entry",   fontName="Helvetica",         fontSize=9,  textColor=C_TEXT,    leading=15)
    return S


def styled_table(data_rows, col_widths=None, header=True) -> Table:
    S = build_styles()
    if not data_rows:
        return Table([["N/A"]])
    fmt = []
    for i, row in enumerate(data_rows):
        frow = []
        for cell in row:
            if isinstance(cell, (Paragraph, Table)):
                frow.append(cell)
            elif i == 0 and header:
                frow.append(Paragraph(_esc(_clean(str(cell))), S["th"]))
            else:
                frow.append(Paragraph(_esc(_clean(str(cell))), S["td"]))
        fmt.append(frow)
    t = Table(fmt, colWidths=col_widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0),  (-1, 0),   C_TEAL),
        ("TEXTCOLOR",     (0, 0),  (-1, 0),   C_WHITE),
        ("ROWBACKGROUNDS",(0, 1),  (-1, -1),  [C_WHITE, C_OFF_WHITE]),
        ("GRID",          (0, 0),  (-1, -1),  0.3, C_BORDER),
        ("LEFTPADDING",   (0, 0),  (-1, -1),  6),
        ("RIGHTPADDING",  (0, 0),  (-1, -1),  6),
        ("TOPPADDING",    (0, 0),  (-1, -1),  4),
        ("BOTTOMPADDING", (0, 0),  (-1, -1),  4),
        ("VALIGN",        (0, 0),  (-1, -1),  "TOP"),
    ]))
    return t


def info_table(rows: List[Tuple[str, Any]], col_widths=None) -> Table:
    S = build_styles()
    cw = col_widths or [4.0*cm, CONTENT_W - 4.0*cm]
    data = [[
        Paragraph(_esc(_clean(k)), S["td_label"]),
        v if isinstance(v, Paragraph) else Paragraph(_esc(_clean(str(v))), S["body"])
    ] for k, v in rows if v not in (None, "", "N/A")]
    if not data:
        return Table([["N/A"]])
    t = Table(data, colWidths=cw)
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_OFF_WHITE]),
        ("GRID",           (0, 0), (-1, -1), 0.2, C_BORDER),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
        ("TOPPADDING",     (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 3),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("FONTNAME",       (0, 0), (0, -1),  "Helvetica-Bold"),
        ("TEXTCOLOR",      (0, 0), (0, -1),  C_SLATE),
    ]))
    return t


def card_header(accent: HexColor, id_str: str, title: str) -> Table:
    S = build_styles()
    id_clean  = _clean(id_str)
    badge = Paragraph(f'<b>{_esc(id_clean)}</b>',
                      ParagraphStyle("badge_mono", parent=S["badge"],
                                     fontName="Helvetica-Bold", fontSize=8,
                                     wordWrap="CJK"))
    ttl   = Paragraph(_esc(_clean(title)), S["card_title"])
    badge_w = max(3.2*cm, min(4.5*cm, len(id_clean) * 0.22*cm))
    t = Table([[badge, ttl]], colWidths=[badge_w, CONTENT_W - badge_w])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), accent),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def divider() -> HRFlowable:
    return HRFlowable(width=CONTENT_W, thickness=0.4, color=C_GOLD)


def thin_divider() -> HRFlowable:
    return HRFlowable(width=CONTENT_W, thickness=0.25, color=C_BORDER)


def _cover_page(canvas_obj, doc_obj, cve_id: str, cve_severity: str, report_date: str,
                item_name: str, assessor_action: str):
    canvas_obj.saveState()
    w, h = A4

    canvas_obj.setFillColor(C_NAVY)
    canvas_obj.rect(0, 0, w, h, fill=1, stroke=0)
    canvas_obj.setFillColor(C_RED if assessor_action == "REVIEW REQUIRED" else C_TEAL)
    canvas_obj.rect(0, h - 0.8*cm, w, 0.8*cm, fill=1, stroke=0)

    canvas_obj.setStrokeColor(C_GOLD)
    canvas_obj.setLineWidth(1.5)
    canvas_obj.line(MARGIN_LEFT, h - 3.5*cm, w - MARGIN_RIGHT, h - 3.5*cm)

    bw, bh = 9*cm, 1.6*cm
    bx, by = w/2 - bw/2, h - 6.5*cm
    sev_c = SEVERITY_COLORS.get(cve_severity.upper(), C_SLATE)
    canvas_obj.setFillColor(sev_c)
    canvas_obj.setStrokeColor(C_GOLD)
    canvas_obj.setLineWidth(1)
    canvas_obj.roundRect(bx, by, bw, bh, 4, fill=1, stroke=1)
    canvas_obj.setFillColor(C_WHITE)
    canvas_obj.setFont("Helvetica-Bold", 11)
    canvas_obj.drawCentredString(w/2, by + 0.52*cm,
        f"CVE RISK REASSESSMENT   {cve_severity.upper()} SEVERITY")

    canvas_obj.setFillColor(C_WHITE)
    canvas_obj.setFont("Helvetica-Bold", 34)
    canvas_obj.drawCentredString(w/2, h - 9.6*cm, "D-TARA Reassessment")
    canvas_obj.setFillColor(C_GOLD)
    canvas_obj.setFont("Helvetica-Bold", 16)
    canvas_obj.drawCentredString(w/2, h - 11.2*cm, "CVE-Driven Risk Delta Report")
    canvas_obj.setFillColor(HexColor("#A8C1D0"))
    canvas_obj.setFont("Helvetica", 11)
    canvas_obj.drawCentredString(w/2, h - 12.2*cm, "ISO/SAE 21434:2021   UN R155 Compliant")
    canvas_obj.setStrokeColor(C_GOLD)
    canvas_obj.setLineWidth(0.7)
    canvas_obj.line(MARGIN_LEFT + 2*cm, h - 13.0*cm, w - MARGIN_RIGHT - 2*cm, h - 13.0*cm)

    canvas_obj.setFillColor(HexColor("#A8C1D0"))
    canvas_obj.setFont("Helvetica-Bold", 13)
    canvas_obj.drawCentredString(w/2, h - 13.8*cm, cve_id)
    canvas_obj.setFont("Helvetica", 10)
    canvas_obj.setFillColor(C_SLATE)
    canvas_obj.drawCentredString(w/2, h - 14.8*cm, report_date)
    canvas_obj.drawCentredString(w/2, h - 15.8*cm, _clean(item_name))

    bx2 = MARGIN_LEFT + 1*cm
    by2 = 4.0*cm
    bw2 = PAGE_W - 2*MARGIN_LEFT - 2*cm
    bh2 = 3.2*cm
    action_c = C_RED if assessor_action == "REVIEW REQUIRED" else HexColor("#1B5E20")
    canvas_obj.setFillColor(HexColor("#1A3A5C"))
    canvas_obj.setStrokeColor(C_BORDER)
    canvas_obj.setLineWidth(0.5)
    canvas_obj.roundRect(bx2, by2, bw2, bh2, 4, fill=1, stroke=1)
    canvas_obj.setFillColor(action_c)
    canvas_obj.setFont("Helvetica-Bold", 12)
    canvas_obj.drawCentredString(w/2, by2 + bh2 - 0.9*cm, f"ASSESSOR ACTION: {assessor_action}")
    canvas_obj.setFillColor(HexColor("#A8C1D0"))
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawCentredString(w/2, by2 + 0.6*cm,
        "Generated by D-TARA workflow   Confidential for Internal Use Only")

    canvas_obj.setFillColor(C_TEAL)
    canvas_obj.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(C_SLATE)
    canvas_obj.drawCentredString(w/2, 1.5*cm, "D-TARA CVE Reassessment Report   Confidential")
    canvas_obj.restoreState()


def _header_footer(canvas_obj, doc_obj, cve_id: str):
    canvas_obj.saveState()
    w, h   = doc_obj.pagesize
    ml     = doc_obj.leftMargin
    mr     = w - doc_obj.rightMargin
    top_y  = h - doc_obj.topMargin + 5
    bot_y  = doc_obj.bottomMargin - 5
    canvas_obj.setStrokeColor(C_TEAL)
    canvas_obj.setLineWidth(0.6)
    canvas_obj.line(ml, top_y, mr, top_y)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(C_SLATE)
    canvas_obj.drawString(ml, top_y + 4, f"D-TARA CVE Reassessment — {cve_id}")
    canvas_obj.drawRightString(mr, top_y + 4, "ISO/SAE 21434:2021")
    canvas_obj.setStrokeColor(C_BORDER)
    canvas_obj.setLineWidth(0.3)
    canvas_obj.line(ml, bot_y, mr, bot_y)
    canvas_obj.drawCentredString(w/2, bot_y - 11, f"Page {doc_obj.page}")
    canvas_obj.restoreState()


def _risk_delta_chart(threat_reassessment: List[Dict]) -> str:
    labels, before_vals, after_vals = [], [], []
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for tr in threat_reassessment:
        for rr in tr.get("risk_assessment", []):
            b = rr["risk_before"]["level"]
            a = rr["risk_after"]["level"]
            if b != a:
                labels.append(_trunc(tr["threat_id"], 18))
                before_vals.append(order.get(b, 1))
                after_vals.append(order.get(a, 1))

    if not labels:
        return ""

    x  = np.arange(len(labels))
    bw = 0.35
    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 1.1), 4.5), facecolor="white")
    b1 = ax.bar(x - bw/2, before_vals, bw, label="Baseline", color="#4A6070", edgecolor="white")
    b2 = ax.bar(x + bw/2, after_vals,  bw, label="Reassessed",
                color=["#C0392B" if a > b else "#1B5E20" if a < b else "#4A6070"
                       for a, b in zip(after_vals, before_vals)],
                edgecolor="white")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, rotation=15, ha="right")
    ax.set_yticks([1, 2, 3, 4])
    ax.set_yticklabels(["Low", "Medium", "High", "Critical"], fontsize=8, color="#4A6070")
    ax.set_title("Risk Delta — Baseline vs Reassessed", fontsize=11,
                 color="#0F2137", fontweight="bold", pad=10)
    ax.legend(fontsize=8, framealpha=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#D0D9E0")
    ax.spines["bottom"].set_color("#D0D9E0")
    plt.tight_layout()
    out = tempfile.mktemp(suffix="_risk_delta.png")
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out


def _feasibility_delta_chart(threat_reassessment: List[Dict]) -> str:
    order  = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Very Low": 1}
    labels, before_vals, after_vals = [], [], []
    for tr in threat_reassessment:
        b = tr.get("feasibility_before", "Low")
        a = tr.get("feasibility_after",  "Low")
        short_id = tr.get("threat_id", "")[-8:]
        labels.append(short_id)
        before_vals.append(order.get(b, 2))
        after_vals.append(order.get(a, 2))

    if not labels:
        return ""

    x  = np.arange(len(labels))
    bw = 0.35
    fig, ax = plt.subplots(figsize=(max(7, len(labels) * 1.2), 4.5), facecolor="white")
    bars_b = ax.bar(x - bw/2, before_vals, bw, label="Baseline",   color="#4A6070", edgecolor="white", alpha=0.85)
    bar_colors = ["#C0392B" if a > b else "#1B5E20" if a < b else "#1A7F8E"
                  for a, b in zip(after_vals, before_vals)]
    bars_a = ax.bar(x + bw/2, after_vals,  bw, label="Reassessed", color=bar_colors, edgecolor="white", alpha=0.9)

    for bar, bv, av in zip(bars_a, before_vals, after_vals):
        if av > bv:
            ax.annotate("▲", xy=(bar.get_x() + bar.get_width()/2, av + 0.05),
                        ha="center", va="bottom", fontsize=9, color="#C0392B")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7, rotation=20, ha="right")
    ax.set_yticks([1, 2, 3, 4, 5])
    ax.set_yticklabels(["Very Low", "Low", "Medium", "High", "Critical"],
                       fontsize=8, color="#4A6070")
    ax.set_ylim(0, 5.8)
    ax.set_title("Attack Feasibility Delta — Baseline vs Reassessed", fontsize=11,
                 color="#0F2137", fontweight="bold", pad=10)
    ax.legend(fontsize=8, framealpha=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#D0D9E0")
    ax.spines["bottom"].set_color("#D0D9E0")
    plt.tight_layout()
    out = tempfile.mktemp(suffix="_feasibility_delta.png")
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out


LLM_CACHE_FILE = "llm_reassessment_cache.json"

_REASSESSMENT_SYSTEM = """\
You are a senior automotive cybersecurity engineer writing a formal CVE-driven risk reassessment report
compliant with ISO/SAE 21434:2021. Explain concisely why the risk or feasibility changed for the given
threat scenario given the CVE data. Focus on the specific technical mechanism.

STRICT RULES:
1. Formal third-person voice. 2-3 sentences maximum.
2. Explain the causal chain: CVE characteristic → attack factor affected → feasibility/risk change.
3. If risk did NOT change, explain why the CVE had limited impact despite matching the component.
4. BANNED: "thereby", "it is important to note", "in this scenario", "this action compromises".
5. Output ONLY the explanation text. No preamble.\
"""


def _load_llm_cache() -> Dict:
    if os.path.exists(LLM_CACHE_FILE):
        try:
            with open(LLM_CACHE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_llm_cache(cache: Dict):
    try:
        with open(LLM_CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def _llm_explain(prompt: str, cache: Dict, client, no_llm: bool) -> str:
    if no_llm or not client:
        return ""
    import hashlib
    key = hashlib.sha256(prompt.encode()).hexdigest()
    if key in cache:
        return cache[key]
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _REASSESSMENT_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            max_tokens=200,
            temperature=0.3,
        )
        result = resp.choices[0].message.content.strip()
        cache[key] = result
        return result
    except Exception as e:
        print(f"    [LLM] {e}")
        return ""


def _build_llm_prompt(cve_id: str, cve_desc: str, cvss_vector: str,
                      threat: Dict, signal_mapping: Dict) -> str:
    factors = []
    for factor, info in signal_mapping.items():
        factors.append(f"  {factor}: value={info['value']}, weight={info['weight']}, source={info['source']}")
    factor_str = "\n".join(factors)

    ra = threat.get("risk_assessment", [{}])[0]
    risk_before = ra.get("risk_before", {}).get("level", "N/A")
    risk_after  = ra.get("risk_after", {}).get("level", "N/A")

    return (
        f"CVE: {cve_id}\n"
        f"Description: {cve_desc[:300]}\n"
        f"CVSS Vector: {cvss_vector}\n"
        f"CVE Signal Factors:\n{factor_str}\n\n"
        f"Threat Scenario: {threat.get('title', '')}\n"
        f"Feasibility before: {threat.get('feasibility_before', 'N/A')}\n"
        f"Feasibility after: {threat.get('feasibility_after', 'N/A')}\n"
        f"Feasibility changed: {threat.get('feasibility_changed', False)}\n"
        f"Paths changed: {threat.get('paths_changed', 0)} of {threat.get('paths_total', 0)}\n"
        f"Risk before: {risk_before}\n"
        f"Risk after: {risk_after}\n"
        f"A-norm max before: {threat.get('a_norm_max_before', 0):.4f}\n"
        f"A-norm max after: {threat.get('a_norm_max_after', 0):.4f}\n"
    )


def section_toc(S) -> List:
    story = []
    story.append(Paragraph("Table of Contents", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.4*cm))
    entries = [
        ("ES",   "Executive Summary"),
        ("1",    "CVE Analysis"),
        ("1.1",  "CVE Details"),
        ("1.2",  "CVSS Attack Factor Mapping"),
        ("2",    "Impact Traceability"),
        ("2.1",  "Impacted Components and Assets"),
        ("2.2",  "Impacted Attack Trees"),
        ("3",    "Threat Scenario Reassessment"),
        ("3.1",  "Feasibility Delta"),
        ("3.2",  "Risk Delta Analysis"),
        ("3.3",  "Per-Threat Detail"),
        ("4",    "Attack Path Analysis"),
        ("5",    "Cybersecurity Goal Impact"),
        ("6",    "Assessor Decision Summary"),
    ]
    for num, title in entries:
        is_top  = "." not in num
        style   = S["toc_h1"] if is_top else S["toc_entry"]
        indent  = 0 if is_top else 1.0*cm
        story.append(Paragraph(
            f'<font name="Helvetica-Bold">{num}</font>   {_esc(title)}',
            ParagraphStyle("toc_i", parent=style, leftIndent=indent)
        ))
    story.append(PageBreak())
    return story


def section_executive_summary(report: Dict, S) -> List:
    story = []
    story.append(Paragraph("Executive Summary", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.3*cm))

    cve       = report.get("cve", {})
    verdict   = report.get("verdict", {})
    summary   = report.get("summary", {})
    trace     = report.get("traceability", {})
    cve_id    = cve.get("cve_id", "N/A")
    sev       = cve.get("cvss_severity", "N/A").upper()
    action    = summary.get("assessor_action", "N/A")
    action_c  = "#C0392B" if action == "REVIEW REQUIRED" else "#1B5E20"

    escalated = summary.get("escalated_risks", [])
    n_ts      = len(trace.get("impacted_threats", []))
    n_assets  = len(trace.get("impacted_assets", []))
    n_ap      = trace.get("impacted_attack_paths_count", 0)
    n_trees   = len(trace.get("impacted_attack_trees", []))
    n_ecus    = len(verdict.get("impacted_ecus", []))

    metrics = [
        ("CVE Identifier",            cve_id),
        ("CVSS Score / Severity",     f"{cve.get('cvss_score', 'N/A')} / {sev}"),
        ("Matched Technologies",      _fmt_list(verdict.get("matched_technologies", []))),
        ("Impacted ECUs",             str(n_ecus)),
        ("Impacted Assets",           str(n_assets)),
        ("Impacted Threat Scenarios", str(n_ts)),
        ("Impacted Attack Paths",     str(n_ap)),
        ("Impacted Attack Trees",     str(n_trees)),
        ("Assessor Action",           Paragraph(
            f'<font color="{action_c}"><b>{_esc(action)}</b></font>', S["body"])),
    ]
    story.append(info_table(metrics))
    story.append(Spacer(1, 0.4*cm))

    if escalated:
        story.append(Paragraph("Escalated Risks", S["subsection"]))
        rows = [["Risk ID", "Threat ID", "Baseline Risk", "Reassessed Risk"]]
        for er in escalated:
            b_lbl = er.get("before", "N/A").split(" ")[0]
            a_lbl = er.get("after",  "N/A").split(" ")[0]
            rows.append([
                _clean(er.get("risk_id", "")),
                _clean(er.get("threat_id", "")),
                Paragraph(f'<font color="{_risk_hex(b_lbl)}"><b>{_esc(b_lbl)}</b></font>', S["td"]),
                Paragraph(f'<font color="{_risk_hex(a_lbl)}"><b>{_esc(a_lbl)}</b></font>', S["td"]),
            ])
        story.append(styled_table(rows, col_widths=[2.5*cm, 4.0*cm, (CONTENT_W-6.5*cm)/2, (CONTENT_W-6.5*cm)/2]))
    else:
        story.append(Paragraph(
            "No risk escalations were identified for this CVE. The matched vulnerability affects "
            f"{n_ts} threat scenario(s) and {n_ap} attack path(s) but does not cross a risk "
            "threshold boundary under current feasibility parameters. The feasibility scores of "
            "affected paths have been updated and are detailed in Section 3.",
            S["body"]
        ))

    story.append(PageBreak())
    return story


def section_cve_analysis(report: Dict, S) -> List:
    story = []
    story.append(Paragraph("1   CVE Analysis", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.3*cm))

    cve    = report.get("cve", {})
    signal = report.get("cve_signal", {})
    cve_id = cve.get("cve_id", "N/A")
    sev    = cve.get("cvss_severity", "N/A").upper()

    story.append(Paragraph("1.1 CVE Details", S["subsection"]))
    rows = [
        ("CVE Identifier",   cve_id),
        ("CVSS Score",       str(cve.get("cvss_score", "N/A"))),
        ("Severity",         Paragraph(
            f'<font color="{_sev_hex(sev)}"><b>{_esc(sev)}</b></font>', S["body"])),
        ("Published",        str(cve.get("published", "N/A"))[:10]),
        ("Affected Products", _fmt_list(cve.get("products", []))),
        ("Vendors",          _fmt_list(cve.get("vendors", []))),
        ("CVSS Vector",      str(signal.get("cvss_vector", "N/A"))),
        ("Description",      _trunc(cve.get("description", ""), 400)),
    ]
    story.append(info_table(rows))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("1.2 CVSS Attack Factor Mapping", S["subsection"]))
    story.append(Paragraph(
        "The CVSS vector is mapped to ISO/SAE 21434 attack feasibility factors. "
        "Each factor influences the normalised attack feasibility score (A-norm) "
        "of impacted attack paths according to its weight and the CVE-derived value.",
        S["body"]
    ))
    story.append(Spacer(1, 0.2*cm))

    mapping = signal.get("mapping", {})
    factor_rows = [["Factor", "CVE-Derived Value", "Weight", "CVSS Source", "Description"]]
    factor_desc = {
        "SE":   "Specialist Expertise required",
        "KoIC": "Knowledge of Item or Component",
        "WoO":  "Window of Opportunity",
        "Eq":   "Equipment / Tooling required",
    }
    for factor, info in mapping.items():
        factor_rows.append([
            factor,
            str(info.get("value", "N/A")),
            str(info.get("weight", "N/A")),
            str(info.get("source", "N/A")),
            factor_desc.get(factor, ""),
        ])
    story.append(styled_table(factor_rows,
        col_widths=[1.8*cm, 2.8*cm, 1.8*cm, 3.5*cm, CONTENT_W - 9.9*cm]))

    story.append(PageBreak())
    return story


def section_impact_traceability(report: Dict, S) -> List:
    story = []
    story.append(Paragraph("2   Impact Traceability", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.3*cm))

    verdict = report.get("verdict", {})
    trace   = report.get("traceability", {})

    story.append(Paragraph("2.1 Impacted Components and Assets", S["subsection"]))
    story.append(Paragraph(
        "The following ECUs, assets, and threat scenarios were identified as impacted through "
        "technology matching between the CVE affected product list and the vehicle architecture.",
        S["body"]
    ))
    story.append(Spacer(1, 0.2*cm))

    ecus = verdict.get("impacted_ecus", [])
    techs = verdict.get("matched_technologies", [])
    ecu_rows = [["Impacted ECU", "Matched Technology"]]
    for ecu in ecus:
        ecu_rows.append([_clean(ecu), _fmt_list(techs)])
    story.append(styled_table(ecu_rows, col_widths=[5.0*cm, CONTENT_W - 5.0*cm]))
    story.append(Spacer(1, 0.3*cm))

    assets = trace.get("impacted_assets", [])
    if assets:
        asset_rows = [["Asset ID", "Asset Name", "Matched ECUs"]]
        for a in assets:
            asset_rows.append([
                _trunc(a.get("asset_id", ""), 20),
                _clean(a.get("name", "")),
                _fmt_list(a.get("matched_ecus", [])),
            ])
        story.append(styled_table(asset_rows,
            col_widths=[3.5*cm, 5.0*cm, CONTENT_W - 8.5*cm]))
        story.append(Spacer(1, 0.3*cm))

    threats = trace.get("impacted_threats", [])
    if threats:
        story.append(Paragraph("Impacted Threat Scenarios", S["subsection"]))
        ts_rows = [["Threat ID", "Title"]]
        for t in threats:
            ts_rows.append([
                _clean(t.get("threat_id", "")),
                _trunc(t.get("title", ""), 80),
            ])
        story.append(styled_table(ts_rows, col_widths=[3.5*cm, CONTENT_W - 3.5*cm]))
        story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("2.2 Impacted Attack Trees", S["subsection"]))
    at_trees = trace.get("impacted_attack_trees", [])
    if at_trees:
        ds_to_trees: Dict[str, Dict] = {}
        for t in at_trees:
            ds_id = t.get("damage_scenario_id", "")
            if ds_id not in ds_to_trees:
                ds_to_trees[ds_id] = {
                    "title":    t.get("damage_scenario_title", ""),
                    "tree_ids": [],
                    "threats":  set(),
                }
            ds_to_trees[ds_id]["tree_ids"].append(t.get("tree_id", ""))
            ds_to_trees[ds_id]["threats"].update(t.get("matched_threat_ids", []))

        tree_rows = [["Damage Scenario", "Attack Trees"]]
        for ds_id, info in ds_to_trees.items():
            tree_rows.append([
                Paragraph(_esc(_clean(info["title"])), S["td"]),
                _fmt_list(sorted(info["tree_ids"])),
            ])
        story.append(styled_table(tree_rows,
            col_widths=[CONTENT_W - 4.0*cm, 4.0*cm]))
    else:
        story.append(Paragraph("No attack trees impacted.", S["body_small"]))

    story.append(PageBreak())
    return story


def section_threat_reassessment(report: Dict, llm_explanations: Dict, S) -> List:
    story = []
    story.append(Paragraph("3   Threat Scenario Reassessment", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.3*cm))

    threat_reassessment = report.get("threat_reassessment", [])
    cve_id = report.get("cve", {}).get("cve_id", "N/A")

    story.append(Paragraph("3.1 Feasibility Delta", S["subsection"]))
    story.append(Paragraph(
        "Attack feasibility is the primary mechanism through which a CVE affects risk. "
        "The table below shows the change in feasibility rating and normalised A-norm score "
        "for each impacted threat scenario.",
        S["body"]
    ))
    story.append(Spacer(1, 0.2*cm))

    feas_rows = [["Threat ID", "Feasibility Before", "Feasibility After",
                  "A-norm Before", "A-norm After"]]
    for tr in threat_reassessment:
        fb = tr.get("feasibility_before", "N/A")
        fa = tr.get("feasibility_after",  "N/A")
        changed = tr.get("feasibility_changed", False)
        symbol  = "▲" if changed else "="
        col_b   = _risk_hex(fb)
        col_a   = "#C0392B" if changed else _risk_hex(fa)
        feas_rows.append([
            _clean(tr.get("threat_id", "")),
            Paragraph(f'<font color="{col_b}"><b>{_esc(fb)}</b></font>', S["td"]),
            Paragraph(f'<font color="{col_a}"><b>{_esc(fa)} {symbol}</b></font>', S["td"]),
            f"{tr.get('a_norm_max_before', 0):.4f}",
            f"{tr.get('a_norm_max_after', 0):.4f}",
        ])
    story.append(styled_table(feas_rows,
        col_widths=[3.5*cm, 3.2*cm, 3.2*cm, CONTENT_W/2 - 5.0*cm, CONTENT_W/2 - 5.0*cm]))

    feas_chart = _feasibility_delta_chart(threat_reassessment)
    if feas_chart and os.path.exists(feas_chart):
        story.append(Spacer(1, 0.3*cm))
        img = Image(feas_chart, width=CONTENT_W * 0.9, height=CONTENT_W * 0.36)
        img.hAlign = "CENTER"
        story.append(img)
        story.append(Paragraph(
            "Figure 3.1: Attack feasibility comparison. Red bars indicate increased feasibility; "
            "green bars indicate decreased feasibility after CVE correlation.",
            S["note"]
        ))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("3.2 Risk Delta Analysis", S["subsection"]))
    story.append(Paragraph(
        "The following table summarises the risk level before and after CVE-driven "
        "feasibility reassessment. Risk escalations are highlighted in red.",
        S["body"]
    ))
    story.append(Spacer(1, 0.2*cm))

    risk_rows = [["Threat ID", "Risk ID", "DS", "Impact",
                  "Risk Before", "Risk After"]]
    any_escalated = False
    for tr in threat_reassessment:
        tid = tr.get("threat_id", "")
        for rr in tr.get("risk_assessment", []):
            rb    = rr["risk_before"]["level"]
            ra    = rr["risk_after"]["level"]
            if rr.get("escalated"):
                any_escalated = True
            risk_rows.append([
                _clean(tid),
                _clean(rr.get("risk_id", "")),
                _trunc(rr.get("damage_scenario_id", ""), 18),
                _clean(rr.get("impact_rating", "")),
                Paragraph(f'<font color="{_risk_hex(rb)}"><b>{_esc(rb)}</b></font>', S["td"]),
                Paragraph(f'<font color="{_risk_hex(ra)}"><b>{_esc(ra)}</b></font>', S["td"]),
            ])
    story.append(styled_table(risk_rows,
        col_widths=[3.0*cm, 1.8*cm, 3.2*cm, 2.0*cm, (CONTENT_W - 10.0*cm)/2, (CONTENT_W - 10.0*cm)/2]))

    risk_chart = _risk_delta_chart(threat_reassessment)
    if risk_chart and os.path.exists(risk_chart):
        story.append(Spacer(1, 0.3*cm))
        img = Image(risk_chart, width=CONTENT_W * 0.9, height=CONTENT_W * 0.36)
        img.hAlign = "CENTER"
        story.append(Paragraph(
            "Figure 3.2: Risk level comparison baseline vs reassessed. "
            "Red = escalated, green = reduced, grey = unchanged.",
            S["note"]
        ))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("3.3 Per-Threat Detail", S["subsection"]))
    story.append(Paragraph(
        "Each impacted threat scenario is detailed below with full feasibility factor "
        "provenance, changed attack paths, and assessor-facing risk rationale.",
        S["body"]
    ))
    story.append(Spacer(1, 0.3*cm))

    for tr in threat_reassessment:
        tid   = tr.get("threat_id", "")
        title = tr.get("title", "")
        fb    = tr.get("feasibility_before", "N/A")
        fa    = tr.get("feasibility_after",  "N/A")

        elements = []
        elements.append(card_header(C_NAVY_MID, tid, _clean(title)))

        ra_list = tr.get("risk_assessment", [{}])
        ra = ra_list[0] if ra_list else {}
        rb_level = ra.get("risk_before", {}).get("level", "N/A")
        ra_level = ra.get("risk_after", {}).get("level", "N/A")

        detail_rows = [
            ("Feasibility Before",
             Paragraph(f'<font color="{_risk_hex(fb)}"><b>{_esc(fb)}</b></font>', S["body"])),
            ("Feasibility After",
             Paragraph(f'<font color="{_risk_hex(fa)}"><b>{_esc(fa)}</b></font>', S["body"])),
            ("A-norm Before / After",
             f"{tr.get('a_norm_max_before', 0):.4f}  →  {tr.get('a_norm_max_after', 0):.4f}"),
            ("Risk Before",
             Paragraph(f'<font color="{_risk_hex(rb_level)}"><b>{_esc(rb_level)}</b></font>',
                       S["body"])),
            ("Risk After",
             Paragraph(f'<font color="{_risk_hex(ra_level)}"><b>{_esc(ra_level)}</b></font>',
                       S["body"])),
            ("Paths Changed",
             f"{tr.get('paths_changed', 0)} of {tr.get('paths_total', 0)} attack paths"),
        ]
        elements.append(info_table(detail_rows))

        explanation = llm_explanations.get(tid, "")
        if explanation:
            elements.append(Spacer(1, 0.15*cm))
            elements.append(Paragraph(
                f'<b>Risk Rationale ({cve_id}):</b> {_esc(explanation)}', S["body"]))

        path_detail = tr.get("path_detail", [])
        if path_detail:
            elements.append(Spacer(1, 0.15*cm))
            elements.append(Paragraph("<b>Changed Attack Paths </b>", S["body_small"]))
            pd_rows = [["Path ID", "Factor", "Before", "After", "CVE Signal",
                        "A-norm Before", "A-norm After"]]
            for pd in path_detail[:5]:
                first = True
                for factor, fdata in pd.get("factors_changed", {}).items():
                    pd_rows.append([
                        _clean(pd.get("path_id", "")) if first else "",
                        factor,
                        str(fdata.get("before", "")),
                        str(fdata.get("after",  "")),
                        str(fdata.get("cve_signal", "")),
                        f"{pd.get('a_norm_before', 0):.4f}" if first else "",
                        f"{pd.get('a_norm_after',  0):.4f}" if first else "",
                    ])
                    first = False
            elements.append(styled_table(pd_rows,
                col_widths=[2.0*cm, 1.5*cm, 1.5*cm, 1.5*cm, 2.0*cm, 2.5*cm, CONTENT_W - 11.0*cm]))

        elements.append(Spacer(1, 0.2*cm))
        elements.append(thin_divider())
        elements.append(Spacer(1, 0.2*cm))
        story.append(KeepTogether(elements))

    story.append(PageBreak())
    return story


def section_attack_paths(report: Dict, S) -> List:
    story = []
    story.append(Paragraph("4   Attack Path Analysis", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "The following table summarises the attack paths whose normalised feasibility score "
        "changed due to CVE correlation. Paths that crossed a rating boundary are highlighted. "
        "All other path parameters (entry point, target ECU, STRIDE sequence) remain unchanged.",
        S["body"]
    ))
    story.append(Spacer(1, 0.3*cm))

    all_paths: Dict[str, Dict] = {}
    for tr in report.get("threat_reassessment", []):
        tid = tr.get("threat_id", "")
        for pd in tr.get("path_detail", []):
            pid = pd.get("path_id", "")
            if pid not in all_paths:
                all_paths[pid] = dict(pd)
                all_paths[pid]["threat_id"] = tid
            else:
                all_paths[pid]["threat_id"] += f", {tid}"

    if not all_paths:
        story.append(Paragraph(
            "No individual attack path detail is available in this report. "
            f"Total impacted paths: "
            f"{report.get('traceability', {}).get('impacted_attack_paths_count', 0)}.",
            S["body_small"]
        ))
        story.append(PageBreak())
        return story

    rows = [["Path ID", "Linked Threats", "Rating Before", "Rating After",
             "A-norm Before", "A-norm After", "Boundary Crossed"]]
    for pid, pd in sorted(all_paths.items()):
        rb   = pd.get("rating_before", "N/A")
        ra_v = pd.get("rating_after",  "N/A")
        crossed = rb != ra_v
        cross_str = "YES" if crossed else "No"
        cross_col = "#C0392B" if crossed else "#4A6070"
        rows.append([
            _clean(pid),
            Paragraph(_esc(_trunc(pd.get("threat_id", ""), 60)), S["td"]),
            Paragraph(f'<font color="{_risk_hex(rb)}"><b>{_esc(rb)}</b></font>', S["td"]),
            Paragraph(f'<font color="{_risk_hex(ra_v)}"><b>{_esc(ra_v)}</b></font>', S["td"]),
            f"{pd.get('a_norm_before', 0):.4f}",
            f"{pd.get('a_norm_after',  0):.4f}",
            Paragraph(f'<font color="{cross_col}"><b>{cross_str}</b></font>', S["td"]),
        ])
    story.append(styled_table(rows,
        col_widths=[1.8*cm, 5.0*cm, 2.2*cm, 2.2*cm, 2.0*cm, 2.0*cm, CONTENT_W - 15.2*cm]))

    story.append(PageBreak())
    return story


def section_goal_impact(report: Dict, S) -> List:
    story = []
    story.append(Paragraph("5   Cybersecurity Goal Impact", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Cybersecurity goals are reviewed against the reassessed threat scenarios. A goal is "
        "considered potentially insufficient if any of its covered threat scenarios show an "
        "increase in feasibility or risk after CVE correlation. Goals covering no impacted "
        "threats remain adequate under this reassessment.",
        S["body"]
    ))
    story.append(Spacer(1, 0.3*cm))

    impacted_ts = {t["threat_id"] for t in
                   report.get("traceability", {}).get("impacted_threats", [])}
    escalated_ts = {
        er.get("threat_id", "")
        for er in report.get("summary", {}).get("escalated_risks", [])
    }
    feas_changed_ts = {
        tr["threat_id"]
        for tr in report.get("threat_reassessment", [])
        if tr.get("feasibility_changed")
    }

    if not impacted_ts:
        story.append(Paragraph("No cybersecurity goal impact identified.", S["body_small"]))
        story.append(PageBreak())
        return story

    rows = [["Threat Scenario", "Feasibility Changed", "Risk Escalated", "Goal Review Status"]]
    for tid in sorted(impacted_ts):
        fc  = tid in feas_changed_ts
        esc = tid in escalated_ts
        if esc:
            status = "ADDITIONAL CONTROLS REQUIRED"
            scol   = "#C0392B"
        elif fc:
            status = "REVIEW RECOMMENDED"
            scol   = "#E65100"
        else:
            status = "ADEQUATE — MONITOR"
            scol   = "#1B5E20"
        rows.append([
            _clean(tid),
            Paragraph(f'<font color="{"#C0392B" if fc else "#1B5E20"}"><b>{"Yes" if fc else "No"}</b></font>', S["td"]),
            Paragraph(f'<font color="{"#C0392B" if esc else "#1B5E20"}"><b>{"Yes" if esc else "No"}</b></font>', S["td"]),
            Paragraph(f'<font color="{scol}"><b>{_esc(status)}</b></font>', S["td"]),
        ])
    story.append(styled_table(rows,
        col_widths=[3.5*cm, 3.0*cm, 2.5*cm, CONTENT_W - 9.0*cm]))

    story.append(PageBreak())
    return story


def section_assessor_decision(report: Dict, S) -> List:
    story = []
    story.append(Paragraph("6   Assessor Decision Summary", S["section"]))
    story.append(divider())
    story.append(Spacer(1, 0.3*cm))

    summary = report.get("summary", {})
    verdict = report.get("verdict", {})
    action  = summary.get("assessor_action", "N/A")
    action_c = "#C0392B" if action == "REVIEW REQUIRED" else "#1B5E20"
    cve_id  = report.get("cve", {}).get("cve_id", "N/A")

    story.append(Paragraph(
        f'<font color="{action_c}"><b>ASSESSOR ACTION: {_esc(action)}</b></font>',
        S["section"]
    ))
    story.append(Spacer(1, 0.3*cm))

    escalated = summary.get("escalated_risks", [])
    if escalated:
        story.append(Paragraph(
            f"{len(escalated)} risk escalation(s) were identified. The following threat scenarios "
            "require immediate assessor review and potential update of cybersecurity goals or "
            "security controls:",
            S["body"]
        ))
        story.append(Spacer(1, 0.2*cm))
        esc_rows = [["Risk ID", "Threat ID", "Baseline", "Reassessed"]]
        for er in escalated:
            b_lbl = er.get("before", "N/A").split(" ")[0]
            a_lbl = er.get("after",  "N/A").split(" ")[0]
            esc_rows.append([
                _clean(er.get("risk_id", "")),
                _clean(er.get("threat_id", "")),
                Paragraph(f'<font color="{_risk_hex(b_lbl)}"><b>{_esc(b_lbl)}</b></font>', S["td"]),
                Paragraph(f'<font color="{_risk_hex(a_lbl)}"><b>{_esc(a_lbl)}</b></font>', S["td"]),
            ])
        story.append(styled_table(esc_rows,
            col_widths=[2.5*cm, 4.0*cm, (CONTENT_W-6.5*cm)/2, (CONTENT_W-6.5*cm)/2]))
    else:
        story.append(Paragraph(
            f"{cve_id} matched {len(verdict.get('impacted_ecus', []))} ECU(s) and affected "
            f"{verdict.get('threats_total', 0)} threat scenario(s). No risk threshold was crossed. "
            "Feasibility scores were updated and are preserved in this report for traceability. "
            "No immediate action is required. The baseline TARA report remains valid.",
            S["body"]
        ))

    story.append(Spacer(1, 0.5*cm))
    decision_rows = [
        ("CVE",                    cve_id),
        ("Architecture Impacted",  "Yes" if verdict.get("architecture_impacted") else "No"),
        ("Threats Total",          str(verdict.get("threats_total", 0))),
        ("Feasibility Changes",    str(verdict.get("threats_feasibility_changed", 0))),
        ("Assessor Action",        Paragraph(
            f'<font color="{action_c}"><b>{_esc(action)}</b></font>', S["body"])),
        ("Report Date",            datetime.now().strftime("%d %B %Y, %H:%M:%S")),
        ("Baseline Report",        "DTARA_Baseline_Report.pdf ,unchanged"),
    ]
    story.append(info_table(decision_rows))
    return story


def run_llm_explanations(report: Dict, client, no_llm: bool) -> Dict:
    cache = _load_llm_cache()
    explanations: Dict[str, str] = {}
    cve    = report.get("cve", {})
    signal = report.get("cve_signal", {})
    cve_id = cve.get("cve_id", "")
    cve_desc   = cve.get("description", "")
    cvss_vector = signal.get("cvss_vector", "")
    mapping    = signal.get("mapping", {})

    total = len(report.get("threat_reassessment", []))
    for i, tr in enumerate(report.get("threat_reassessment", []), 1):
        tid = tr.get("threat_id", "")
        print(f"    LLM [{i}/{total}] {tid}", end="\r")
        prompt = _build_llm_prompt(cve_id, cve_desc, cvss_vector, tr, mapping)
        explanations[tid] = _llm_explain(prompt, cache, client, no_llm)

    print()
    _save_llm_cache(cache)
    return explanations


def generate_reassessment_pdf(report: Dict, output_path: str,
                               openai_key: str = "", no_llm: bool = False):
    print(f"  Generating reassessment PDF: {output_path}")
    S = build_styles()

    cve       = report.get("cve", {})
    summary   = report.get("summary", {})
    cve_id    = cve.get("cve_id", "N/A")
    sev       = cve.get("cvss_severity", "N/A")
    action    = summary.get("assessor_action", "NO ESCALATION")
    report_dt = datetime.now().strftime("%d %B %Y, %H:%M:%S")
    item_name = "Vehicle Safety Item"

    client = None
    if not no_llm and HAS_OPENAI and openai_key:
        client = OpenAI(api_key=openai_key)

    print("    Running LLM explanations...")
    llm_explanations = run_llm_explanations(report, client, no_llm)

    doc = BaseDocTemplate(
        output_path, pagesize=A4,
        topMargin=MARGIN_TOP + 1.0*cm,
        bottomMargin=MARGIN_BOTTOM + 0.8*cm,
        leftMargin=MARGIN_LEFT,
        rightMargin=MARGIN_RIGHT,
    )
    cover_frame = Frame(0, 0, PAGE_W, PAGE_H, id="cover", showBoundary=0,
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body_frame  = Frame(MARGIN_LEFT, MARGIN_BOTTOM + 0.5*cm,
                        CONTENT_W, PAGE_H - MARGIN_TOP - MARGIN_BOTTOM - 1.2*cm,
                        id="body", showBoundary=0)

    def on_cover(c, d):
        _cover_page(c, d, cve_id, sev, report_dt, item_name, action)

    def on_later(c, d):
        _header_footer(c, d, cve_id)

    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=on_cover, pagesize=A4),
        PageTemplate(id="body",  frames=[body_frame],  onPage=on_later, pagesize=A4),
    ])

    story = []
    story.append(Spacer(1, PAGE_H))
    story.append(NextPageTemplate("body"))
    story.append(PageBreak())

    print("    TOC", end=" ")
    story += section_toc(S); print("done")
    print("    Exec Summary", end=" ")
    story += section_executive_summary(report, S); print("done")
    print("    Sec 1 CVE Analysis", end=" ")
    story += section_cve_analysis(report, S); print("done")
    print("    Sec 2 Impact Traceability", end=" ")
    story += section_impact_traceability(report, S); print("done")
    print("    Sec 3 Threat Reassessment", end=" ")
    story += section_threat_reassessment(report, llm_explanations, S); print("done")
    print("    Sec 4 Attack Paths", end=" ")
    story += section_attack_paths(report, S); print("done")
    print("    Sec 5 Goal Impact", end=" ")
    story += section_goal_impact(report, S); print("done")
    print("    Sec 6 Assessor Decision", end=" ")
    story += section_assessor_decision(report, S); print("done")

    doc.build(story)
    print(f"  PDF written: {output_path}")


def parse_args():
    p = argparse.ArgumentParser(description="D-TARA CVE Reassessment Report Generator")
    p.add_argument("report_json", help="Path to the CVE dtara_report.json file")
    p.add_argument("--output",     default=None,
                   help="Output PDF path (default: derived from CVE ID)")
    p.add_argument("--openai_key", default=os.environ.get("OPENAI_API_KEY", ""))
    p.add_argument("--no_llm",     action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    report_path = Path(args.report_json)
    if not report_path.exists():
        print(f"[ERROR] Report JSON not found: {report_path}")
        sys.exit(1)

    report = json.loads(report_path.read_text(encoding="utf-8"))

    if not report.get("verdict", {}).get("architecture_impacted"):
        print(f"[INFO] {report.get('cve', {}).get('cve_id', '?')} — no architecture impact. "
              "No reassessment PDF generated.")
        sys.exit(0)

    cve_id = report.get("cve", {}).get("cve_id", "UNKNOWN")
    output = args.output or str(
        report_path.parent / f"DTARA_CVE_Reassessment_{cve_id.replace('-', '_')}.pdf"
    )

    generate_reassessment_pdf(
        report      = report,
        output_path = output,
        openai_key  = args.openai_key,
        no_llm      = args.no_llm,
    )


if __name__ == "__main__":
    main()