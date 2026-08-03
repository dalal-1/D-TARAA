from __future__ import annotations

import argparse
import json
import os
import time
from pywinauto import Application
from pywinauto.keyboard import send_keys


# -------------------------
# Utils
# -------------------------
def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)


def sleep_short():
    time.sleep(0.5)


# -------------------------
# Launch MTMT
# -------------------------
def tmt_start(tmt_exe: str):
    if not os.path.exists(tmt_exe):
        raise FileNotFoundError(f"TMT not found: {tmt_exe}")

    print("[2] Launching MTMT...")
    app = Application(backend="win32").start(tmt_exe)

    app.wait_cpu_usage_lower(threshold=5, timeout=30)
    win = app.top_window()
    win.set_focus()

    return app, win


# -------------------------
# Popup handler
# -------------------------
def handle_error_popup(app):
    try:
        popup = app.window(title_re=".*Errors were detected.*")
        if popup.exists(timeout=3):
            print("[!] Error popup detected → clicking OK")
            popup.set_focus()

            try:
                popup.child_window(title="OK", control_type="Button").click()
            except:
                send_keys("{ENTER}")

            time.sleep(1)
    except Exception:
        pass


# -------------------------
# Open model
# -------------------------
def tmt_open_file(app, win, tm7_path: str):
    print("[3] Opening model...")
    win.set_focus()
    sleep_short()

    send_keys("%fo")  # Alt+F → Open
    sleep_short()

    dlg = win.child_window(title_re=".*Open.*", control_type="Window")
    dlg.wait("visible", timeout=15)

    try:
        edit = dlg.child_window(control_type="Edit")
        edit.set_edit_text(os.path.abspath(tm7_path))
    except Exception:
        send_keys("^l")
        send_keys(os.path.abspath(tm7_path), with_spaces=True)

    sleep_short()
    send_keys("{ENTER}")

    time.sleep(2)

    # Handle popup after loading
    handle_error_popup(app)


# -------------------------
# Analyze model
# -------------------------
def tmt_run_analyze(app, win):
    print("[4] Running STRIDE analysis...")
    win.set_focus()
    time.sleep(1)

    send_keys("{F5}")  # Analyze

    # Wait until MTMT is idle
    app.wait_cpu_usage_lower(threshold=5, timeout=120)

    # Handle popup after analysis
    handle_error_popup(app)


# -------------------------
# Export report
# -------------------------
def tmt_export_report_html(win, out_html: str):
    print("[5] Exporting STRIDE report...")
    win.set_focus()
    sleep_short()

    send_keys("%fe")  # File → Export
    sleep_short()

    send_keys("h")  # HTML
    sleep_short()

    dlg = win.child_window(title_re=".*Save.*|.*Export.*", control_type="Window")
    dlg.wait("visible", timeout=15)

    ensure_dir(os.path.dirname(out_html))

    try:
        edit = dlg.child_window(control_type="Edit")
        edit.set_edit_text(os.path.abspath(out_html))
    except Exception:
        send_keys("^l")
        send_keys(os.path.abspath(out_html), with_spaces=True)

    sleep_short()
    send_keys("{ENTER}")

    time.sleep(2)


# -------------------------
# MAIN PIPELINE
# -------------------------
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="manifest.json")
    parser.add_argument("--model", default=None)
    parser.add_argument("--out_html", default=None)
    parser.add_argument("--tmt_exe", required=True)
    args = parser.parse_args()

    print("[1] Loading config...")

    model_path = args.model
    out_html = args.out_html

    # Load manifest if exists
    if os.path.exists(args.manifest):
        manifest = read_json(args.manifest)

        if not model_path:
            model_path = manifest["architecture"]["last_tm7_model"]

        if not out_html:
            out_html = manifest["architecture"]["last_stride_report"]

    if not model_path or not os.path.exists(model_path):
        raise FileNotFoundError("TM7 model not found")

    if not out_html:
        out_html = "reports/strideeee_report.html"

    # PIPELINE
    app, win = tmt_start(args.tmt_exe)
    tmt_open_file(app, win, model_path)
    tmt_run_analyze(app, win)
    tmt_export_report_html(win, out_html)

    print(f"[✔] STRIDE report generated: {out_html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())