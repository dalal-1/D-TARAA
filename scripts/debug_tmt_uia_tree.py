from pywinauto import Application, Desktop
import time
from pathlib import Path

TMT_EXE = r"C:\Program Files (x86)\Microsoft Threat Modeling Tool 2016\TMT7.exe"

def main():
    app = Application(backend="uia").start(TMT_EXE)
    time.sleep(3)

    win = app.window(title_re=".*Threat Modeling Tool 2016.*")
    win.wait("visible", timeout=30)
    win.set_focus()
    time.sleep(1)

    lines = []
    lines.append("=== MAIN WINDOW ===")
    lines.append(win.window_text())
    lines.append("")

   
    def dump(elem, indent=0, max_depth=3):
        if indent > max_depth:
            return
        try:
            name = elem.window_text()
        except Exception:
            name = ""
        try:
            ctrl = elem.friendly_class_name()
        except Exception:
            ctrl = ""
        try:
            aid = elem.element_info.automation_id
        except Exception:
            aid = ""
        try:
            ctype = elem.element_info.control_type
        except Exception:
            ctype = ""
        lines.append(f"{'  '*indent}{ctype}/{ctrl}  name='{name}'  aid='{aid}'")
        for ch in elem.children():
            dump(ch, indent+1, max_depth)

    dump(win, 0, 4)

    Path("outputs").mkdir(exist_ok=True)
    Path("outputs/tmt_uia_tree.txt").write_text("\n".join(lines), encoding="utf-8")
    print("[+] Wrote outputs/tmt_uia_tree.txt")

if __name__ == "__main__":
    main()
