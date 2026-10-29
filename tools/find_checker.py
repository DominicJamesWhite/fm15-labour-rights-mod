"""Watches a running FM15 for code that reads its own .text as data (the tamper checker).

Usage: python find_checker.py [minutes, default 60] [report, default reports/checker/findings.txt]
"""

import json
import pathlib
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(argv):
    minutes = float(argv[1]) if len(argv) > 1 else 60
    out = pathlib.Path(argv[2]) if len(argv) > 2 else ROOT / "reports" / "checker" / "findings.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    find = lambda: next((p.pid for p in frida.get_local_device().enumerate_processes()
                         if p.name.lower() == "fm.exe"), None)
    pid = find()
    if pid is None:
        print("waiting for fm.exe to start...", flush=True)
        while pid is None:
            time.sleep(0.2)
            pid = find()

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print(f"watching {payload['ready']} code pages", flush=True)
            return
        readers = sorted(payload["readers"].items(), key=lambda kv: -kv[1]["pages"])
        lines = [time.strftime("%H:%M:%S") + f"  watched pages: {payload['watched']}, "
                 f"execute hits ignored: {payload['executes']}", ""]
        for va, r in readers:
            flag = "  <-- reads many code pages: likely the checker" if r["pages"] >= 10 else ""
            lines.append(f"{va}  {r['op']}  {r['pages']} pages{flag}")
            for bt in r["backtraces"]:
                lines.append(f"      {bt}")
        out.write_text("\n".join(lines), "utf-8")

    session = frida.attach(pid)
    script = session.create_script((pathlib.Path(__file__).parent / "find_checker.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    print(f"watching for {minutes:g} minutes; report: {out}", flush=True)
    time.sleep(minutes * 60)
    session.detach()
    print(out.read_text("utf-8") if out.exists() else "no report")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
