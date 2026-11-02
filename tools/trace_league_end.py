"""Attaches trace_league_end.js (when FM marks a league finished; reports/parity/league_playoff.md
check L1) to a running fm.exe and writes one JSON line per event.

Usage: python trace_league_end.py <output .jsonl> [minutes, default 600]
"""

import json
import pathlib
import sys
import time

import frida


def main(argv):
    out = pathlib.Path(argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    minutes = float(argv[2]) if len(argv) > 2 else 600

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print("attached, fm.exe base", payload["ready"], "game date", payload["date"], flush=True)
            return
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
        e = payload["event"]
        print(f"{e['date']} {e['kind']}: {e['comp']} status {e['status']}", flush=True)

    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / "trace_league_end.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    try:
        time.sleep(minutes * 60)
    except KeyboardInterrupt:
        pass
    session.detach()
    print("done:", out, flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
