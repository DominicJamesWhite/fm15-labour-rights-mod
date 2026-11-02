"""Attaches trace_finance.js to a running fm.exe and writes one JSON line per game day.

Usage: python trace_finance.py <output .jsonl> [minutes, default 600]
Prints a line per game day so progress through month and season boundaries is visible.
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

    def write(record):
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print("attached, fm.exe base", payload["ready"], "game date", payload["date"], flush=True)
        elif "event" in payload:
            write(payload)
        elif "day" in payload:
            write(payload)
            d = payload["day"]
            total = sum(v["n"] for v in d["agg"].values())
            print(f"{d['date']}  {total:7} calls  {len(d['agg'])} keys", flush=True)

    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / "trace_finance.js").read_text("utf-8"))
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
