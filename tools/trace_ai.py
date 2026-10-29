"""Attaches trace_ai.js to a running fm.exe and writes aggregated AI squad-building counts to a log.

Usage: python trace_ai.py <output log> [minutes, default 15]
"""

import pathlib
import sys
import time

import frida


def main(argv):
    out = pathlib.Path(argv[1])
    minutes = float(argv[2]) if len(argv) > 2 else 15
    latest = {}

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print("attached, fm.exe base", payload["ready"], flush=True)
            return
        latest.clear()
        latest.update(payload)
        lines = sorted(latest.items(), key=lambda kv: -kv[1]["n"])
        out.write_text(
            "\n".join(f"{v['n']:8}  max={v['max']:<11} avg={v['sum'] // max(v['n'], 1):<11} {k}" for k, v in lines),
            "utf-8",
        )

    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / "trace_ai.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    time.sleep(minutes * 60)
    session.detach()
    print(f"done, {len(latest)} distinct entries in {out}", flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
