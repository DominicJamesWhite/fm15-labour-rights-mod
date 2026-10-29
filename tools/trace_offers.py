"""Attaches trace_offers.js to a running fm.exe and writes aggregated call counts to a log.

Usage: python trace_offers.py <output log> [minutes, default 20]
"""

import json
import pathlib
import sys
import time

import frida


def main(argv):
    out = pathlib.Path(argv[1])
    minutes = float(argv[2]) if len(argv) > 2 else 20
    latest = {}

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print("attached, fm.exe base", payload["ready"], flush=True)
            return
        if "sample" in payload:
            with out.with_suffix(".samples.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload["sample"]) + "\n")
            return
        latest.clear()
        latest.update(payload)
        lines = sorted(latest.items(), key=lambda kv: -kv[1]["n"])
        out.write_text("\n".join(f"{v['n']:7}  maxfee={v['maxFee']:<12} {k}" for k, v in lines), "utf-8")

    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / "trace_offers.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    time.sleep(minutes * 60)
    session.detach()
    print(f"done, {len(latest)} distinct call sites in {out}", flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
