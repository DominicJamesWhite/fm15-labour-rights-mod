"""Attaches trace_foreign_cap.js to a running fm.exe and writes aggregated foreign-cap checks to a log.

Run it after tools/fm15_loader.py has applied the patches (it detects which of nostalgia_3_plus_2, nostalgia_foreign_cap_rules,
nostalgia_foreign_cap_ai and nostalgia_foreign_cap are present; without them it records a baseline).

Usage: python trace_foreign_cap.py <output log> [minutes, default 10]
"""

import pathlib
import sys
import time

import frida


def main(argv):
    out = pathlib.Path(argv[1])
    minutes = float(argv[2]) if len(argv) > 2 else 10

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print("attached, fm.exe base", payload["ready"], flush=True)
            return
        lines = sorted(payload.items(), key=lambda kv: -kv[1])
        out.write_text("\n".join(f"{n:7}  {k}" for k, n in lines), "utf-8")

    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / "trace_foreign_cap.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    time.sleep(minutes * 60)
    session.detach()
    print(f"done, see {out}", flush=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
