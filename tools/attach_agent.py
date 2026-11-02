"""Loads one mode agent (tools/<name>.js) into the running fm.exe and eternalizes it, as
fm15_loader.py does for its mode, without re-applying patches. For an agent that failed to load or
changed mid-session. Don't attach an agent that is already running: its hooks would run twice.

Usage: python attach_agent.py parity_agent.js
"""

import pathlib
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main(argv):
    agent = argv[1]
    log = ROOT / "reports" / f"{pathlib.Path(agent).stem}.log"
    started = []
    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / agent).read_text("utf-8"))
    script.on("message", lambda message, data: started.append(message))
    script.load()
    script.post({"type": "config", "log": str(log)})
    for _ in range(50):
        if started:
            break
        time.sleep(0.1)
    script.eternalize()
    session.detach()
    print(f"agent {agent}: {started[0].get('payload', started[0]) if started else 'no reply'} (log: {log})")
    return 0 if started else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
