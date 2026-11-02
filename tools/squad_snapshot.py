"""Read-only squad snapshot of clubs in a running fm.exe (nostalgia foreign-player diagnostics).

Usage: python squad_snapshot.py <output dir> "Manchester City" ["Arsenal" ...] [--minutes N]

Writes <output dir>/squads_<club>.txt per club: every player in the club's teams with nationality,
foreign (the game's type-0x15 test, relative to the club), homegrown-in-nation, value, squad status,
transfer-status flags, rest-of-contract wages, contract dates and the KEEP ranking.
The agent waits for the game to count each club's squad (happens many times a day while the game
advances), so let the game run (continue/holiday) while it waits.
"""

import pathlib
import re
import sys
import time

import frida


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    minutes = 5.0
    if "--minutes" in argv:
        minutes = float(argv[argv.index("--minutes") + 1])
        args = [a for a in args if a != argv[argv.index("--minutes") + 1]]
    out = pathlib.Path(args[0])
    clubs = args[1:]
    out.mkdir(parents=True, exist_ok=True)
    pending = set(clubs)

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
            return
        payload = message["payload"]
        if "ready" in payload:
            print("attached, fm.exe base", payload["ready"], flush=True)
        elif "debug" in payload:
            print("debug:", payload["debug"].encode("ascii", "replace").decode(), flush=True)
        elif "finished" in payload:
            print("finished; missing:", payload.get("missing"), flush=True)
            pending.clear()
        elif "club" in payload:
            name = re.sub(r"[^a-z0-9]+", "_", payload["club"].lower()).strip("_")
            path = out / f"squads_{name}.txt"
            path.write_text(payload["text"], "utf-8")
            pending.discard(payload["club"])
            print("wrote", path, flush=True)

    session = frida.attach("fm.exe")
    script = session.create_script((pathlib.Path(__file__).parent / "squad_snapshot.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    script.post({"type": "targets", "names": clubs})
    deadline = time.time() + minutes * 60
    while pending and time.time() < deadline:
        time.sleep(1)
    session.detach()
    if pending:
        print("not found (let the game advance, check the exact name):", ", ".join(sorted(pending)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
