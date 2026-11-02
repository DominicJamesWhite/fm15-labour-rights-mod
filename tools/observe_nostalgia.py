"""Watches a running FM15 in nostalgia mode and reports whether the transfer market, contracts and
squad rules behave as that mode intends. Writes a readable report every 15 seconds.

Usage: python observe_nostalgia.py [minutes, default 120] [report file, default reports/observer/latest.txt]

Start FM15 in nostalgia mode first (launcher, or fm15_loader.py --mode nostalgia), then run this and
go on holiday. The report says, for each check, how often it was seen and whether anything broke
the rules (FAIL lines show examples).
"""

import importlib.util
import pathlib
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parent.parent
ROLLOVER = bytes.fromhex("0fb74626")  # movzx eax,word [esi+0x26]: the cave's "add a year" step

EXPECTED = [
    "What nostalgia mode should show:",
    "- transfer windows flag stays 0, and transfers complete all year round",
    "- out-of-contract / expiring players only move with a compensation fee (> 0)",
    "- contracts roll over instead of expiring (rollover count rises around 30 June)",
    "- foreign-player rules (3+2): check real lineups in game (the rule-check counts include candidate squads)",
    "- AI clubs with more than 5 foreigners transfer-list the surplus, so that count rises over the season",
]


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render(stats, started):
    lines = [time.strftime("FM15 nostalgia observer, %H:%M:%S") + f" (watching for {(time.time() - started) / 60:.0f} min)", ""]
    for key in sorted(stats, key=lambda k: (k.startswith("activity"), k.startswith("patch"), k)):
        s = stats[key]
        if key.startswith("activity") or key.startswith("rejected") or "payout" in key:
            status = "INFO"
        else:
            status = "OK" if s["bad"] == 0 else "FAIL"
        extra = f"  (avg {s['sum'] // s['n']:,}, max {s['max']:,})" if s["sum"] or s["max"] else ""
        bad = f", {s['bad']:,} against the rules" if s["bad"] else ""
        lines.append(f"[{status:4}] {key}: {s['n']:,}{bad}{extra}")
        for example in s["examples"]:
            lines.append(f"         e.g. {example}")
    return "\n".join(lines + [""] + EXPECTED)


def main(argv):
    minutes = float(argv[1]) if len(argv) > 1 else 120
    out = pathlib.Path(argv[2]) if len(argv) > 2 else ROOT / "reports" / "observer" / "latest.txt"
    out.parent.mkdir(parents=True, exist_ok=True)

    loader = load_module(ROOT / "tools" / "fm15_loader.py")
    patcher = load_module(ROOT / "patcher" / "patch.py")
    to_va = loader.section_map(loader.ORIGINAL.read_bytes())
    patches, retain = [], None
    for name in patcher.NOSTALGIA:
        for p in patcher.PATCHES[name]:
            data = bytes.fromhex(p["patched"].replace(" ", ""))
            at = p["va"] if "va" in p else to_va(p["offset"])
            patches.append({"name": name, "va": at, "len": len(data), "patched": data.hex(" ")})
            if name == "nostalgia_retain_on_expiry" and ROLLOVER in data:
                retain = at + data.index(ROLLOVER)

    pid = loader.find_fm()
    if pid is None:
        print("fm.exe is not running; start FM15 in nostalgia mode first")
        return 1
    started = time.time()

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
        elif "stats" in message["payload"]:
            out.write_text(render(message["payload"]["stats"], started), "utf-8")
        elif "ready" in message["payload"]:
            print("attached to fm.exe", flush=True)

    session = frida.attach(pid)
    script = session.create_script((pathlib.Path(__file__).parent / "observe_nostalgia.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    script.post({"type": "start", "patches": patches, "retainCave": retain})
    print(f"observing for {minutes:g} minutes; report: {out}", flush=True)
    try:
        time.sleep(minutes * 60)
    except KeyboardInterrupt:
        pass
    session.detach()
    print(out.read_text("utf-8") if out.exists() else "no report written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
