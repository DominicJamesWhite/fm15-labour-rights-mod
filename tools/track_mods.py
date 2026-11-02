"""Checks, in a running FM15, that every patch applied by fm15_loader.py is still in memory and doing
its job. Writes a readable report every 15 seconds.

Usage: python track_mods.py [minutes, default 20] [report file, default reports/tracker/latest.txt]
                            [mode, default labour; see patch.py MODES]

The behaviour checks in track_mods.js are for the labour-rights rules; in other modes only the
integrity checks (patches still in memory) apply.
"""

import importlib.util
import pathlib
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render(stats):
    lines = [time.strftime("FM15 mod tracker, %H:%M:%S"), ""]
    for key in sorted(stats):
        s = stats[key]
        if key.startswith("activity"):
            status = "INFO"
        elif s["n"] == 0:
            status = "NO DATA"
        else:
            status = "OK" if s["bad"] == 0 else "FAIL"
        extra = f"  (max {s['max']:,}, avg {s['sum'] // s['n']:,})" if s["sum"] or s["max"] else ""
        bad = f", {s['bad']} failed" if s["bad"] else ""
        lines.append(f"[{status:7}] {key}: {s['n']:,} checked{bad}{extra}")
        for example in s["examples"]:
            lines.append(f"            e.g. {example}")
    lines.append("")
    lines.append("Not tracked automatically: whether moves complete 14 days after agreement "
                 "(transfer_notice_14_days) and whether clubs approach bigger names (ai_approach_anyone); "
                 "check those in game.")
    return "\n".join(lines)


def main(argv):
    minutes = float(argv[1]) if len(argv) > 1 else 20
    out = pathlib.Path(argv[2]) if len(argv) > 2 else ROOT / "reports" / "tracker" / "latest.txt"
    mode = argv[3] if len(argv) > 3 else "labour"
    out.parent.mkdir(parents=True, exist_ok=True)

    loader = load_module(ROOT / "tools" / "fm15_loader.py")
    patcher = load_module(ROOT / "patcher" / "patch.py")
    runtime_writes, writable = {}, {}
    for path in sorted((ROOT / "patcher").glob("patches*.py")):
        module = load_module(path)
        runtime_writes.update(getattr(module, "RUNTIME_WRITES", {}))
        writable.update(getattr(module, "WRITABLE", {}))
    to_va = loader.section_map(loader.ORIGINAL.read_bytes())
    patches, writes = [], []
    for name in patcher.MODES[mode]:
        slots = {va for va, _ in writable.get(name, [])}
        for p in patcher.PATCHES[name]:
            data = bytes.fromhex(p["patched"].replace(" ", ""))
            if p.get("va") in slots:
                continue    # pointer slot of a loader-allocated block: non-zero once the loader ran
            patches.append({"name": name, "va": p["va"] if "va" in p else to_va(p["offset"]), "len": len(data), "patched": data.hex(" ")})
        for addr, data in runtime_writes.get(name, []):
            raw = bytes.fromhex(data.replace(" ", ""))
            writes.append({"name": name, "va": addr, "len": len(raw), "bytes": raw.hex(" ")})

    pid = loader.find_fm()
    if pid is None:
        print("fm.exe is not running; start it with tools/fm15_loader.py first")
        return 1

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
        elif "stats" in message["payload"]:
            out.write_text(render(message["payload"]["stats"]), "utf-8")

    session = frida.attach(pid)
    script = session.create_script((pathlib.Path(__file__).parent / "track_mods.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    script.post({"type": "start", "patches": patches, "writes": writes})
    print(f"tracking for {minutes:g} minutes; report: {out}", flush=True)
    time.sleep(minutes * 60)
    session.detach()
    print(out.read_text("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
