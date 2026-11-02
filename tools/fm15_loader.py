"""In-memory mod loader for FM15 (like Sider for PES): leaves fm.exe on disk untouched, so the
game's code-signature check (.crsig) still passes, and writes the byte patches into the running
game instead.

Usage:
    python fm15_loader.py [--delay SECONDS] [--mode labour|nostalgia|parity] [patch name ...]
    python fm15_loader.py --custom foreign3,fees     # rule groups from patch.py CUSTOM
    (default: --mode labour, i.e. patch.py DEFAULT; patch names override the mode)

Starts FM15 through Steam if it isn't running, waits for fm.exe, waits --delay seconds (default 30,
so start-up checks finish first), then applies the patches. They stay in memory after the loader
exits; run it again each time you start the game.
"""

import argparse
import importlib.util
import os
import pathlib
import struct
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "original" / "fm.exe"
STEAM_URL = "steam://rungameid/295270"


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def section_map(exe):
    """File offset -> VA for the original exe's sections."""
    pe = struct.unpack_from("<I", exe, 0x3C)[0]
    count = struct.unpack_from("<H", exe, pe + 6)[0]
    opt = struct.unpack_from("<H", exe, pe + 20)[0]
    base = struct.unpack_from("<I", exe, pe + 24 + 28)[0]
    sections = []
    for i in range(count):
        o = pe + 24 + opt + 40 * i
        vsize, rva, rsize, raw = struct.unpack_from("<IIII", exe, o + 8)
        sections.append((raw, min(rsize, vsize), base + rva))

    def to_va(offset):
        for raw, size, va in sections:
            if raw <= offset < raw + size:
                return va + offset - raw
        raise ValueError(f"file offset {offset:#x} is not in a mapped section")

    return to_va


def find_fm():
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() == "fm.exe":
            return p.pid
    return None


def main(argv):
    patcher = load_module(ROOT / "patcher" / "patch.py")
    args = argparse.ArgumentParser()
    args.add_argument("--delay", type=float, default=30)
    args.add_argument("--mode", choices=sorted(patcher.MODES), default="labour",
                      help="rule set from patch.py MODES (ignored if patch names are given)")
    args.add_argument("--custom", help="comma-separated rule groups from patch.py CUSTOM (instead of --mode)")
    args.add_argument("--gate", action="store_true",
                      help="hold FM's main-menu setup (and so an auto-setup career) until the rules are loaded")
    args.add_argument("names", nargs="*")
    opts = args.parse_args(argv[1:])

    names = opts.names or patcher.MODES[opts.mode]
    agents = getattr(patcher, "MODE_AGENTS", {}).get(opts.mode, [])
    if opts.custom is not None and not opts.names:
        try:
            names, agents = patcher.custom_set([k for k in opts.custom.split(",") if k])
        except ValueError as e:
            print(e)
            return 1
    unknown = [n for n in names if n not in patcher.PATCHES]
    if unknown:
        print(f"Unknown patches: {', '.join(unknown)}")
        return 1
    runtime_writes, writable = {}, {}
    for path in sorted((ROOT / "patcher").glob("patches*.py")):
        module = load_module(path)
        runtime_writes.update(getattr(module, "RUNTIME_WRITES", {}))
        # WRITABLE: patch name -> [(pointer VA, size)]: zeroed read-write memory the patch's code
        # reaches through a pointer slot (a 4-byte zero cave of that patch, filled in at load time).
        writable.update(getattr(module, "WRITABLE", {}))

    to_va = section_map(ORIGINAL.read_bytes())
    patches, writes, blocks, claimed = [], [], [], {}
    for name in names:
        slots = {va for va, _ in writable.get(name, [])}
        for p in patcher.PATCHES[name]:
            at = p["va"] if "va" in p else to_va(p["offset"])
            for b in range(at, at + len(bytes.fromhex(p["original"].replace(" ", "")))):
                if claimed.setdefault(b, name) != name:
                    print(f"{name} and {claimed[b]} both patch {b:#x}; aborting")
                    return 1
            if at in slots:
                continue    # the pointer slot is filled in by the agent (it is non-zero once set)
            patches.append({"name": name, "va": at, "original": p["original"], "patched": p["patched"]})
        for va, size in writable.get(name, []):
            if any(claimed.get(b) != name for b in range(va, va + 4)):
                print(f"{name}: writable pointer {va:#x} is not a 4-byte cave of the patch; aborting")
                return 1
            blocks.append({"name": name, "va": va, "size": size})
        for va, data in runtime_writes.get(name, []):
            writes.append({"name": name, "va": va, "bytes": data})
    if not patches and not writes:
        # vanilla: no shield needed, since nothing gets changed
        if find_fm() is None:
            print("Starting FM15 through Steam, unmodified", flush=True)
            os.startfile(STEAM_URL)
        else:
            print("fm.exe already running; nothing to patch")
        return 0

    pid = find_fm()
    if pid is None:
        print("Starting FM15 through Steam...", flush=True)
        os.startfile(STEAM_URL)
        while pid is None:
            time.sleep(1)
            pid = find_fm()
        started = time.time()
        if opts.gate:
            print(f"fm.exe started (pid {pid}); shield and auto-setup gate now, patches after {opts.delay:.0f}s", flush=True)
        else:
            print(f"fm.exe started (pid {pid}); waiting {opts.delay:.0f}s before patching", flush=True)
            time.sleep(opts.delay)
    else:
        started = None
        print(f"fm.exe already running (pid {pid}); patching now", flush=True)

    done = []
    shield = []

    def on_message(message, data):
        if message["type"] == "error":
            print(message["stack"], flush=True)
        elif "done" in message["payload"]:
            done.extend(message["payload"]["done"])
        elif "shield" in message["payload"]:
            shield.append(message["payload"]["shield"])

    # Untouched .text (file offset 0x1000, virtual size) for the checksum shield.
    exe = ORIGINAL.read_bytes()
    pe = struct.unpack_from("<I", exe, 0x3C)[0]
    text_vsize, _, text_raw_size, text_raw = struct.unpack_from("<IIII", exe, pe + 24 + struct.unpack_from("<H", exe, pe + 20)[0] + 8)
    pristine = exe[text_raw:text_raw + text_raw_size].ljust(text_vsize, b"\0")

    session = frida.attach(pid)
    script = session.create_script((pathlib.Path(__file__).parent / "fm15_loader.js").read_text("utf-8"))
    script.on("message", on_message)
    script.load()
    script.post({"type": "pristine"}, pristine)
    for _ in range(300):
        if shield:
            break
        time.sleep(0.1)
    if not shield:
        print("checksum shield did not install; not patching (names would turn fake)")
        session.detach()
        return 1
    print(f"checksum shield installed ({shield[0]:,} bytes of original code)")
    gate = None
    if opts.gate:
        # tools/harness_gate.js: the auto-setup harness builds the career at the first main-menu setup,
        # which can come before the patches below; the gate holds it until release().
        gate = session.create_script((pathlib.Path(__file__).parent / "harness_gate.js").read_text("utf-8"))
        gate.load()
        print("auto-setup gate installed", flush=True)
        if started is not None:
            time.sleep(max(0, opts.delay - (time.time() - started)))
    script.post({"type": "apply", "patches": patches, "writes": writes, "writable": blocks})
    for _ in range(100):
        if done:
            break
        time.sleep(0.1)
    # Keep the shield hook alive after this process exits.
    script.eternalize()
    print("\n".join(done))
    skipped = [line for line in done if "SKIPPED" in line]

    # Mode agents (rules that need running code, e.g. parity pools). Eternalized like the shield;
    # they log to a file because nobody receives their messages once the loader exits.
    if opts.names or skipped:
        agents = []
    for agent in agents:
        log = ROOT / "reports" / f"{pathlib.Path(agent).stem}.log"
        started = []
        agent_script = session.create_script((pathlib.Path(__file__).parent / agent).read_text("utf-8"))
        agent_script.on("message", lambda message, data: started.append(message))
        agent_script.load()
        agent_script.post({"type": "config", "log": str(log)})
        for _ in range(50):
            if started:
                break
            time.sleep(0.1)
        agent_script.eternalize()
        print(f"agent {agent}: {started[0].get('payload', started[0]) if started else 'no reply'} (log: {log})")
    if gate:
        gate.exports_sync.release()
        gate.eternalize()
        print("auto-setup gate released")
    session.detach()
    print(f"{len(done) - len(skipped)} applied, {len(skipped)} skipped")
    return 1 if skipped or not done else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
