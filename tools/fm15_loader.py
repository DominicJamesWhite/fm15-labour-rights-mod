"""In-memory mod loader for FM15 (like Sider for PES): leaves fm.exe on disk untouched, so the
game's code-signature check (.crsig) still passes, and writes the byte patches into the running
game instead.

Usage:
    python fm15_loader.py [--delay SECONDS] [patch name ...]   (default patches: patch.py DEFAULT)

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
    args = argparse.ArgumentParser()
    args.add_argument("--delay", type=float, default=30)
    args.add_argument("names", nargs="*")
    opts = args.parse_args(argv[1:])

    patcher = load_module(ROOT / "patcher" / "patch.py")
    names = opts.names or patcher.DEFAULT
    runtime_writes = {}
    for path in sorted((ROOT / "patcher").glob("patches*.py")):
        runtime_writes.update(getattr(load_module(path), "RUNTIME_WRITES", {}))

    to_va = section_map(ORIGINAL.read_bytes())
    patches, writes = [], []
    for name in names:
        for p in patcher.PATCHES[name]:
            patches.append({"name": name, "va": to_va(p["offset"]),
                            "original": p["original"], "patched": p["patched"]})
        for va, data in runtime_writes.get(name, []):
            writes.append({"name": name, "va": va, "bytes": data})

    pid = find_fm()
    if pid is None:
        print("Starting FM15 through Steam...", flush=True)
        os.startfile(STEAM_URL)
        while pid is None:
            time.sleep(1)
            pid = find_fm()
        print(f"fm.exe started (pid {pid}); waiting {opts.delay:.0f}s before patching", flush=True)
        time.sleep(opts.delay)
    else:
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
    script.post({"type": "apply", "patches": patches, "writes": writes})
    for _ in range(100):
        if done:
            break
        time.sleep(0.1)
    # Keep the shield hook alive after this process exits.
    script.eternalize()
    session.detach()
    print("\n".join(done))
    skipped = [line for line in done if "SKIPPED" in line]
    print(f"{len(done) - len(skipped)} applied, {len(skipped)} skipped")
    return 1 if skipped or not done else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
