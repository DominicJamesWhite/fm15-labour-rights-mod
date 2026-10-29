"""Applies byte patches to a copy of fm.exe.

Usage:
    python patch.py <input fm.exe> <output fm.exe> [patch name ...]   (default: DEFAULT below)

Every patch's original bytes are checked before anything is written, so a different
game version fails loudly instead of being corrupted. Patches that touch the same bytes
are refused.
"""

import hashlib
import importlib.util
import pathlib
import struct
import sys

# patches.py plus any patches_<topic>.py next to this file
PATCHES = {}
for path in sorted(pathlib.Path(__file__).parent.glob("patches*.py")):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    PATCHES.update(module.PATCHES)

# The labour-rights rule set. Others in PATCHES (e.g. ai_accepts_all_offers, no_compensation,
# ai_ignores_valuations, no_age_quota, no_salary_cap, no_work_permits) are optional extras to
# name explicitly.
DEFAULT = [
    "no_loans",
    "always_open_windows",
    "no_transfer_fees",
    "notice_club_side",
    "notice_mutual_termination",
    "notice_player_side",
    # football-only squad rules (work permits and the non-EU signings-per-season quota stay)
    "squad_rules_core",
    "no_homegrown_quota",
    "no_nationality_quota",
    "no_non_eu_limit",
    "no_squad_size_cap",
    "squad_rules_counters",
    # AI behaviour to match the new rules
    "ai_fee_free_targets",
    "transfer_notice_14_days",
    "ai_approach_anyone",
]


def parse(hex_bytes):
    return bytes.fromhex(hex_bytes.replace(" ", ""))


def fix_pe_checksum(data):
    """Recompute the optional header CheckSum (as imagehlp's CheckSumMappedFile does); the
    original fm.exe has a valid one."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    field = pe + 24 + 64
    struct.pack_into("<I", data, field, 0)
    total = 0
    for (word,) in struct.iter_unpack("<H", data[:len(data) & ~1]):
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    if len(data) & 1:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    struct.pack_into("<I", data, field, ((total & 0xFFFF) + (total >> 16)) + len(data))


def fix_crsig(original, data):
    """Re-sign patched sections in .crsig, FM15's code signature.

    .crsig holds a 16-byte header (dword 0 = header + entries size) and one 0x3c-byte entry per
    signed section: a copy of the 40-byte section header plus a 20-byte SHA-1 of the section's raw
    bytes. If a hash doesn't match, the game silently switches to fake player/manager names. Only
    entries whose stored hash is the SHA-1 of the original raw bytes are updated.
    """
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    crsig = None
    for i in range(count):
        o = pe + 24 + opt + 40 * i
        if data[o:o + 8].rstrip(b"\0") == b".crsig":
            crsig = struct.unpack_from("<I", data, o + 20)[0]
    if crsig is None:
        return
    entries = (struct.unpack_from("<I", data, crsig)[0] - 0x10) // 0x3C
    for i in range(entries):
        e = crsig + 0x10 + i * 0x3C
        size, raw = struct.unpack_from("<II", data, e + 16)
        stored = bytes(data[e + 40:e + 60])
        if stored != hashlib.sha1(original[raw:raw + size]).digest():
            continue
        new = hashlib.sha1(data[raw:raw + size]).digest()
        if new != stored:
            data[e + 40:e + 60] = new
            print(f"re-signed {data[e:e + 8].rstrip(b'\0').decode()} in .crsig")


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1
    src, dst, names = argv[1], argv[2], argv[3:] or DEFAULT

    unknown = [n for n in names if n not in PATCHES]
    if unknown:
        print(f"Unknown patches: {', '.join(unknown)}. Available: {', '.join(PATCHES)}")
        return 1

    claimed = {}
    for name in names:
        for p in PATCHES[name]:
            for at in range(p["offset"], p["offset"] + len(parse(p["original"]))):
                if at in claimed and claimed[at] != name:
                    print(f"{name} and {claimed[at]} both patch {at:#x}; aborting")
                    return 1
                claimed[at] = name

    data = bytearray(open(src, "rb").read())
    for name in names:
        for p in PATCHES[name]:
            original, patched = parse(p["original"]), parse(p["patched"])
            at = p["offset"]
            found = bytes(data[at:at + len(original)])
            if found == patched:
                print(f"{name} @ {at:#x}: already patched")
                continue
            if found != original:
                print(f"{name} @ {at:#x}: expected {original.hex(' ')}, found {found.hex(' ')}; aborting")
                return 1
            data[at:at + len(patched)] = patched
            print(f"{name} @ {at:#x}: patched")

    fix_crsig(open(src, "rb").read(), data)
    fix_pe_checksum(data)
    open(dst, "wb").write(data)
    print(f"Wrote {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
