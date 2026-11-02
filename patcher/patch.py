"""Applies byte patches to a copy of fm.exe.

Usage:
    python patch.py <input fm.exe> <output fm.exe> [patch name ...]   (default: DEFAULT below)

Every patch's original bytes are checked before anything is written, so a different
game version fails loudly instead of being corrupted. Patches that touch the same bytes
are refused.

Each patch has either a file "offset" or, for code caves past the end of .text's raw data
(VA 0x020c1600-0x020c1fff, zero-filled only in memory), a virtual address "va". The latter can
only be applied by the in-memory loader.
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

# The pre-Bosman rule set: clubs own players' registrations, at most 3 foreigners per squad.
NOSTALGIA = [
    "always_open_windows",  # before 2002 there were no transfer windows
    # Release clauses stay as in FM: they existed pre-Bosman (mandatory in Spain since 1985).
    # nostalgia_no_release_clauses removes them, if wanted.
    # Compensation is due for out-of-contract moves at any age and to any country. Pre-contracts
    # stay allowed, as before 1995, when the new club still paid a fee;
    # nostalgia_no_pre_contracts blocks them, if wanted.
    "nostalgia_compensation_any_age",
    # Belgian-style retention: a contract the club doesn't release rolls over a year on the same
    # terms, so an unsold player stays (pre-contracts still allowed, but cost compensation)
    "nostalgia_retain_on_expiry",
    # At most 3 foreigners in the match squad, stored as each competition's own rule (so FM's
    # foreign-limited AI mode switches on natively), and shown on the rules screen.
    "nostalgia_3_foreigners",
    "nostalgia_3_foreigners_ui",
    # AI clubs list their senior (21+) foreigners outside their best 3 by ability for sale and loan,
    # then settle them (20-75% of remaining wages); and only pursue foreign targets with fewer than
    # 3 senior foreigners or none signed in the last 365 days, and only if the target beats the
    # club's 3rd-best senior foreigner. Until 1 Sep 2014 releasing foreigners is free and AI clubs
    # release unsold surplus foreigners in late August (reports/foreign_cap, transfer_ai).
    "nostalgia_foreign_cap_ai",
    # listed Not Needed players are left out of the AI depth chart, so their places become needs
    "nostalgia_ai_plan_without_surplus",
]

# Competitive parity: the labour-rights rules plus redistribution. These byte patches cover the
# simple rules; the loader also runs tools/parity_agent.js for the pools and levies
# (reports/parity/PLAN.md).
PARITY = DEFAULT + [
    "parity_no_dividends",
    "parity_no_parachutes",
    "parity_cup_gates_50_50",
    # virtual players (FM's stand-ins for clubs without real squads) are rated as for a loaded
    # league everywhere, so an unloaded minnow is weak (reports/parity/virtual_players_fix.md)
    "parity_virtual_players_loaded_strength",
]

# Rule sets offered by tools/launcher.pyw and fm15_loader.py --mode.
MODES = {
    "vanilla": [],
    "labour": DEFAULT,
    "nostalgia": NOSTALGIA,
    "parity": PARITY,
}

# Frida agents (in tools/) that fm15_loader.py also runs, eternalized, for a mode. squad_strip.js
# removes the football-only squad rules that DEFAULT switches off from the competitions' stored
# rules, so the rules screen and the AI stop seeing them too (reports/squad/strip_rules.md).
MODE_AGENTS = {
    "labour": ["squad_strip.js"],
    "parity": ["squad_strip.js", "parity_agent.js", "parity_continental.js", "parity_playoff.js"],
}

# Rule groups for a custom rule set (launcher "Custom", fm15_loader.py --custom windows,fees).
# "needs" are switched on with the group; "clashes" can't be combined with it. No two groups patch
# the same bytes (the loader checks that too).
CUSTOM = {
    "windows": {
        "label": "No transfer windows",
        "text": "Players can move at any time of year.",
        "patches": ["always_open_windows"],
    },
    "fees": {
        "label": "No transfer fees",
        "text": "No fees, instalments, add-ons or compensation. The AI treats every player as free to sign.",
        "patches": ["no_transfer_fees", "ai_fee_free_targets"],
    },
    "loans": {
        "label": "No loans",
        "text": "Loans are abolished.",
        "patches": ["no_loans"],
    },
    "notice": {
        "label": "Two weeks' notice",
        "text": "Clubs accept every offer and the player decides; a move completes 14 days after it's "
                "agreed; releasing a player costs at most two weeks' wages. AI clubs approach anyone.",
        "patches": ["notice_club_side", "notice_mutual_termination", "notice_player_side",
                    "transfer_notice_14_days", "ai_approach_anyone"],
        # with fees, a club that must accept every offer could be bought for a token fee
        "needs": ["fees"],
    },
    "quotas": {
        "label": "No football-only squad quotas",
        "text": "Homegrown, nationality and non-EU squad quotas and the squad size cap are switched off "
                "(work permits and Italy's visa quota stay). With 3 foreign players, nationality "
                "quotas stay on.",
        "patches": ["squad_rules_core", "no_homegrown_quota", "no_nationality_quota", "no_non_eu_limit",
                    "no_squad_size_cap", "squad_rules_counters"],
        "agents": ["squad_strip.js"],
    },
    "prebosman": {
        "label": "Pre-Bosman contracts",
        "text": "A contract the club doesn't release rolls over a year on the same terms, and moving at "
                "the end of a contract costs compensation at any age.",
        "patches": ["nostalgia_compensation_any_age", "nostalgia_retain_on_expiry"],
        # both zero the compensation these rules rely on
        "clashes": ["fees", "notice"],
    },
    "foreign3": {
        "label": "3 foreign players",
        "text": "At most 3 foreigners in a match squad in every league. AI clubs sell the foreigners "
                "they can't use.",
        "patches": ["nostalgia_3_foreigners", "nostalgia_3_foreigners_ui", "nostalgia_foreign_cap_ai",
                    "nostalgia_ai_plan_without_surplus"],
    },
    "redistribution": {
        "label": "Redistribution",
        "text": "Pooled league TV, shared gates, levies on big commercial earners and owner money, wage "
                "budgets that follow revenue, no dividends or parachutes, one-match national cup ties "
                "with gates split 50/50.",
        "patches": ["parity_no_dividends", "parity_no_parachutes", "parity_cup_gates_50_50"],
        "agents": ["parity_agent.js"],
    },
    "continental": {
        "label": "Knockout continental cups",
        "text": "One knockout stage: champions and cup winners in the primary cup, the next two clubs "
                "per nation in the secondary cup. Prize money shared, with solidarity to every nation.",
        "patches": ["parity_virtual_players_loaded_strength"],
        "agents": ["parity_continental.js", "parity_playoff.js"],
    },
}
# The 3-foreigner rule is FM rule type 0x04, one of the nationality quotas, so no_nationality_quota
# would switch it off and squad_strip.js (which strips what the quota patches switch off) remove it.
CUSTOM_DROPS = {("quotas", "foreign3"): ["no_nationality_quota"]}


def custom_set(keys):
    """Patch names and agents for a list of CUSTOM keys, with needs added; raises on clashes."""
    keys = list(dict.fromkeys(keys))
    for key in keys:
        if key not in CUSTOM:
            raise ValueError(f"unknown rule group {key!r} (choose from {', '.join(CUSTOM)})")
        keys += [k for k in CUSTOM[key].get("needs", []) if k not in keys]
    for key in keys:
        bad = [k for k in CUSTOM[key].get("clashes", []) if k in keys]
        if bad:
            raise ValueError(f"{CUSTOM[key]['label']} can't be combined with "
                             f"{', '.join(CUSTOM[k]['label'] for k in bad)}")
    drop = {n for pair, names in CUSTOM_DROPS.items() if set(pair) <= set(keys) for n in names}
    order = [k for k in CUSTOM if k in keys]
    names = [n for k in order for n in CUSTOM[k]["patches"] if n not in drop]
    agents = [a for k in order for a in CUSTOM[k].get("agents", [])]
    return names, agents


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
    # Patches with a "va" instead of an "offset" live past .text's raw data (code caves that are
    # only zero-filled in memory), so only tools/fm15_loader.py can apply them.
    memory_only = sorted({n for n in names for p in PATCHES[n] if "offset" not in p})
    if memory_only:
        print(f"{', '.join(memory_only)} can only be applied in memory (tools/fm15_loader.py)")
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
