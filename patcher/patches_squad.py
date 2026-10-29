"""Squad-registration rule patches for FM15 (fm.exe 15.3). See reports/squad/README.md.

Competition squad rules are {type, value, compare} objects (type u16 at +0xc, value at +0x8,
compare byte at +0xe: 0xff = maximum, 1 = minimum). Type names come from the enum table at
0x02193018 (reports/squad/rule_types.txt).

How it works:
- squad_rules_core hooks the two places rules are applied and asks a checker whether the rule's
  type is "disabled":
    A. FUN_00f8a750 (rule satisfied? thiscall, ret 8): disabled types always count as satisfied.
    B. FUN_00852050 (AI squad selector building constraints from the rules): its call to
       FUN_00f89f40 is redirected so disabled types are skipped, as the selector already does for
       starting-XI rules. The AI then isn't made to follow them either.
- Each other group only fills in its own 32-byte bitmap of rule types (one bit per type, 0-255).
  With no bitmap groups the core changes nothing; a bitmap without the core does nothing.
  Combine squad_rules_core with any of the groups.

Work permits are a separate system (FUN_00eb28f0) and none of these patches touch it.
Addresses in comments are Ghidra VAs (image base 0x400000; .text file offset = VA - 0x400000).
"""

import struct


def rel32(source, length, target):
    return struct.pack("<i", target - (source + length)).hex(" ")


def off(va):
    return va - 0x400000


def bitmap(types):
    bits = bytearray(32)
    for t in types:
        bits[t >> 3] |= 1 << (t & 7)
    return bits.hex(" ")


ZERO32 = " ".join(["00"] * 32)

# One bitmap per group, in the zero padding at the end of .text.
BITMAPS = {
    "no_homegrown_quota": 0x020C1420,
    "no_nationality_quota": 0x020C1440,
    "no_non_eu_limit": 0x020C1460,
    "no_squad_size_cap": 0x020C1480,
    "no_age_quota": 0x020C14A0,
    "no_salary_cap": 0x020C14C0,
}
CHECK = 0x020C1570  # CF = 1 if the rule type in EAX is disabled by any bitmap
HOOK_A = 0x020C15B0
HOOK_B = 0x020C15D4
RULE_SATISFIED = 0x00F8A750
STARTING_XI_TYPE = 0x00F89F40  # FUN_00f89f40(short type): rule applies to the starting XI
SELECTOR_CALL = 0x0085216F  # in FUN_00852050: call FUN_00f89f40


def check_routine():
    code = "a9 00 ff ff ff 75 34 "  # test eax,0xffffff00 ; jnz done (CF cleared)
    jumps = ["72 2b", "72 22", "72 19", "72 10", "72 07", ""]
    for va, jc in zip(BITMAPS.values(), jumps):
        code += "0f a3 05 " + struct.pack("<I", va).hex(" ") + " " + (jc + " " if jc else "")
    return code + "c3"  # done: ret


def hook_a():
    # push eax ; movzx eax,word [ecx+0xc] ; call CHECK ; pop eax ; jc SAT
    # push ecx ; mov dl,[ecx+0xe] ; cmp dl,3 ; jmp 00f8a757    (the replaced original code)
    # SAT: mov eax,1 ; ret 8
    return ("50 0f b7 41 0c e8 " + rel32(HOOK_A + 0x05, 5, CHECK) + " 58 72 0c "
            "51 8a 51 0e 80 fa 03 e9 " + rel32(HOOK_A + 0x14, 5, RULE_SATISFIED + 7) + " "
            "b8 01 00 00 00 c2 08 00")


def hook_b():
    # movzx eax,word [esp+4] ; call CHECK ; jc YES ; jmp FUN_00f89f40 (tail call, same arg)
    # YES: mov al,1 ; ret
    return ("0f b7 44 24 04 e8 " + rel32(HOOK_B + 0x05, 5, CHECK) + " 72 05 "
            "e9 " + rel32(HOOK_B + 0x0C, 5, STARTING_XI_TYPE) + " b0 01 c3")


def group(name, types):
    return [{"offset": off(BITMAPS[name]), "original": ZERO32, "patched": bitmap(types)}]


# Rule type sets. Where a type mixes categories (e.g. foreign_over_21), it goes in the
# nationality / non-EU group, not the age group, so turning on age alone leaves it enforced.
HOMEGROWN = [
    0x26, 0x27,  # homegrown_players_15_21_from_club / _from_nation
    0x58, 0x59,  # homegrown (0-21) from club / nation in match squad
    0x67,  # non_homegrown_players_in_squad
    0x80, 0x81,  # homegrown from club / nation in 11
    0x91, 0x92,  # homegrown (0-21) from club / nation (registered squad)
]
NATIONALITY = [
    # the game's own "foreign player" rule set (FUN_00f8a050)
    0x02, 0x03, 0x04, 0x15, 0x34, 0x35, 0x3C, 0x41, 0x72, 0x7D, 0x7E, 0x8A, 0xB4, 0xB6, 0xC1, 0xC6,
    0x28,  # all_foreign_gks_in_squad
    0x2E, 0x33,  # chinese_players_in_squad / _in_match_squad
    0x3D, 0x47,  # hong_kong_players_in_match_squad / _in_squad
    0xAE,  # max non Canadian players in squad for Canadian teams
    0xD4,  # same_nation_players_in_squad
    0x13, 0x14, 0x69, 0x71, 0xBE, 0xD1,  # under_N_national_players_in_* minimums
]
NON_EU = [
    # the game's own "non-EEC" rule set (FUN_00f8a240)
    0x05, 0x06, 0x07, 0x12, 0x53, 0xA7, 0xB5, 0xB7,
    # 0x1E non_eu_players_signed_from_abroad_per_season is deliberately left enforced: it mirrors
    # Italy's government quota of sports visas (immigration control), not a squad-composition rule.
    0x21,  # italy_non_eu_players_allowed_for_club
]
SQUAD_SIZE = [
    0x09,  # max_squad_size
    0xA9,  # outfield_players_in_squad
]
SALARY = [
    0x00, 0x46, 0x6E,  # yearly_wage (cap) variants
    0x5D,  # yearly_wage_foreign_players
    0x37, 0x6D, 0xC5,  # MLS off-budget / designated players
    0x6F, 0xB2, 0xB3,  # A-League marquee players
]
LOANS = [  # FUN_00f8a150; moot with no_loans, excluded from the age group
    0x0C, 0x0D, 0x0E, 0x19, 0x1A, 0x1B, 0x1C, 0x22, 0x23, 0x24, 0x42, 0x43, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x65, 0x66, 0x70, 0xC7, 0xC9, 0xCA, 0xCD, 0xCE,
]
# every rule type with an age bound (FUN_00f8a8a0), minus the mixed ones above
AGE_ALL = [
    0x10, 0x11, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1D, 0x20, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x30, 0x36,
    0x38, 0x39, 0x3A, 0x3B, 0x3F, 0x42, 0x43, 0x44, 0x45, 0x48, 0x50, 0x51, 0x53, 0x56, 0x5C, 0x5F,
    0x61, 0x62, 0x65, 0x69, 0x6A, 0x6B, 0x6C, 0x70, 0x71, 0x73, 0x74, 0x75, 0x78, 0x79, 0x7A, 0x7B,
    0x7C, 0x7F, 0x85, 0x86, 0x87, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x93, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA4, 0xA8, 0xAA, 0xAB, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
    0xBD, 0xBE, 0xBF, 0xC0, 0xC2, 0xC3, 0xC4, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xD1,
    0xD2, 0xD3, 0xD8,
]
AGE = sorted(set(AGE_ALL) - set(NATIONALITY) - set(NON_EU) - set(LOANS))

PATCHES = {
    "squad_rules_core": [
        {"offset": off(CHECK), "original": " ".join(["00"] * 0x3C), "patched": check_routine()},
        {"offset": off(HOOK_A), "original": " ".join(["00"] * 0x21), "patched": hook_a()},
        {"offset": off(HOOK_B), "original": " ".join(["00"] * 0x14), "patched": hook_b()},
        {
            # FUN_00f8a750 entry: push ecx ; mov dl,[ecx+0xe] ; cmp dl,3  ->  jmp HOOK_A ; nop ; nop
            "offset": off(RULE_SATISFIED),
            "original": "51 8a 51 0e 80 fa 03",
            "patched": "e9 " + rel32(RULE_SATISFIED, 5, HOOK_A) + " 90 90",
        },
        {
            # FUN_00852050: call FUN_00f89f40  ->  call HOOK_B
            "offset": off(SELECTOR_CALL),
            "original": "e8 cc 7d 73 00",
            "patched": "e8 " + rel32(SELECTOR_CALL, 5, HOOK_B),
        },
    ],
    "no_homegrown_quota": group("no_homegrown_quota", HOMEGROWN),
    "no_nationality_quota": group("no_nationality_quota", NATIONALITY),
    "no_non_eu_limit": group("no_non_eu_limit", NON_EU),
    "no_squad_size_cap": group("no_squad_size_cap", SQUAD_SIZE),
    "no_age_quota": group("no_age_quota", AGE),
    "no_salary_cap": group("no_salary_cap", SALARY),
}
