"""Nostalgia mode: keep surplus players out of the AI's squad plan (fm.exe 15.3).
See reports/transfer_ai/README.md and reports/transfer_ai/native_mode.md.

nostalgia_ai_plan_without_surplus (use with nostalgia_foreign_cap_ai):

  depth chart     FUN_009ed420 (own player eligible for a shortlist slot, used by the depth chart
                  select_player_for_this_slot): a transfer-listed (contract +0x32 bit 0) "Not Needed"
                  (+0x30 == 7) player is not eligible. The surplus ladder of nostalgia_foreign_cap_ai lists
                  every surplus foreigner and the status hook keeps him at 7, so surplus foreigners stop
                  filling slots and the club sees real needs, which the game's own foreign-limited mode
                  (shortlist +0xea, switched on by nostalgia_3_foreigners' stored rule) then fills.
                  Unslotted players are hawked by the game (FUN_00809590 -> FUN_01f263b0).

The planning-flag part of the earlier nostalgia_ai_domestic_planning (forced +0xea, +0xcc = 20 domestic
pools for clubs "short" of domestic players) is gone: the native mode does the planning
(reports/transfer_ai/native_mode.md).

Code cave: 0x02047B80-0x02047BFF, inside a 1074-byte zero run (0x02047956-0x02047D87) in .text's raw
data: the body of a function whose code was moved to helper.dll (its stub at 0x02047950 is a bare
"jmp [0x0246b858]" that nothing references; Ghidra: no references, instructions or data in the run;
no pointer or rel32 branch into it; still all zero in a running game after hours). These entries use
"offset" with the original zero bytes. patches_foreign_cap.py's anti-churn gate uses 0x02047960-0x02047B7F.
Addresses are Ghidra VAs (image base 0x400000; .text file offset = VA - 0x400000).
"""

import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "_fc_for_transfer_ai", pathlib.Path(__file__).with_name("patches_foreign_cap.py"))
_fc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fc)
Asm, off = _fc.Asm, _fc.off
VBASE_ECX_EAX = _fc.VBASE_ECX_EAX

# --- caves (zero run of a relocated function body, see the docstring) ------------------------------
ZERO_RUN = (0x02047956, 0x02047D88)
ELIGIBLE_CAVE = 0x02047B80  # FUN_009ed420 entry
CAVE_LIMIT = 0x02047C00
assert _fc.CHURN_CAVE_END <= ELIGIBLE_CAVE

# --- sites --------------------------------------------------------------------------------------------
ELIGIBLE_SITE = 0x009ED420  # push ecx ; push ebp ; push esi ; mov esi,[esp+0x10]
ELIGIBLE_CONT = 0x009ED427  # mov ebp,ecx


def eligible_cave():
    """FUN_009ed420 entry (thiscall: ECX = shortlist; args: player, slot, ?, team, ?; ret 0x14)."""
    a = Asm(ELIGIBLE_CAVE)
    a.b("51 8b 44 24 08 85 c0"); a.jcc("84", "orig")    # push ecx ; eax = player
    a.b(VBASE_ECX_EAX + " 8b 01 ff 90 d8 01 00 00")     # contract = person->vfunc_0x1d8()
    a.b("85 c0"); a.jcc("84", "orig")
    a.b("f6 40 32 01"); a.jcc("84", "orig")             # transfer-listed
    a.b("80 78 30 07"); a.jcc("85", "orig")             # "Not Needed"
    # No team / foreign test: FM15 crashed (17:16, return 02047b4f) when the foreign test was run on
    # "argument 4", which during career creation isn't always a team. Any listed Not Needed player
    # is one his club is selling, so leaving him out of the depth chart is right whatever his
    # nationality (vanilla only lists Not Needed players anyway).
    a.b("59 32 c0 c2 14 00")                            # not eligible
    a.label("orig")
    a.b("59 51 55 56 8b 74 24 10")                      # pop ecx + the replaced code
    a.jmp(ELIGIBLE_CONT)
    return a.build()


def zero_cave(va, code):
    """A cave in .text's raw data: file offset, original zeros."""
    return {"offset": off(va), "original": " ".join(["00"] * len(code)), "patched": code.hex(" ")}


def site(va, original, target):
    n = len(bytes.fromhex(original.replace(" ", "")))
    jmp = b"\xe9" + (target - (va + 5)).to_bytes(4, "little", signed=True)
    return {"offset": off(va), "original": original, "patched": (jmp + b"\x90" * (n - 5)).hex(" ")}


_ELIGIBLE = eligible_cave()
assert ZERO_RUN[0] <= ELIGIBLE_CAVE and ELIGIBLE_CAVE + len(_ELIGIBLE) <= CAVE_LIMIT <= ZERO_RUN[1]

PATCHES = {
    "nostalgia_ai_plan_without_surplus": [
        zero_cave(ELIGIBLE_CAVE, _ELIGIBLE),
        site(ELIGIBLE_SITE, "51 55 56 8b 74 24 10", ELIGIBLE_CAVE),  # push ecx/ebp/esi ; mov esi,[esp+0x10]
    ],
}
