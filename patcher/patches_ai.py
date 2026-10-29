"""Optional AI-behaviour patches for FM15 (fm.exe 15.3). See reports/ai/README.md.

None of these are in DEFAULT. Addresses in comments are Ghidra VAs (image base 0x400000;
.text file offset = VA - 0x400000).

Code-cave space used here (zero padding at the end of .text, see also patches_notice.py and
patches_squad.py, which use 020c1420-020c14df, 020c1500-020c1569 and 020c1570-020c15e7):
    020c14e0-020c14f9   squad_rules_counters hook for FUN_00f8ba60
    020c15e8-020c15ff   squad_rules_counters hook for FUN_00f8bab0
Still free: 020c1414-020c141f, 020c14fa-020c14ff, 020c156a-020c156f, 020c15ac-020c15af,
020c15d1-020c15d3.
"""

import struct


def rel32(source, length, target):
    return struct.pack("<i", target - (source + length)).hex(" ")


def off(va):
    return va - 0x400000


# Bit 9 (max_squad_size) of the no_squad_size_cap bitmap in patches_squad.py.
# "bt dword ptr [0x020c1480], 9" reads that group's own bitmap, so this patch does nothing unless
# no_squad_size_cap is applied, and can't crash if squad_rules_core is missing.
BT_SQUAD_CAP_BIT = "0f ba 25 " + struct.pack("<I", 0x020C1480).hex(" ") + " 09"

CAP_RULE = 0x00F8BA60  # find the max_squad_size rule in a rule list (thiscall, arg: byte* index out, ret 4)
CAP_VALUE = 0x00F8BAB0  # max_squad_size value of a rule list, or -1 (fastcall ECX, plain ret)
HOOK_CAP_RULE = 0x020C14E0
HOOK_CAP_VALUE = 0x020C15E8


def hook_cap_rule():
    # bt [bitmap],9 ; jc NOCAP
    # mov edx,[ecx] ; xor eax,eax ; push esi ; jmp 00f8ba65   (the replaced original prologue)
    # NOCAP: push esi ; jmp 00f8ba82   (the function's own "not found" exit: *out = 0xff, return 0)
    a = HOOK_CAP_RULE
    return (BT_SQUAD_CAP_BIT + " 72 0a "
            "8b 11 33 c0 56 e9 " + rel32(a + 0x0F, 5, CAP_RULE + 5) + " "
            "56 e9 " + rel32(a + 0x15, 5, 0x00F8BA82))


def hook_cap_value():
    # bt [bitmap],9 ; jc NONE
    # mov eax,[ecx] ; xor edx,edx ; push esi ; jmp 00f8bab5   (the replaced original prologue)
    # NONE: or eax,-1 ; ret   (the function's own "no cap" answer)
    a = HOOK_CAP_VALUE
    return (BT_SQUAD_CAP_BIT + " 72 0a "
            "8b 01 33 d2 56 e9 " + rel32(a + 0x0F, 5, CAP_VALUE + 5) + " "
            "83 c8 ff c3")


PATCHES = {
    # AI transfer planning prices contracted targets (shortlist types 4 and 13) at their release
    # clause, or failing that at the selling club's valuation, then drops targets above its budget
    # ("can't afford"). With fees abolished, treat every player as having a £0 release clause in
    # TC_SHORTLIST::calculate_cost_of_transfer only. The contract/wage cost (FUN_00e785f0) that
    # the function adds on top is kept, so wage affordability still counts.
    "ai_fee_free_targets": [
        {
            # 0095d02a (type 4): push eax ; call FUN_0163e8c0  ->  xor eax,eax ; nop x4
            "offset": off(0x0095D02A),
            "original": "50 e8 90 18 ce 00",
            "patched": "31 c0 90 90 90 90",
        },
        {
            # 0095d223 (type 13): push eax ; call FUN_0163e8c0  ->  xor eax,eax ; nop x4
            "offset": off(0x0095D223),
            "original": "50 e8 97 16 ce 00",
            "patched": "31 c0 90 90 90 90",
        },
    ],
    # Make the two direct readers of the max_squad_size rule report "no cap" when that rule type
    # is disabled by no_squad_size_cap, i.e. answer exactly as for a competition without a cap.
    # Use together with squad_rules_core + no_squad_size_cap.
    "squad_rules_counters": [
        {"offset": off(HOOK_CAP_RULE), "original": " ".join(["00"] * 0x1A), "patched": hook_cap_rule()},
        {"offset": off(HOOK_CAP_VALUE), "original": " ".join(["00"] * 0x18), "patched": hook_cap_value()},
        {
            # FUN_00f8ba60 entry: mov edx,[ecx] ; xor eax,eax ; push esi  ->  jmp HOOK_CAP_RULE
            "offset": off(CAP_RULE),
            "original": "8b 11 33 c0 56",
            "patched": "e9 " + rel32(CAP_RULE, 5, HOOK_CAP_RULE),
        },
        {
            # FUN_00f8bab0 entry: mov eax,[ecx] ; xor edx,edx ; push esi  ->  jmp HOOK_CAP_VALUE
            "offset": off(CAP_VALUE),
            "original": "8b 01 33 d2 56",
            "patched": "e9 " + rel32(CAP_VALUE, 5, HOOK_CAP_VALUE),
        },
    ],
    # With transfer windows off, FUN_00b9dc30 ("next window date") returns today + 30 days. That
    # date becomes the offer's completion/response date (add_transfer_offer -> FUN_0063b120), so
    # agreed moves wait 30 days: an accidental notice period. Make it 14 days to match the
    # two-week notice design. The AI's "window is more than 9 / 13 days away" branches in
    # make_transfer_offer / make_free_transfer_offer still fire at 14.
    "transfer_notice_14_days": [
        {
            # 00b9dc53: push 0x1e  ->  push 0x0e
            "offset": off(0x00B9DC53),
            "original": "6a 1e",
            "patched": "6a 0e",
        },
    ],
    "ai_approach_anyone": [
        {
            # TC_SHORTLIST::make_transfer_decision_for_player at 00518d14: after comparing
            # 0.9 * the target player's reputation (EDI = player, word at +0xc0) with the buying
            # club's reputation (EBX, FUN_0149d6d0), `ja 00518c96` gives up on the target
            # ("he'd never join us"). NOP it so clubs always ask; the player still decides in
            # contract talks.
            "offset": 0x118D14,
            "original": "77 80",
            "patched": "90 90",
        },
    ],
}
