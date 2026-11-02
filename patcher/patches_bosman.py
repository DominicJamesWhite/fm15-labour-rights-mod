"""Nostalgia (pre-Bosman) contract patches for FM15 (fm.exe 15.3). See reports/bosman/README.md.

None of these are in DEFAULT. They are meant for the "nostalgia" mode and contradict the
labour-rights set (no_transfer_fees and notice_player_side zero or bypass every fee, including
the compensation these patches create), so don't combine the two.

Addresses in comments are Ghidra VAs (image base 0x400000; .text file offset = VA - 0x400000).
Code cave: nostalgia_retain_on_expiry uses VA 0x020C1A00-0x020C1ABF (past .text's raw data, so it
has a "va" key and can only be applied by tools/fm15_loader.py). 0x020C1AC0-0x020C1BFF is still free.

How FM15 handles a player whose contract is running out:
- FUN_00640ad0(person, buying club, &kind, &date, &compensation, flag, flag) (cdecl) is the
  "Bosman / pre-contract approach" check. It needs a live contract with an end date, and the
  days left (FUN_015c0cb0) must be within the nation's window: TRANSFER_RULES slot 0x3c
  (bosman_number_days, field +0x94; ENG_TRANSFER_RULES returns 31 days for some domestic cases),
  read via FUN_0103a840 / FUN_0103a8a0. If FUN_00ea7fc0 says compensation is due, the
  compensation is the player's vfunc +0x2c (FUN_0163e480 -> GAME_ACTUAL_PLAYER vfunc +0x74 =
  FUN_006d4d20).
- Its users: the AI shortlist turns "buy" targets (type 4) into "free transfer" targets (type 5)
  when it returns true (FUN_00db28b0), prices type 5 targets with it
  (TC_SHORTLIST::calculate_cost_of_transfer, which adds the compensation to the cost), and the AI
  bid code FUN_00cb9e40 / FUN_01e4c5f0 use it; the human "can offer a contract" check
  FUN_00ee8530 accepts a player when it, or FUN_00d454a0 (free agents and special contracts),
  returns true.
"""


import struct


def off(va):
    return va - 0x400000


def rel32(source, length, target):
    """Little-endian rel32 for a jump/call instruction at `source` of `length` bytes."""
    return struct.pack("<i", target - (source + length)).hex(" ")


# nostalgia_retain_on_expiry
EXPIRY_CHECK = 0x007CB5B3     # FUN_007cb2d0: cmp dword [esp+0x28],0 (days left) ; je 007cb5e5
NONZERO_DAYS = 0x007CB5BA     # FUN_007cb2d0: the original "days left != 0" path
EXPIRE = 0x007CB5E5           # FUN_007cb2d0: push 0 ; push esi ; push edi ; call FUN_00478070 (expiry)
RETURN_0 = 0x007CB47B         # FUN_007cb2d0: pop ebp/ebx/edi ; xor al,al ; pop esi ; ret 8
NO_END_DATE = 0x015C10A0      # fastcall(contract): end date is the "no date" sentinel
DAYS_IN_YEAR = 0x01C1EA50     # stdcall(year) -> 365 or 366
HUMAN_TEAM = 0x0158A9E0       # thiscall(team, 1) (ret 4): team is human-controlled
NOT_NEEDED = 7                # contract squad status (vfunc +0x80 = byte +0x30)
# nostalgia_foreign_cap_ai's cdecl IS_SURPLUS(contract) -> AL (patches_foreign_cap.py: transfer-listed
# surplus foreigner of an AI club). Called only when its first dword is IS_SURPLUS_SIG, i.e. when that
# patch is applied (the cave memory is zero otherwise).
IS_SURPLUS = 0x020C1600
IS_SURPLUS_SIG = 0x53EC8B55
RETAIN_CAVE = 0x020C1A00
RETAIN_CAVE_SIZE = 0xC0


def retain_cave():
    """Code at RETAIN_CAVE, entered with FUN_007cb2d0's stack and registers: ESI = contract,
    EDI = person, [esp+0x14] = person->vfunc 0x378 (the player part, 0 for staff),
    [esp+0x28] = days left on the contract (FUN_015c0cb0, 0 on expiry day and for no end date),
    EBP = the club's first team (as used by FUN_007cb2d0 itself at 007cb55c)."""
    a = RETAIN_CAVE
    code = []

    def emit(hex_bytes):
        code.append(hex_bytes)
        return a + sum(len(bytes.fromhex(c.replace(" ", ""))) for c in code)

    pc = emit("83 7c 24 28 00")                          # cmp dword [esp+0x28],0
    pc = emit("0f 85 " + rel32(pc, 6, NONZERO_DAYS))     # jne 007cb5ba (original path)
    pc = emit("8b ce")                                   # mov ecx,esi
    pc = emit("e8 " + rel32(pc, 5, NO_END_DATE))         # call FUN_015c10a0
    pc = emit("84 c0")                                   # test al,al
    pc = emit("0f 85 " + rel32(pc, 6, EXPIRE))           # jne EXPIRE (no end date: vanilla)
    pc = emit("8b 4c 24 14")                             # mov ecx,[esp+0x14] (player)
    pc = emit("85 c9")                                   # test ecx,ecx
    pc = emit("0f 84 " + rel32(pc, 6, EXPIRE))           # je EXPIRE (staff: vanilla)
    pc = emit("8b 01")                                   # mov eax,[ecx]
    pc = emit("6a 00 6a 00")                             # push 0 ; push 0
    pc = emit("ff 90 e8 00 00 00")                       # call [eax+0xe8] (future transfer arranged?)
    pc = emit("84 c0")                                   # test al,al
    pc = emit("0f 85 " + rel32(pc, 6, EXPIRE))           # jne EXPIRE (let the agreed move happen)
    pc = emit("6a 01")                                   # push 1
    pc = emit("8b cd")                                   # mov ecx,ebp (club's first team)
    pc = emit("e8 " + rel32(pc, 5, HUMAN_TEAM))          # call FUN_0158a9e0 (human-controlled?)
    pc = emit("84 c0")                                   # test al,al
    pc = emit("75 3c")                                   # jne EXTEND (human: his releases went via
                                                         #   the news release flag, handled earlier)
    pc = emit("8b 06")                                   # mov eax,[esi]
    pc = emit("8b ce")                                   # mov ecx,esi
    pc = emit("ff 90 80 00 00 00")                       # call [eax+0x80] (squad status, +0x30)
    pc = emit("3c 07")                                   # cmp al,7 (Not Needed)
    pc = emit("0f 84 " + rel32(pc, 6, EXPIRE))           # je EXPIRE (AI doesn't want him: vanilla)
    # Surplus foreigners of nostalgia_foreign_cap_ai, should their status not be 7:
    pc = emit("8a 46 32")                                # mov al,[esi+0x32] (transfer status flags)
    pc = emit("24 81")                                   # and al,0x81
    pc = emit("3c 81")                                   # cmp al,0x81 (listed + its Jan/Jul surplus mark)
    pc = emit("0f 84 " + rel32(pc, 6, EXPIRE))           # je EXPIRE
    pc = emit("81 3d " + struct.pack("<II", IS_SURPLUS, IS_SURPLUS_SIG).hex(" "))
                                                         # cmp dword [IS_SURPLUS],SIG (applied?)
    pc = emit("75 11")                                   # jne EXTEND
    pc = emit("56")                                      # push esi (contract)
    pc = emit("e8 " + rel32(pc, 5, IS_SURPLUS))          # call IS_SURPLUS (listed, AI, surplus)
    pc = emit("83 c4 04")                                # add esp,4
    pc = emit("84 c0")                                   # test al,al
    pc = emit("0f 85 " + rel32(pc, 6, EXPIRE))           # jne EXPIRE
    pc = emit("0f b7 46 26")                             # EXTEND: movzx eax,word [esi+0x26] (end year)
    pc = emit("40")                                      # inc eax
    pc = emit("66 89 46 26")                             # mov [esi+0x26],ax
    pc = emit("50")                                      # push eax
    pc = emit("e8 " + rel32(pc, 5, DAYS_IN_YEAR))        # call FUN_01c1ea50 (days in new year)
    pc = emit("0f b7 4e 24")                             # movzx ecx,word [esi+0x24] (end day)
    pc = emit("81 e1 ff 01 00 00")                       # and ecx,0x1ff
    pc = emit("49")                                      # dec ecx (0-based day of year)
    pc = emit("3b c8")                                   # cmp ecx,eax
    pc = emit("75 04")                                   # jne +4
    pc = emit("66 ff 4e 24")                             # dec word [esi+0x24] (day 366 -> 365)
    pc = emit("e9 " + rel32(pc, 5, RETURN_0))            # jmp 007cb47b (return 0: not expired)
    out = " ".join(code)
    n = len(bytes.fromhex(out.replace(" ", "")))
    assert n <= RETAIN_CAVE_SIZE, n
    return out, n


PATCHES = {
    # Compensation for a player at the end of his contract, whatever his age and wherever he goes.
    "nostalgia_compensation_any_age": [
        {
            # FUN_00ea7fc0(person, contract, buying club) (cdecl), "is compensation due". Vanilla:
            # selling club exists and is a real club (vfunc +0xb8), then the player's age must be
            # below the selling nation's limit (FUN_015e9560: 21 for nation 0x2f3, 22 for 0x317,
            # otherwise 24), and either the nation isn't 0x317 or contract flag bit 1 is set, and
            # the buying club must pass FUN_00cceed0(FUN_0157f410(selling nation)) (destination
            # check); or nation 0x2fb with contract type 1.
            # At 00ea7feb, right after the "real club" test (EDI still pushed):
            #   push ebx ; push esi ; mov ecx,edi  ->  mov al,1 ; pop edi ; ret
            "offset": off(0x00EA7FEB),
            "original": "53 56 8b cf",
            "patched": "b0 01 5f c3",
        },
        {
            # FUN_006d4d20 (GAME_ACTUAL_PLAYER vfunc +0x74, the compensation amount). After the
            # per-nation special cases, the general formula only runs for players under 24:
            #   006d55d7: cmp byte [esp+0x1b],0x18 (age, stored at 006d4d5b) ; jge 006d570f (-> 0)
            # NOP the jge so every age gets the formula (reputation/ability plus 156 weeks' wages,
            # times constants, clamped to 5,000..3,000,000). The other conditions (player status
            # bit, buying club type != 3) are unchanged.
            "offset": off(0x006D55DC),
            "original": "0f 8d 2d 01 00 00",
            "patched": "90 90 90 90 90 90",
        },
    ],
    # No pre-contract (Bosman) deals: nobody, AI or human, can agree a move with a player whose
    # contract is running out. He can still be bought with a transfer, or signed once he's a
    # free agent.
    "nostalgia_no_pre_contracts": [
        {
            # FUN_00640ad0 at 00640b0e, after the person check and after the kind/compensation
            # out-parameters have been zeroed:
            #   push ebp ; mov ebp,[esp+0x18]  ->  jmp 00640adc (xor al,al ; pop ebx ;
            #   add esp,8 ; ret: the function's own "no" exit). The rest of the replaced
            #   instruction is never reached.
            "offset": off(0x00640B0E),
            "original": "55 8b",
            "patched": "eb cc",
        },
    ],
    # Pre-Bosman "retain on equal terms": when a player's contract runs out and his club wants to
    # keep him, it keeps him on the same terms for another year instead of releasing him, so he
    # can only leave for a fee (or on a pre-contract, which costs compensation with
    # nostalgia_compensation_any_age). "Wants to keep":
    #   human club: unless the human chose "release" on the contracts-expiring news (contract
    #     flag 0x20, handled before this hook);
    #   AI club: unless the AI has made him "Not Needed" (contract squad status 7), or he is a
    #     transfer-listed surplus foreigner of nostalgia_foreign_cap_ai (its Jan/Jul mark, +0x32
    #     bit 7, or its IS_SURPLUS test when that patch is applied), whatever his status.
    # Players with a move already agreed, staff, and non-contract/amateur deals expire as before.
    "nostalgia_retain_on_expiry": [
        {
            # Cave (see retain_cave()).
            "va": RETAIN_CAVE,
            "original": " ".join(["00"] * retain_cave()[1]),
            "patched": retain_cave()[0],
        },
        {
            # FUN_007cb2d0(contract, person) (ret 8, called daily per person by FUN_00b04f30), in the
            # branch for contract types other than 2, 4 and 0x10 (FUN_016dd350):
            #   007cb5b3: cmp dword [esp+0x28],0 ; je 007cb5e5 (expire: FUN_00478070(person,
            #   contract, 0), which releases the player via FUN_00ebf920 and posts
            #   CONTRACT_EXPIRES_NEWS)  ->  jmp RETAIN_CAVE ; nop ; nop
            # The human's "release" choice (contract flag 0x20 at +0x32, set by
            # CONTRACT_EXPIRING_RELEASE_PLAYERS_RESPONSE_OBJECT 01f6ccf0) is handled earlier, at
            # 007cb487, and still releases.
            "offset": off(EXPIRY_CHECK),
            "original": "83 7c 24 28 00 74 2b",
            "patched": "e9 " + rel32(EXPIRY_CHECK, 5, RETAIN_CAVE) + " 90 90",
        },
    ],
}
