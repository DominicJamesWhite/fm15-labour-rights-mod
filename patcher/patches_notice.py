"""Notice-period patches for FM15 (fm.exe 15.3).

Club side: releasing a player costs at most 2 weeks' wages.
Player side: every transfer offer (types 1 and 2) is accepted by the selling club on arrival,
like a universal release clause; the move then depends on the player agreeing personal terms.

Addresses in comments are Ghidra virtual addresses (image base 0x400000).
Uses the code cave at 0x020c1500-0x020c1569 (zero padding at the end of .text, inside its
virtual size; the last real code ends at 0x020c1414).
"""

import struct


def rel32(source, length, target):
    """Little-endian rel32 for a jump/call instruction at `source` of `length` bytes."""
    return struct.pack("<i", target - (source + length)).hex(" ")


CAVE = 0x020C1500
CAVE_OFFSET = 0x1CC1500  # file offset of CAVE (.text: VA 0x401000 <-> file 0x1000)
ACCEPT = 0x00E66043  # add_transfer_offer: push 0; push 0; push edi; mov ecx,ebx; call accept_offer (00ca6360)
SKIP = 0x00E6604F  # add_transfer_offer: code after the accept call

PATCHES = {
    "notice_club_side": [
        {
            # FUN_0047ca40 (release compensation for a person, used by the release dialog, the human
            # release action 00ebf920 and AI releases 00f32700): it pays wage * days_left / 7 plus a
            # second weekly amount * days_left / 7. Clamp days_left (EBP) to [0, 14] and skip the
            # scheduled-wage-change branch (0047cb06-0047cb7b), jumping to the main sum at 0047cb7d.
            #   xor eax,eax ; test ebp,ebp ; cmovs ebp,eax ; mov al,14 ; cmp ebp,eax ; cmovg ebp,eax
            #   jmp 0047cb7d
            # EDI is already 0 (0047cad9) and EBX holds the contract, as the main sum expects.
            "offset": 0x7CAFD,
            "original": "8b cb 33 c0 85 ed 0f 48 e8 e8 55 cb 13 01 6a 02",
            "patched": "33 c0 85 ed 0f 48 e8 b0 0e 39 c5 0f 4f e8 eb 70",
        },
    ],
    "notice_mutual_termination": [
        {
            # FUN_00ebf920 (contract release) at 00ebfbe8: `cmp esi,-1 ; jnz` pays an agreed amount
            # (mutual termination settlement, ESI) instead of the capped FUN_0047ca40 payout.
            # NOP the jnz so the capped payout is always used; ESI still marks the release as
            # mutual for the payment type further down (00ebfc2d).
            "offset": 0xABFBE8,
            "original": "75 0f",
            "patched": "90 90",
        },
    ],
    "notice_player_side": [
        {
            # TRANSFER_MANAGER::add_transfer_offer at 00e66038: originally
            #   cmp al,8 ; jz ACCEPT ; cmp byte [esp+0x13],0 ; jz SKIP
            # (AL = offer type from vfunc +0x48). Jump to the cave, which also accepts types 1 and 2.
            "offset": 0xA66038,
            "original": "3c 08 74 07 80 7c 24 13 00 74 0c",
            "patched": "e9 " + rel32(0x00E66038, 5, CAVE) + " 90 90 90 90 90 90",
        },
        {
            # Cave at 020c1500 (EDI = offer). Transfer offers also have every money field zeroed here:
            # tracing showed most AI-to-AI offers get their fee written without the fee setter, and
            # that the offer's total (FULL_TRANSFER_OFFER vfunc +0x24, 00e71020) also sums add-ons.
            #   00: cmp al,8 ; je ACC ; cmp al,2 ; je FULL ; cmp al,1 ; je BASE
            #   0c: cmp byte [esp+0x13],0 ; jne ACC ; jmp 00e6604f (skip)
            #   18 FULL (FULL_TRANSFER_OFFER only):
            #        and dword [edi+0x78],0      add-on (e.g. after N appearances, count at +0x7c)
            #        and dword [edi+0x80],0      add-on
            #        and dword [edi+0x88],0      add-on (e.g. after N goals/caps, count at +0x8c)
            #        and dword [edi+0x90],0      add-on
            #        and dword [edi+0x9c],0      installments
            #        and word  [edi+0xa0],0      sell-on / next-sale percentages (bytes +0xa0, +0xa1)
            #        mov byte  [edi+0xae],0      friendly-match clause flag (valued by FUN_00892cd0)
            #        and dword [edi+0xa8],0      amount subtracted from the total (FUN_0092a9e0)
            #        and dword [edi+0xb0],0      amount added to the total (FUN_00908820)
            #        mov eax,[edi+0x60] ; mov [edi+0x64],eax   empty the 0x14-byte clause list
            #        mov eax,[edi+0x6c] ; mov [edi+0x70],eax   empty the 0x18-byte list
            #   61 BASE: and dword [edi+0x18],0  up-front fee
            #   65 ACC:  jmp 00e66043            accept (EAX is not used there)
            "offset": CAVE_OFFSET,
            "original": " ".join(["00"] * 0x6A),
            "patched": "3c 08 74 61 3c 02 74 10 3c 01 74 55 80 7c 24 13 00 75 52 "
            + "e9 " + rel32(CAVE + 0x13, 5, SKIP) + " "
            + "83 67 78 00 "
            + "83 a7 80 00 00 00 00 "
            + "83 a7 88 00 00 00 00 "
            + "83 a7 90 00 00 00 00 "
            + "83 a7 9c 00 00 00 00 "
            + "66 83 a7 a0 00 00 00 00 "
            + "c6 87 ae 00 00 00 00 "
            + "83 a7 a8 00 00 00 00 "
            + "83 a7 b0 00 00 00 00 "
            + "8b 47 60 89 47 64 "
            + "8b 47 6c 89 47 70 "
            + "83 67 18 00 "
            + "e9 " + rel32(CAVE + 0x65, 5, ACCEPT),
        },
    ],
}
