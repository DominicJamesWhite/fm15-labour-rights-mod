"""Nostalgia mode: clubs can refuse any move (no release clauses). See reports/clauses/README.md.

Not in DEFAULT. Independent of the labour-rights patches (it touches none of their bytes).
Addresses in comments are Ghidra VAs (image base 0x400000; .text file offset = VA - 0x400000).

How FM15 decides that a bid "meets a release clause":
  FUN_00ab1cf0(offer)  "offer meets release clause" (22 callers: AI evaluation FUN_01f325f0,
      TRANSFER_OFFER_RESPONSE 01fa9050 for human sellers, auto-responses, counter-offers...)
    -> FUN_00c2f780(player, buying team, &kind, &amount, &flag), the release-fee lookup.
       It returns the lowest fee the selling club must accept, from these sources:
         '%'  affiliated club relation (amount 0)                        inter-club agreement, kept
         '$'  player's loan arrangement (+0x14 fee for that club)        inter-club agreement, kept
         contract clause: FULL_CONTRACT vfunc +0xb8 (016dc550)           RELEASE CLAUSE, removed
         '!'  player's LOAN_CONTRACT with the buyer (+0x3c option fee)   inter-club agreement, kept
         '#'  selling club's agreement list (+0x50, entry kind 7)        inter-club agreement, kept
         nation/competition rule list (FUN_010376d0, clause kinds 0x10/0x11/0x12/0x1b)
                                                                         RULE-BASED CLAUSE, removed
  Making both removed sources report "no clause" turns every clause-meeting bid into an ordinary
  bid everywhere FM asks, for AI and human sellers alike.
"""


def off(va):
    return va - 0x400000


PATCHES = {
    "nostalgia_no_release_clauses": [
        {
            # FULL_CONTRACT@DB vfunc +0xb8 (016dc550, thiscall, 1 arg = buying club, ret 4): walks
            # the contract's clause list (+0x3c, 8-byte {amount, kind} entries) and returns the
            # cheapest release clause that applies to that club: kind 0x00 (any club), 0x10 (foreign
            # clubs), 0x12 (domestic clubs), 0x11 (clubs in a higher division), 0x1b (clubs in a
            # given competition), 0x27 and 0x28 (unconditional). NULL means "no clause applies".
            # B_CLUB_CONTRACT's +0xb8 forwards here; other contract classes already return NULL.
            #   sub esp,8 ; push ebx ; mov ebx,ecx...  ->  xor eax,eax ; ret 4
            # Callers: FUN_00c2f780 (00c2f928) and the human auto-response FUN_004d8b20 (which took
            # min(asking price, clause) as its threshold), plus any other reader of this vfunc.
            # Clauses stay stored in contracts (and visible in the UI); they just never apply.
            "offset": off(0x016DC550),
            "original": "83 ec 08 53 8b",
            "patched": "33 c0 c2 04 00",
        },
        {
            # FUN_00c2f780 at 00c2fa7e: `test esi,esi ; jz 00c2fb09` guards the last source, a
            # nation/competition rule list (FUN_00fd83b0 -> FUN_010376d0) that imposes release fees
            # of clause kinds 0x10/0x11/0x12/0x1b (FUN_015c6f80 maps rule kinds 3..6 to them).
            # Always take the jump: jmp 00c2fb09 ; nop x3 (00c2fb09 is the function's normal tail;
            # it only reloads EBX from the stack, as on the original esi == 0 path).
            # The '#' branch above falls through to 00c2fa7e too, so it also lands on the tail.
            "offset": off(0x00C2FA7E),
            "original": "85 f6 0f 84 83 00 00 00",
            "patched": "e9 86 00 00 00 90 90 90",
        },
    ],
}
