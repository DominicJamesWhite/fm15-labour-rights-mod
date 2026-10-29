"""Transfer fee patches for FM15 (fm.exe, 15.3, built Apr 2 2015).

Each patch lists the file offset, the bytes expected there in the original exe, and the replacement.
Addresses in comments are virtual addresses as shown in Ghidra (image base 0x400000).
Transfer offer objects keep the up-front fee at offer+0x18; the offer type is offer->vfunc[0x48]
(3 = loan, 7 = compensation-style offer for an out-of-contract player, 9 = trade).
"""

PATCHES = {
    "no_transfer_fees": [
        {
            # FUN_00abeba0, the transfer offer fee setter (thiscall, purges 4).
            # mov eax,[esp+4] -> xor eax,eax ; nop ; nop, so every offer, counter-offer and
            # compensation fee is stored as 0 (lock flag check and return value unchanged).
            "offset": 0x6BEBA6,
            "original": "8b 44 24 04",
            "patched": "31 c0 90 90",
        },
    ],
    # Optional: superseded by notice_player_side for ordinary transfers, and also forces acceptance
    # of every other offer type that reaches this evaluator (enquiry, trade, agent, B-club...).
    "ai_accepts_all_offers": [
        {
            # FUN_01f325f0, AI evaluation of incoming transfer offers (thiscall, purges 0xc).
            # At 01f32b52, right after offer->vfunc[0x24](0,0) has returned and popped its args,
            # jmp 01f32b6c: the existing "accept" block, which still honours the evaluate-only
            # flag at [esp+0x60] (EBX = this, EBP = offer are set in the prologue).
            # Skips the value-vs-offer comparison and the "not for sale"/"too valuable" rejections.
            "offset": 0x1B32B52,
            "original": "8b 17",
            "patched": "eb 18",
        },
    ],
    "no_compensation": [
        {
            # FUN_01f325f0 at 01f328c7: jnz 01f32b4a (offer type != 7) becomes an unconditional
            # jmp 01f32b4a + nop, so type 7 offers skip the branch that demands compensation via a
            # counter-offer and take the general path (accepted by the patch above). The two
            # PUSH 0 before it are the args for the vfunc[0x24] call on that path, as in the original.
            "offset": 0x1B328C7,
            "original": "0f 85 7d 02 00 00",
            "patched": "e9 7e 02 00 00 90",
        },
    ],
    "ai_ignores_valuations": [
        {
            # TC_SHORTLIST::calculate_cost_of_transfer (0095cfe0, cdecl): switch index byte for
            # shortlist type 4 (buy a contracted player), 01 -> 00, so it uses the type 3 handler
            # at 0095d314 (xor esi,esi; return 0). AI budget checks then stop treating contracted
            # players as costing their market value. Also drops the wage component for this type.
            "offset": 0x55D561,
            "original": "01",
            "patched": "00",
        },
    ],
}
