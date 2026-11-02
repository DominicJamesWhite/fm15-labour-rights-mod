"""Competitive-parity patches for FM15 (fm.exe 15.3): the byte-patch part of parity mode.

The pools and levies (TV, gates, commercial, owner money) run in tools/parity_agent.js. See
reports/parity/PLAN.md and the research there. Addresses in comments are Ghidra VAs.
"""

PATCHES = {
    "parity_no_dividends": [
        {
            # FUN_00d15b60(club) (stdcall, ret 4) pays owners a dividend when the balance exceeds
            # ~reputation x 8000 (DIVIDEND_PAYOUT_NEWS). Both callers (0097b3bf in the owner's
            # monthly routine, 00d2338f) ignore the return value.
            #   sub esp,0x8c -> ret 4
            "offset": 0x915B60,
            "original": "81 ec 8c",
            "patched": "c2 04 00",
        },
    ],
    "parity_no_parachutes": [
        {
            # ACTUAL_COMP vt+0x50 = FUN_00f9f0e0(&years) (thiscall, ret 8): the parachute amount for
            # a relegated club, read by the payer at 00fa3e96 (CompPay type 10, which skips amounts
            # <= 0) and by budget projections. Return 0 and set *years = 0, as the original does
            # before its lookup.
            #   push ebp; mov ebp,esp; and esp,-8; sub esp,0xc; push ebx; mov ebx,[ebp+8]
            #   -> mov eax,[esp+4]; mov byte [eax],0; xor eax,eax; ret 8
            "offset": 0xB9F0E0,
            "original": "55 8b ec 83 e4 f8 83 ec 0c 53 8b 5d",
            "patched": "8b 44 24 04 c6 00 00 31 c0 c2 08 00",
        },
    ],
    "parity_cup_gates_50_50": [
        {
            # FUN_00fb8110 sets the home/away gate split of a fixture: 100/0 for league fixtures,
            # 90/10 when comp->vt+0x2b8() is true, otherwise 50/50. At 00fb8175 the jz after that
            # vcall becomes a jmp to the 50/50 tail, so every non-league fixture splits evenly.
            #   jz 00fb818f -> jmp 00fb818f
            "offset": 0xBB8175,
            "original": "74",
            "patched": "eb",
        },
    ],
    "parity_virtual_players_loaded_strength": [
        # FUN_008b1340 (thiscall, ret 8; its only caller is the virtual-player pool getter 0x0090e1e0,
        # reached through the thunk 0x0095efc0, i.e. every attribute read of every VIRTUAL_PLAYER)
        # generates a club's virtual player from FUN_00d68810(club) (~reputation/45). A flag byte at
        # [esp+0x1c] ("bVar21", zeroed at 008b19bd, set at 008b1b52/008b1bd3 when the club's league
        # is a running, loaded competition) selects FM's treatment for loaded leagues:
        #   008b1c0e  base halved and capped at 90
        #   008b1c7b  no "league level x 5 + base/2" re-rating
        #   008b2023  CA = base +- rand(20) instead of base x ~0.70-1.04 capped by nation reputation
        #   008b2246  CA/PA set through vt+0x220/0x224 (PA rules of real youngsters) instead of
        #             FUN_01630bf0 and PA = CA + 20..50
        # Force the flag to 1 for every club-based virtual player, so a club in an unloaded league
        # gets exactly what an equal-reputation club in a loaded league gets. Paths that never reach
        # 008b1bf6 (no club: national teams 008b1e7a, team id 0x44b459d / comp 0x28 008b1a35) keep
        # the flag at 0 and are unchanged. See reports/parity/virtual_players_fix.md.
        {
            # 008b1bf6: cmp byte [esp+0x1c],0 -> mov byte [esp+0x1c],1
            "offset": 0x4B1BF6,
            "original": "80 7c 24 1c 00",
            "patched": "c6 44 24 1c 01",
        },
        {
            # 008b1c0e: jz 008b1c30 (skip the halving) -> nop nop (no longer depends on the flags
            # left by the cmp replaced above)
            "offset": 0x4B1C0E,
            "original": "74 20",
            "patched": "90 90",
        },
    ],
}
