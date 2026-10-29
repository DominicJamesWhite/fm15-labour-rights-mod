"""League-rule patches for FM15 (fm.exe 15.3). Optional: not part of patch.py DEFAULT.

See reports/rules/README.md for how these were found. Addresses in comments are Ghidra VAs.
"""

PATCHES = {
    "no_work_permits": [
        {
            # FUN_00eb28f0(rules, person, club) (cdecl, plain ret): "does this move need a work
            # permit?". Every permit path calls it, both the full-FM ones (00a11570, 00b04e20,
            # 00f27c10) and the ones gated by DAT_02392458 (009502f0, 00b11510, 00a29140...).
            #   mov ecx,[esp+4] -> xor al,al ; ret      (always "no permit needed")
            "offset": 0xAB28F0,
            "original": "8b 4c 24",
            "patched": "32 c0 c3",
        },
    ],
    "no_foreign_restrictions": [
        {
            # FUN_00dbc070 at 00dbc5e8: after FM Classic's "no foreign restrictions" check
            # (cmp byte [FUN_011a5a50()+0x34],0), jnz 00dbd2be skips the rest of the player-status
            # computation. Make it unconditional, i.e. the FMC unlock is always on.
            #   jnz 00dbd2be -> jmp 00dbd2be ; nop
            "offset": 0x9BC5E8,
            "original": "0f 85 d0 0c 00 00",
            "patched": "e9 d1 0c 00 00 90",
        },
    ],
}
