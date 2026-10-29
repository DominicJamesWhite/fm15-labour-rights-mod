"""Transfer-window patches for FM15 (fm.exe, 15.3, built Apr 2 2015).

DAT_02392459 is the game's global "transfer windows active" flag. FM Classic's "no transfer windows"
store unlock clears it (FUN_00ba9210); every window check honours it, e.g. TRANSFER_RULES'
open-window lookup (FUN_01035ca0) returns "open" and the has-windows check (FUN_01037830) returns
false when it is 0. Outside Classic mode nothing but this startup initialiser sets it.
"""

# For the in-memory loader: the initialiser below has already run by the time the loader attaches,
# so it also writes the flag itself. VA -> bytes.
RUNTIME_WRITES = {
    "always_open_windows": [(0x02392459, "00")],
}

PATCHES = {
    "always_open_windows": [
        {
            # Static initialiser at 00a94af0 (run from the CRT init table at .rdata 020d0f04):
            # mov byte ptr [0x02392459], 1  ->  mov byte ptr [0x02392459], 0
            "offset": 0x694AF0,
            "original": "c6 05 59 24 39 02 01",
            "patched": "c6 05 59 24 39 02 00",
        },
        {
            # FUN_00ba9210 (applies FM Classic's "no transfer windows" unlock state, e.g. when a game
            # is created): setz byte ptr [0x02392459]  ->  mov byte ptr [0x02392459], 0
            # Without this, starting a new game switches windows back on.
            "offset": 0x7A921A,
            "original": "0f 94 05 59 24 39 02",
            "patched": "c6 05 59 24 39 02 00",
        },
    ],
}
