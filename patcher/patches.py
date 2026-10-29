"""Byte patches for FM15 (fm.exe, 15.3, built Apr 2 2015).

Each patch lists the file offset, the bytes expected there in the original exe, and the replacement.
Addresses in comments are virtual addresses as shown in Ghidra (image base 0x400000).
"""

PATCHES = {
    "no_loans": [
        {
            # TC_SHORTLIST::should_attempt_loans (00b87d00): AI never shortlists loan targets.
            # xor al,al ; ret 8
            "offset": 0x787D00,
            "original": "56 8b f1 80 be",
            "patched": "32 c0 c2 08 00",
        },
        {
            # TRANSFER_MANAGER::computer_evaluate_loan_offer (007f0ca2, just after the prologue):
            # jmp 007f0d2a, the existing "reject offer" block (EBP = this, EBX = offer already set).
            "offset": 0x3F0CA2,
            "original": "89 44 24 10 e8",
            "patched": "e9 83 00 00 00",
        },
    ],
}
