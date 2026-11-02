"""Nostalgia mode: pre-Bosman foreign-player limits for FM15 (fm.exe 15.3). See reports/foreign_cap/README.md.

"Foreign" is always the game's own test for squad rule type 0x15 (FUN_015440e0): not of the club's
nation (nor of the nation whose league it plays in), second nationalities count as domestic, EU
nationals are foreign.

The nostalgia patch is nostalgia_3_plus_2 (defined further down): UEFA's 1991-96 "3+2" rule, stored
in every club competition's own squad-selection rule list ([rule group+0x34], saved with the career)
on first use of each group (p32_store_cave). Clubs may own any number of foreigners; only 3 (+2 "assimilated", approximated by
FM's homegrown-from-nation status) can be named for a match. Transfers and registration are untouched.

Everything else here is optional (the earlier designs):
- nostalgia_foreign_cap_rules (same site as nostalgia_3_plus_2, so patch.py refuses to combine them):
  puts a plain cap into the game's own rule lists, built per call as heap
  copies (FUN_01063090 adjusts each club's copy):
    match-day lists (FUN_01062190 with a fixture): all_foreign_players_in_match_squad (type 0x04)
        <= CAP. Only CAP foreigners can be picked for a match, everywhere; the AI selector
        (FUN_00852050) turns the rule into a selection constraint, as for leagues whose data
        already has such a rule.
    registered-squad lists (FUN_011a6b90): all_foreign_players_in_squad (type 0x15) <= CAP, so
        leagues with squad registration register at most CAP foreigners.
  Existing rules of the same type are tightened to CAP; otherwise a rule is allocated from the game's
  SQUAD_SELECTION_RULE pool and appended (freed with the list by the game).
- nostalgia_foreign_cap_ai: the AI plans around the cap, using one checker that ranks a club's
  foreigners by value (player vfunc +0x20):
    target gate  make_transfer_decision_for_player: drop a foreign target unless he'd be one of the
                 club's CAP most valuable foreigners (so the AI only buys foreigners it would play).
    surplus      FUN_006296b0 (AI squad review, per player): every surplus foreigner of an AI club is
                 transfer- and loan-listed (FUN_00e5f250 directly; status 7 "Not Needed"); still unsold
                 after the next Jan/Jul -> Jun/Dec checkpoint he is released with a 20-75% settlement
                 of his remaining wages (see surplus_cave).
    status       contract set_squad_status FUN_015c8920 (every squad-status write): the AI's daily
                 re-rating can't move a listed surplus foreigner off 7 "Not Needed" (see status_cave).
- nostalgia_foreign_cap: a hard signing block (offer validity FUN_006f69f0 fails with reason 0x29,
  FUN_00b9c670 returns "can't join", the AI drops every foreign target once at the cap). It patches the
  same AI site as nostalgia_foreign_cap_ai, so patch.py refuses to combine the two.

Code caves: 0x020C1600-0x020C19FF and 0x020C1C00-0x020C1FFF (0x020C1A00-0x020C1BFF belongs to
patches_bosman.py), inside .text's virtual size but past its raw data, so those
entries use "va" instead of "offset" (no file offset; the memory is zero at runtime). The checker and
the AI target cave are shared by nostalgia_foreign_cap and nostalgia_foreign_cap_ai (identical bytes
for the checker), which are mutually exclusive anyway; nostalgia_3_plus_2 reuses the
nostalgia_foreign_cap_rules cave range (same hook site). nostalgia_3_plus_2 combines with
nostalgia_foreign_cap or nostalgia_foreign_cap_ai.
Addresses in comments are Ghidra VAs (image base 0x400000; .text file offset = VA - 0x400000).
"""

import struct

CAP = 3  # foreign players a club may register / field
# Foreigners a club keeps when the AI plans its squad (CHECK: nostalgia_foreign_cap_ai keeps its KEEP
# most valuable and transfer-lists the rest; nostalgia_foreign_cap blocks the signing past KEEP).
# 5 matches nostalgia_3_plus_2: 3 foreigners plus 2 assimilated can play.
KEEP = 5
# Domestic-aware AI: a club whose first team has fewer than DOMESTIC_MIN domestic players buys no
# foreigners at all and keeps only its KEEP_SHORT most valuable ones (3+2 needs 8+ domestic starters).
DOMESTIC_MIN = 15
KEEP_SHORT = 3

# --- game functions -------------------------------------------------------------------------------
CONTRACT_WITH = 0x01545810   # thiscall(person; ctx, flag): person's contract with ctx's club, ret 8
IS_FOREIGN = 0x015440E0      # thiscall(person; ctx, 1, 1): type 0x15 "foreign" test, ret 0xc
TEAM_COUNT = 0x0149F3C0      # fastcall(club): number of teams
TEAM_AT = 0x0149F260         # thiscall(club; index): team (players at +0x24..+0x28), ret 4
OFFER_BUYER = 0x00D9FC00     # thiscall(offer): destination team ctx
REMOVE_TARGET = 0x00940680   # TC_SHORTLIST::remove_target thiscall(shortlist; club, person, flag), ret 0xc
LIST_PLAYER = 0x0089BBF0     # AI transfer-listing thiscall(ai manager; club, player, mode), ret 0xc
LIST_FN = 0x00E5F250         # its inner routine thiscall(ai manager; player, club, reason, price, 0), ret 0x14
HUMAN_TEAM = 0x0158A9E0      # thiscall(team; 1), ret 4: team is human-controlled
RELEASE = 0x00EBF920         # contract release thiscall(TRANSFER_MANAGER; person, team, type, ...), ret 0x1c
TRANSFER_MANAGER = 0x0241C138
PAYOUT = 0x0047CA40          # cdecl(person): wages for the rest of the contract (normal release cost)
SETTLE_MIN = 20              # surplus release settlement: SETTLE_MIN..SETTLE_MAX % of PAYOUT (rdtsc)
SETTLE_MAX = 75
SETTLE_SPAN = SETTLE_MAX - SETTLE_MIN + 1
TODAY = 0x0239EBF4           # current date: word 0 = day of year (low 9 bits, 1-based), word 1 = year
STATUS_SETTER = 0x015C8920   # contract vfunc +0x84 thiscall(contract; status, club), ret 8 (every
                             # contract class's vtable; it forwards to [0x024260d4] vfunc +0xc)
STATUS_SETTER_CONT = 0x015C8926
RULE_POOL = 0x00F842A0       # returns the SQUAD_SELECTION_RULE pool
POOL_ALLOC = 0x00F5E4B0      # thiscall(pool; size), ret 4
VEC_PUSH_BACK = 0x00F64EC0   # thiscall(vector; &item), ret 4

# --- cave layout ----------------------------------------------------------------------------------
CHECK = 0x020C1E00        # cdecl CHECK(ctx, player, flags) -> AL = 1 if over the cap (second cave range)
IS_SURPLUS = 0x020C1600   # nostalgia_foreign_cap_ai only: cdecl IS_SURPLUS(contract) -> AL, then the
                          # squad-status setter hook (patches_bosman.py's retain cave calls IS_SURPLUS
                          # when it finds IS_SURPLUS_SIG there)
IS_SURPLUS_SIG = 0x53EC8B55  # its first 4 bytes: push ebp ; mov ebp,esp ; push ebx
AI_CAVE = 0x020C1740      # target gate (flag byte differs between the two patches)
OFFER_CAVE = 0x020C1790   # nostalgia_foreign_cap only
JOIN_CAVE = 0x020C17F0    # nostalgia_foreign_cap only
SURPLUS_CAVE = 0x020C1C00 # nostalgia_foreign_cap_ai only (second cave range 0x020C1C00-0x020C1FFF)
INJECT_CAVE = 0x020C18D0  # nostalgia_foreign_cap_rules
CAVE_END = 0x020C1A00

# CHECK flags
RANK = 1           # count only foreigners more valuable than the player (else: all foreigners)
SKIP_CONTRACT = 2  # don't exempt players already under contract with the club

# --- hook sites -----------------------------------------------------------------------------------
OFFER_SITE = 0x006F6A3D   # FUN_006f69f0: mov ebp,[esp+0x2c] ; test ebp,ebp ; jz 006f6acd
OFFER_RET2 = 0x006F6ACD   # FUN_006f69f0 epilogue returning 2 ("offer can't go ahead")
OFFER_CONT = 0x006F6A49
AI_SITE = 0x005181C7      # make_transfer_decision_for_player: mov ecx,ebx ; call 014a6d60 ; test ; je
AI_GATE = 0x014A6D60
AI_GATE_NO = 0x0051821E
AI_GATE_YES = 0x005181D2
AI_DROPPED = 0x0051820D   # sets *param_9 = 0xb ("target dropped") and returns AL
JOIN_SITE = 0x00B9C670    # FUN_00b9c670 entry: sub esp,0x18 ; push ebx ; mov ebx,[esp+0x20]
JOIN_CONT = 0x00B9C678
REVIEW_SITE = 0x006296B0  # FUN_006296b0 entry: sub esp,0x10 ; push ebx ; push ebp ; push esi
REVIEW_CONT = 0x006296B6
RULES_FN = 0x01063090     # per-club rule list adjustment (cdecl ctx, list, p3, fixture; ECX = group)
RULES_CONT = 0x01063096
RET_REGISTERED = 0x011A6DB7  # return address of the call in FUN_011a6b90 (registered squad rules)
RET_GROUP_1 = 0x01062204     # FUN_01062190, first call (fixture in arg 4)
RET_GROUP_2 = 0x0106241E     # FUN_01062190, second call after merging fixture rule sets


def off(va):
    return va - 0x400000


class Asm:
    """Tiny assembler: raw byte strings plus branches to labels (rel8 where they fit) or absolute
    addresses (rel32)."""

    def __init__(self, base):
        self.base, self.parts, self.labels = base, [], {}

    def b(self, hexbytes):
        self.parts.append(bytes.fromhex(hexbytes))

    def d(self, value):
        self.parts.append(struct.pack("<I", value & 0xFFFFFFFF))

    def label(self, name):
        self.parts.append(("label", name))

    def _branch(self, opcode, target):
        self.parts.append(("branch", bytes.fromhex(opcode), target))

    def call(self, t):
        self._branch("e8", t)

    def jmp(self, t):
        self._branch("e9", t)

    def jcc(self, cc, t):  # "84" je, "85" jne, "8c" jl, "8e" jle, "83" jae, "86" jbe
        self._branch("0f" + cc, t)

    @staticmethod
    def _short(opcode):
        """rel8 form of a jmp/jcc rel32 opcode, or None for call."""
        if opcode == b"\xe9":
            return b"\xeb"
        if len(opcode) == 2:
            return bytes([opcode[1] - 0x10])
        return None

    def build(self):
        # Branches to local labels start as rel8 and grow to rel32 until every one fits.
        long = set()
        while True:
            addr, sizes = self.base, {}
            for i, p in enumerate(self.parts):
                if isinstance(p, bytes):
                    addr += len(p)
                elif p[0] == "label":
                    self.labels[p[1]] = addr
                else:
                    short = isinstance(p[2], str) and self._short(p[1]) and i not in long
                    sizes[i] = 2 if short else len(p[1]) + 4
                    addr += sizes[i]
            out, grew = bytearray(), False
            for i, p in enumerate(self.parts):
                addr = self.base + len(out)
                if isinstance(p, bytes):
                    out += p
                elif p[0] == "branch":
                    target = self.labels[p[2]] if isinstance(p[2], str) else p[2]
                    if sizes[i] == 2:
                        rel = target - (addr + 2)
                        if not -128 <= rel <= 127:
                            long.add(i)
                            grew = True
                            rel = 0
                        out += self._short(p[1]) + struct.pack("<b", rel)
                    else:
                        out += p[1] + struct.pack("<i", target - (addr + len(p[1]) + 4))
            if not grew:
                return bytes(out)


VBASE_ECX_ESI = "8b 46 04 8d 4e 04 03 48 04"   # ecx = person (virtual base) of player in esi
VBASE_ECX_EAX = "8b 50 04 8d 48 04 03 4a 04"   # ecx = person of player in eax


def check_routine():
    """CHECK(ctx, player, flags): AL = 1 when `player` is foreign for ctx's club (and, unless
    SKIP_CONTRACT, not already under contract there) and the club has KEEP or more other foreigners
    (with RANK: KEEP or more other foreigners worth more than him). Counts every team of the club,
    skipping players the game's squad counter FUN_00e50550 also skips (vfuncs +0x2bc, +0x16c).
    Domestic-aware: while ctx's own team (the first team) has fewer than DOMESTIC_MIN domestic
    players, buying any foreigner is blocked (flags without SKIP_CONTRACT), and the surplus review
    (SKIP_CONTRACT) keeps only KEEP_SHORT foreigners."""
    a = Asm(CHECK)
    a.b("55 8b ec 53 56 57 83 ec 18")   # frame; locals: -0x10 thr, -0x14 n, -0x18 team i, -0x1c cursor, -0x20 m, -0x24 domestic
    a.b("8b 5d 08 8b 75 0c 33 c0")      # ebx = ctx ; esi = player
    a.b("85 db"); a.jcc("84", "out")
    a.b("85 f6"); a.jcc("84", "out")
    a.b("80 7b 23 00"); a.jcc("85", "out")              # clubs only
    a.b("83 7b 10 00"); a.jcc("84", "out")
    a.b("8b 46 04 8d 7e 04 03 78 04")                   # edi = person
    a.b("f6 45 10 02"); a.jcc("85", "foreign")
    a.b("6a 00 53 8b cf"); a.call(CONTRACT_WITH)        # already contracted to this club?
    a.b("85 c0"); a.jcc("85", "out0")
    a.label("foreign")
    a.b("6a 01 6a 01 53 8b cf"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "out0")
    a.b("33 c0 89 45 ec 89 45 e8 89 45 dc")             # n = 0 ; team index = 0 ; domestic = 0
    a.b("f6 45 10 01"); a.jcc("84", "teams")
    a.b("8b ce 8b 06 ff 50 20 89 45 f0")                # thr = player's value
    a.label("teams")
    a.b("8b 4b 10"); a.call(TEAM_COUNT)
    a.b("3b 45 e8"); a.jcc("86", "done")                # count <= index: no more teams
    a.b("ff 75 e8 8b 4b 10"); a.call(TEAM_AT)
    a.b("ff 45 e8 85 c0"); a.jcc("84", "teams")
    a.b("8b f8 8b 47 24 89 45 e4")                      # edi = team ; cursor = players begin
    a.label("members")
    a.b("8b 45 e4 3b 47 28"); a.jcc("83", "teams")
    a.b("83 45 e4 04 8b 00 85 c0"); a.jcc("84", "members")
    a.b("3b c6"); a.jcc("84", "members")                # not the player himself
    a.b("89 45 e0")
    a.b(VBASE_ECX_EAX + " 8b 01 ff 90 bc 02 00 00 84 c0"); a.jcc("85", "members")
    a.b("8b 4d e0 6a 00 6a 00 8b 01 ff 90 6c 01 00 00 84 c0"); a.jcc("85", "members")
    a.b("8b 45 e0 " + VBASE_ECX_EAX + " 6a 01 6a 01 53"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "domestic")
    a.b("f6 45 10 01"); a.jcc("84", "count")
    a.b("8b 4d e0 8b 01 ff 50 20 3b 45 f0"); a.jcc("8e", "members")  # value <= thr: not ahead of him
    a.label("count")
    a.b("ff 45 ec"); a.jmp("members")
    a.label("domestic")                                 # domestic players of ctx's own team
    a.b("3b fb"); a.jcc("85", "members")
    a.b("ff 45 dc"); a.jmp("members")
    a.label("done")
    a.b(f"33 c0 b9 {KEEP:02x} 00 00 00 83 7d dc {DOMESTIC_MIN:02x}"); a.jcc("8d", "limit")
    a.b("f6 45 10 02"); a.jcc("85", "short")            # surplus review: keep only KEEP_SHORT
    a.b("b0 01"); a.jmp("out")                          # buying: no foreigners at all while short
    a.label("short")
    a.b(f"b9 {KEEP_SHORT:02x} 00 00 00")
    a.label("limit")
    a.b("39 4d ec"); a.jcc("8c", "out")                 # n < limit: fine
    a.b("b0 01")
    a.label("out")
    a.b("8d 65 f4 5f 5e 5b 5d c3")
    a.label("out0")
    a.b("33 c0"); a.jmp("out")
    return a.build()


def ai_cave(flags):
    """make_transfer_decision_for_player at 005181c7: EBX = club, EDI = target player, EBP = shortlist."""
    a = Asm(AI_CAVE)
    a.b("85 ff"); a.jcc("84", "orig")
    a.b("8b 43 10 3b 43 14"); a.jcc("84", "orig")       # club's first team ctx
    a.b(f"8b 00 6a {flags:02x} 57 50"); a.call(CHECK); a.b("83 c4 0c")
    a.b("84 c0"); a.jcc("84", "orig")
    a.b("8b 47 04 8b 40 04 83 c0 04 03 c7")             # eax = person
    a.b("6a 00 50 53 8b cd"); a.call(REMOVE_TARGET)     # shortlist->remove_target(club, person, 0)
    a.b("b0 01"); a.jmp(AI_DROPPED)                     # *param_9 = 0xb ; return 1
    a.label("orig")
    a.b("8b cb"); a.call(AI_GATE)                       # the replaced code
    a.b("84 c0"); a.jcc("84", AI_GATE_NO)
    a.jmp(AI_GATE_YES)
    return a.build()


def offer_cave():
    """FUN_006f69f0(offer, ctx, short* reason, ...): EBX = offer, ESI = its person, EDI = reason."""
    a = Asm(OFFER_CAVE)
    a.b("8b 6c 24 2c 85 ed"); a.jcc("84", OFFER_RET2)   # the replaced code
    a.b("85 f6"); a.jcc("84", "back")
    a.b("3b 6b 08"); a.jcc("84", "buyer")               # ctx == offer's buying club?
    a.b("8b cb"); a.call(OFFER_BUYER)                   # ... or its destination team
    a.b("3b c5"); a.jcc("85", "back")
    a.label("buyer")
    a.b("8b ce 8b 06 ff 90 78 03 00 00")                # player = person->vfunc_0x378()
    a.b("85 c0"); a.jcc("84", "back")
    a.b("6a 00 50 55"); a.call(CHECK); a.b("83 c4 0c")
    a.b("84 c0"); a.jcc("84", "back")
    a.b("85 ff 74 05 66 c7 07 29 00")                   # *reason = 0x29 (breaks squad rules)
    a.jmp(OFFER_RET2)                                   # return 2: offer fails
    a.label("back")
    a.jmp(OFFER_CONT)
    return a.build()


def ai_offer_cave():
    """nostalgia_foreign_cap_ai's offer gate (same site as nostalgia_foreign_cap's): an offer by an
    AI club for a foreign player fails (reason 0x29) when CHECK(first team, player, RANK) says the club
    can't take him (not among its KEEP most valuable foreigners, or any foreigner while its first
    team is short of domestic players). Catches AI buying routes that don't pass
    make_transfer_decision_for_player. Human buyers are never affected.
    - CHECK always gets the BUYING CLUB's first team, whatever team ctx is (an offer's ctx can be its
      destination team, e.g. the U21s, whose own domestic count would make every club look short).
    - Agreed deals (offer state +0x28 == 0x13, the state the completion queue FUN_00daf4f0 executes)
      are never re-checked, so a deal the gate allowed can't collapse on completion day."""
    a = Asm(OFFER_CAVE)
    a.b("8b 6c 24 2c 85 ed"); a.jcc("84", OFFER_RET2)   # the replaced code
    a.b("85 f6"); a.jcc("84", "back")
    a.b("80 7b 28 13"); a.jcc("84", "back")             # agreed deal: never re-checked
    a.b("3b 6b 08"); a.jcc("84", "buyer")               # ctx == offer's buying club?
    a.b("8b cb"); a.call(OFFER_BUYER)                   # ... or its destination team
    a.b("3b c5"); a.jcc("85", "back")
    a.label("buyer")
    a.b("80 7d 23 00"); a.jcc("85", "back")             # club teams only
    a.b("8b 45 10 85 c0"); a.jcc("84", "back")          # club
    a.b("8b 48 10 3b 48 14"); a.jcc("84", "back")
    a.b("8b 09 85 c9"); a.jcc("84", "back")             # ecx = the buying club's first team
    a.b("51 6a 01"); a.call(HUMAN_TEAM); a.b("5a")      # (keep it in edx)
    a.b("84 c0"); a.jcc("85", "back")                   # human buyers: never blocked
    a.b("52 8b ce 8b 06 ff 90 78 03 00 00 5a")          # player = person->vfunc_0x378()
    a.b("85 c0"); a.jcc("84", "back")
    a.b(f"6a {RANK:02x} 50 52"); a.call(CHECK); a.b("83 c4 0c")
    a.b("84 c0"); a.jcc("84", "back")
    a.b("85 ff 74 05 66 c7 07 29 00")                   # *reason = 0x29 (breaks squad rules)
    a.jmp(OFFER_RET2)
    a.label("back")
    a.jmp(OFFER_CONT)
    return a.build()


def join_cave():
    """FUN_00b9c670(person, ctx, ...) (ECX = global, ret 0x38): 0xff = can't join."""
    a = Asm(JOIN_CAVE)
    a.b("51 8b 44 24 08 8b 54 24 0c")                   # push ecx ; eax = person ; edx = ctx
    a.b("85 c0"); a.jcc("84", "go")
    a.b("85 d2"); a.jcc("84", "go")
    a.b("52 8b c8 8b 00 ff 90 78 03 00 00 5a")          # player = person->vfunc_0x378()
    a.b("85 c0"); a.jcc("84", "go")
    a.b("6a 00 50 52"); a.call(CHECK); a.b("83 c4 0c")
    a.b("84 c0"); a.jcc("84", "go")
    a.b("59 0c ff c2 38 00")                            # pop ecx ; or al,0xff ; ret 0x38
    a.label("go")
    a.b("59 83 ec 18 53 8b 5c 24 20")                   # pop ecx + the replaced code
    a.jmp(JOIN_CONT)
    return a.build()


def surplus_cave(unlist=None, doy=None, as_function=False):
    """FUN_006296b0 entry (AI squad review, per player; thiscall: ECX -> {club, ...}; args: player
    base, AI manager, ...). For a foreign squad member of an AI club who isn't among the club's KEEP
    most valuable foreigners (and isn't on loan elsewhere, has no move pending and holds a normal
    contract):
      - not listed: transfer-list him with the AI's own listing routine FUN_00e5f250 (reason 0x0f:
        listed flag, squad status 7 "Not Needed", asking price = value) and loan-list him (contract
        +0x32 bit 3, the flag the game reads as "listed for loan");
      - listed: during January / July mark him (contract +0x32 bit 7, unused by the game); if he is
        still listed and marked in June / December, release him through the AI's own release call
        (FUN_00ebf920 type 4, as FUN_01f08430 does) with a negotiated settlement: a uniformly random
        SETTLE_MIN-SETTLE_MAX % of the rest of his contract (FUN_0047ca40), passed as the release's
        agreed amount (arg 5), which the release then pays and books instead of the full payout.
    A listed surplus player whose squad status isn't 7 is set back to 7 (KEEP7; status_cave's setter
    hook keeps it there between reviews).
    A player who is no longer surplus loses the mark. Every skip calls SINK(reason) for the tracer."""
    a = Asm(SURPLUS_CAVE)
    a.b("60 8b 19 8b 74 24 24")                         # pushad ; ebx = club ; esi = arg
    a.b("85 db"); a.jcc("84", "done")
    a.b("85 f6"); a.jcc("84", "done")
    a.b("83 7c 24 28 00"); a.jcc("84", "done")          # AI manager
    a.b(VBASE_ECX_ESI + " 8b 01 ff 90 78 03 00 00")     # player = person->vfunc_0x378()
    a.b("85 c0"); a.jcc("84", "done")
    a.b("8b f0 8b 43 10 3b 43 14"); a.jcc("84", "done")
    a.b("8b 28 85 ed"); a.jcc("84", "done")             # ebp = club's first team
    a.b("6a 01 8b cd"); a.call(HUMAN_TEAM)
    a.b("84 c0"); a.jcc("85", "done")                   # human clubs: leave alone
    a.b("8b ce 6a 00 6a 00 8b 06 ff 90 6c 01 00 00 84 c0"); a.jcc("85", "r_away")    # on loan elsewhere
    a.b("8b ce 6a 00 6a 00 8b 06 ff 90 e8 00 00 00 84 c0"); a.jcc("85", "r_pending") # move arranged
    a.b(VBASE_ECX_ESI + " 8b 01 ff 90 d8 01 00 00")     # contract = person->vfunc_0x1d8()
    a.b("85 c0"); a.jcc("84", "done")
    a.b("8b f8 8b cf 8b 07 ff 50 1c a8 fe"); a.jcc("85", "r_type")  # contract type (as FUN_0089bbf0)
    a.b(f"6a {RANK | SKIP_CONTRACT:02x} 56 55"); a.call(CHECK); a.b("83 c4 0c")
    a.b("84 c0"); a.jcc("84", "notsurplus")
    a.b("8a 47 32 a8 01"); a.jcc("85", "listed")
    a.b("8b 4c 24 28 6a 00 6a ff 6a 0f 53 56"); a.call(LIST_FN)  # ai->list(player, club, 0x0f, -1, 0)
    a.b("80 4f 32 08 80 67 32 7f"); a.jmp("done")       # + listed for loan ; no mark yet
    a.label("listed")
    a.b("80 4f 32 08")                                  # keep him listed for loan
    a.b("53 57"); a.call(KEEP7)                         # and Not Needed (status_cave's KEEP7(contract, club))
    if doy:
        a.call(doy)                                     # eax = day of year (0-based), transition-aware
    else:
        a.b("0f b7 05"); a.d(TODAY); a.b("25 ff 01 00 00 48")   # eax = day of year (0-based)
    a.b("83 f8 1e"); a.jcc("86", "mark")                # January
    a.b("3d b5 00 00 00"); a.jcc("82", "release")
    a.b("3d d3 00 00 00"); a.jcc("86", "mark")          # July
    a.label("release")
    a.b("3d 97 00 00 00"); a.jcc("82", "done")
    a.b("3d b4 00 00 00"); a.jcc("86", "free")          # June
    a.b("3d 4e 01 00 00"); a.jcc("82", "done")          # December
    a.label("free")
    a.b("f6 47 32 80"); a.jcc("84", "done")             # not listed since the last Jan / Jul
    a.b("80 67 32 7f")                                  # unmark first: never release (and pay) twice
    a.b(VBASE_ECX_ESI + " 51 51"); a.call(PAYOUT)      # full = FUN_0047ca40(person) (rest of contract)
    a.b("83 c4 04 85 c0 7d 02 33 c0 8b f8")             # edi = max(full, 0)
    # edx = MIN..MAX %: rdtsc's low bits barely change between reads on some CPUs (in game, 48% came
    # up for 5 of 8 settlements), so mix the counter (xorshift + Knuth multiply) and scale by the high
    # half of eax * SPAN instead of taking it mod SPAN.
    a.b("0f 31 33 c2 8b c8 c1 e9 0d 33 c1 69 c0 b1 79 37 9e")  # rdtsc ; eax ^= edx ; eax ^= eax >> 13 ; eax *= 0x9e3779b1
    a.b(f"b9 {SETTLE_SPAN:02x} 00 00 00 f7 e1 83 c2 {SETTLE_MIN:02x}")  # edx = eax * SPAN >> 32 ; edx += MIN
    a.b("8b c7 f7 ea b9 64 00 00 00 f7 f9 59")          # eax = full * pct / 100 ; ecx = person
    a.b("6a 00 6a 00 50 6a 00 6a 04 55 51 b9"); a.d(TRANSFER_MANAGER)
    a.call(RELEASE)                                     # release(person, team, 4, 0, settlement, 0, 0)
    a.jmp("done")
    a.label("mark")
    a.b("80 4f 32 80"); a.jmp("done")
    a.label("notsurplus")
    if unlist:
        a.call(unlist)                                  # UNLIST_JUNIOR (edi = contract, esi = player, ebp = team)
    a.b("80 67 32 7f"); a.jmp("done")
    for reason, name in ((1, "r_away"), (2, "r_pending"), (3, "r_type")):
        a.label(name)
        a.b(f"6a {reason:02x}"); a.call("sink"); a.b("83 c4 04"); a.jmp("done")
    a.label("done")
    if as_function:                                     # SURPLUS_ONE(member, ai manager), ECX -> {club}
        a.b("61 c2 08 00")
    else:
        a.b("61 83 ec 10 53 55 56")                     # popad + the replaced code
        a.jmp(REVIEW_CONT)
    a.label("sink")                                     # SINK(reason): no-op, a hook point for the tracer
    a.b("8b 44 24 04 90 90 90 c3")
    return a.build()


def status_cave():
    """Keeps listed surplus foreigners "Not Needed" (squad status 7). See reports/squad_status.

    The AI re-rates every squad status each time an AI club manages its squad (FUN_007c7bf0 ->
    FUN_00b59850 -> contract vfunc +0x84 from 00b599be), computing it from ability alone
    (FUN_0163e2b0 -> FUN_00a013d0), which never looks at the transfer-listed flag. So the 7 that
    listing sets was overwritten within a day. Contract +0x32 has no spare bit for a marker (bits
    0-6 are the game's, 7 is surplus_cave's Jan/Jul mark), so the setter asks IS_SURPLUS instead.

    IS_SURPLUS(contract), cdecl, AL = 1 when the contract is transfer-listed (+0x32 bit 0), its team
    (+0x8, the club's first team) is an AI club, and CHECK(team, player, RANK|SKIP_CONTRACT) says
    the player is surplus: exactly surplus_cave's test, so it stops as soon as he isn't surplus.

    Hook at STATUS_SETTER's entry (every squad-status write goes through it): a re-rating to 1-6
    of an IS_SURPLUS contract is turned into 7. Writes of 7 and of 0xff (unset), human clubs and
    unlisted players take the fast path untouched. Every changed write calls KEPT(original status)
    for the tracer.

    KEEP7(contract, club), stdcall, called by surplus_cave for listed surplus players: sets status
    7 through the setter when it is 1-6 (fixes saves rated before this hook, and direct writes)."""
    a = Asm(IS_SURPLUS)
    a.b("55 8b ec 53 56 57")                            # IS_SURPLUS
    a.b("8b 75 08 33 c0")                               # esi = contract ; result 0
    a.b("85 f6"); a.jcc("84", "out")
    a.b("f6 46 32 01"); a.jcc("84", "out")              # not transfer-listed
    a.b("8b 5e 08 85 db"); a.jcc("84", "out")           # ebx = its team (club's first team)
    a.b("80 7b 23 00"); a.jcc("85", "out")              # clubs only
    a.b("83 7b 10 00"); a.jcc("84", "out")
    a.b("6a 01 8b cb"); a.call(HUMAN_TEAM)
    a.b("84 c0"); a.jcc("85", "out0")                   # human clubs: never
    a.b("8b 4e 04 85 c9"); a.jcc("84", "out0")          # person
    a.b("8b 01 ff 90 78 03 00 00 85 c0"); a.jcc("84", "out0")  # player = person->vfunc_0x378()
    a.b(f"6a {RANK | SKIP_CONTRACT:02x} 50 53"); a.call(CHECK); a.b("83 c4 0c")
    a.jmp("out")
    a.label("out0")
    a.b("33 c0")
    a.label("out")
    a.b("5f 5e 5b 5d c3")
    a.label("hook")                                     # STATUS_SETTER entry: ECX = contract
    a.b("8a 44 24 04 fe c8 3c 05"); a.jcc("87", "orig") # only re-ratings to 1..6
    a.b("51 51"); a.call(IS_SURPLUS); a.b("83 c4 04 59")
    a.b("84 c0"); a.jcc("84", "orig")
    a.b("ff 74 24 04"); a.call("kept"); a.b("83 c4 04")  # KEPT(original status)
    a.b("c7 44 24 04 07 00 00 00")                      # status = 7 (Not Needed)
    a.label("orig")
    a.b("ff 74 24 08 8b d1")                            # the replaced code
    a.jmp(STATUS_SETTER_CONT)
    a.label("keep7")                                    # KEEP7(contract, club), stdcall
    a.b("56 8b 74 24 08 8b ce 8b 06 ff 90 80 00 00 00")  # al = status
    a.b("fe c8 3c 05"); a.jcc("87", "k_done")           # already 7 (or unset): nothing to do
    a.b("ff 74 24 0c 6a 07 8b ce 8b 06 ff 90 84 00 00 00")  # contract->set_status(7, club)
    a.label("k_done")
    a.b("5e c2 08 00")
    a.label("kept")                                     # KEPT(status): no-op, a hook point for the tracer
    a.b("8b 44 24 04 90 90 90 c3")
    code = a.build()
    return code, a.labels["hook"], a.labels["keep7"]


def inject_cave():
    """FUN_01063090(ctx, list, p3, fixture) entry. Club lists only:
    - from FUN_011a6b90 (registered squad): type 0x15 all_foreign_players_in_squad <= CAP;
    - from FUN_01062190 with a fixture (match-day rules): type 0x04 all_foreign_players_in_match_squad
      <= CAP.
    An existing maximum of that type is tightened to CAP, else a new rule is appended (lists with
    15 rules are left alone: the counter structs hold 15)."""
    a = Asm(INJECT_CAVE)
    a.b("60 8b 44 24 20 3d"); a.d(RET_REGISTERED); a.jcc("85", "group")
    a.b("bd 15 00 00 00"); a.jmp("common")              # ebp = 0x15
    a.label("group")
    a.b("3d"); a.d(RET_GROUP_1); a.jcc("84", "fixture")
    a.b("3d"); a.d(RET_GROUP_2); a.jcc("85", "done")
    a.label("fixture")
    a.b("83 7c 24 30 00"); a.jcc("84", "done")          # only lists built for a fixture
    a.b("bd 04 00 00 00")                               # ebp = 0x04
    a.label("common")
    a.b("8b 54 24 24 85 d2"); a.jcc("84", "done")
    a.b("80 7a 23 00"); a.jcc("85", "done")             # clubs only
    a.b("8b 5c 24 28 85 db"); a.jcc("84", "done")
    a.b("8b 33 8b 4b 04 8b f9 2b fe c1 ff 02")          # esi = begin ; ecx = end ; edi = count
    a.label("scan")
    a.b("3b f1"); a.jcc("83", "notfound")
    a.b("8b 06 66 39 68 0c"); a.jcc("85", "next")
    a.b("80 78 0e ff"); a.jcc("85", "next")
    a.b("83 78 08"); a.b(f"{CAP:02x}"); a.jcc("8e", "done")
    a.b("c7 40 08"); a.d(CAP); a.jmp("done")            # tighten an existing cap
    a.label("next")
    a.b("83 c6 04"); a.jmp("scan")
    a.label("notfound")
    a.b("83 ff 0f"); a.jcc("83", "done")
    a.call(RULE_POOL)
    a.b("6a 10 8b c8"); a.call(POOL_ALLOC)
    a.b("85 c0"); a.jcc("84", "done")
    a.b("33 c9 89 08 89 48 04 c7 40 08"); a.d(CAP)
    a.b("89 68 0c c6 40 0e ff")                         # type = ebp ; compare 0xff (maximum)
    a.b("50 54 8b cb"); a.call(VEC_PUSH_BACK); a.b("58")
    a.label("done")
    a.b("61 55 8b ec 83 e4 f8")                         # popad + the replaced prologue
    a.jmp(RULES_CONT)
    return a.build()


def jmp_patch(site, target, length):
    code = b"\xe9" + struct.pack("<i", target - (site + 5))
    return (code + b"\x90" * (length - 5)).hex(" ")


def cave(va, code):
    return {"va": va, "original": " ".join(["00"] * len(code)), "patched": code.hex(" ")}


def site(va, original, target, note):
    n = len(bytes.fromhex(original.replace(" ", "")))
    return {"offset": off(va), "original": original, "patched": jmp_patch(va, target, n)}  # note: comment only



# --- nostalgia_3_plus_2 ---------------------------------------------------------------------------
# UEFA's "3+2" (1991-92 to 1995-96): in a match squad, at most 3 foreigners plus 2 "assimilated"
# foreigners. Assimilated is approximated by FM's homegrown-from-nation status (the test rule type
# 0x59 uses, FUN_016033c0 != 0). Two match-day rules are stored in every club competition's rule list (p32_store_cave):
#   all_foreign_players_in_match_squad (type 0x04) <= 5             (all foreigners)
#   all_foreign_players_in_match_squad (type 0x04) <= 3, ref MAGIC  (foreigners not homegrown in
#                                                                     the nation)
# The second rule is marked by MAGIC in its ref field (+0x4, ignored by the game when the tag at
# +0x0 is 0). The squad counter FUN_00f8c610 passes each rule's {tag, ref} to the per-player
# counter FUN_01605ae0; a hook in its foreign case skips homegrown-from-nation players for that rule.
MAGIC = 0x3250334E          # "N3P2"
FOREIGN_LIMIT = 3
FOREIGN_TOTAL = 5
P32_COUNT_CAVE = 0x020C16C8   # after status_cave (ends <= 0x020C16C6), before AI_CAVE
P32_STORE_CAVE = INJECT_CAVE   # shares this cave range with nostalgia_foreign_cap_rules (exclusive)
P32_INJECT_CAVE = P32_STORE_CAVE  # (old name, kept for the UI patch's assert)
GROUP_RULES_FN = 0x01062190   # thiscall(rule group; ctx, list out, fixture, ...): builds a club's rule list
GROUP_RULES_CONT = 0x01062196
VEC_POOL = 0x00F8E380         # returns the pool for rule-list vectors (as the rule loader FUN_011c8170)
VEC_CTOR = 0x00F8E4E0         # thiscall(vector): construct an empty rule-list vector
P32_ADDRULE = 0x020C1F80      # in the slack after CHECK (badge cave no longer used)
COUNT_CASE = 0x01606539     # FUN_01605ae0 case 2/3/4/0x15/0x7e: mov eax,[ebp+0xc] ; test eax,eax ; je 01605b09
COUNT_CASE_CONT = 0x01606544
COUNT_RETURN = 0x01606562   # the case's epilogue (returns EAX)
COUNT_NONE = 0x01605b09     # "doesn't count"
HOMEGROWN = 0x016033C0      # thiscall(player; ctx, 0): homegrown status bits (0 = not homegrown)
FROM_SQUAD_COUNTER = 0x00F8C699  # return address of FUN_00f8c610's call (arg 9 = &{tag, ref})


def p32_count_cave():
    a = Asm(P32_COUNT_CAVE)
    a.b("8b 45 0c 85 c0"); a.jcc("84", COUNT_NONE)      # the replaced code
    a.b("81 7d 04"); a.d(FROM_SQUAD_COUNTER); a.jcc("85", "back")
    a.b("66 83 7d 08 04"); a.jcc("85", "back")          # type 0x04 only
    a.b("8b 55 28 81 7a 04"); a.d(MAGIC); a.jcc("85", "back")
    a.b("6a 00 50 8b cf"); a.call(HOMEGROWN)            # assimilated (homegrown from nation)?
    a.b("84 c0 8b 45 0c"); a.jcc("84", "back")
    a.b("33 c0"); a.jmp(COUNT_RETURN)                   # assimilated: doesn't count for this rule
    a.label("back")
    a.jmp(COUNT_CASE_CONT)
    return a.build()


def p32_store_cave():
    """FUN_01062190 entry (thiscall: ECX = a competition's rule group; arg 1 = team). Puts 3+2 into
    the group's STORED squad-selection rule list ([group+0x34]), the list the game saves with the
    competition, the first time the group is used for a club team:
      - type-0x04 maxima above FOREIGN_TOTAL are tightened to FOREIGN_TOTAL (in place);
      - if the list has no type-0x04 maximum <= 3 of its own, {0x04 <= 5} (unless a 4..5 maximum is
        already there) and the marked non-assimilated {0x04 <= 3, ref MAGIC} are added: the group
        gets a NEW vector (old rule pointers + the new rules, from the game's own pools) which is
        then published with one pointer write, so a thread reading the old list is never disturbed
        (the old vector is deliberately leaked, once per group);
      - a list that already has 3+2 (a save from this mode) is left alone; if its <= 3 rule lost the
        marker in the save (only fields the game saves are guaranteed), the marker is restored when
        the list also has a 4..5 maximum (dword write only);
      - a list whose own data already caps foreigners at <= 3 (stricter) is left alone.
    Lists with 14 or more rules are left alone (the counters hold 15). Competitions with no stored
    list get a new one with the two rules."""
    a = Asm(P32_STORE_CAVE)
    a.b("60 8b 54 24 24 85 d2"); a.jcc("84", "done")    # pushad ; edx = team
    a.b("80 7a 23 00"); a.jcc("85", "done")             # club teams only
    a.b("8b 74 24 18 8b 5e 34")                         # esi = group ; ebx = stored list
    a.b("33 ed 33 d2 85 db"); a.jcc("84", "decide")     # ebp = found flags ; edx = unmarked <= 3 rule
    a.b("8b 3b 8b 4b 04")                               # edi = begin ; ecx = end
    a.label("scan")
    a.b("3b f9"); a.jcc("83", "decide")
    a.b("8b 07 83 c7 04 85 c0"); a.jcc("84", "scan")
    a.b("66 83 78 0c 04"); a.jcc("85", "scan")          # type 0x04
    a.b("80 78 0e ff"); a.jcc("85", "scan")             # maximum
    a.b("81 78 04"); a.d(MAGIC); a.jcc("85", "unmarked")
    a.b("83 cd 02"); a.jmp("scan")                      # our marked rule: 3+2 already there
    a.label("unmarked")
    a.b("83 78 08 03"); a.jcc("8f", "total")
    a.b("8b d0"); a.jmp("scan")                         # an unmarked <= 3 maximum
    a.label("total")
    a.b(f"83 cd 01 83 78 08 {FOREIGN_TOTAL:02x}"); a.jcc("8e", "scan")
    a.b("c7 40 08"); a.d(FOREIGN_TOTAL); a.jmp("scan")  # tighten > 5 to 5
    a.label("decide")
    a.b("f7 c5 02 00 00 00"); a.jcc("85", "done")       # already has 3+2
    a.b("85 d2"); a.jcc("84", "build")
    a.b("f7 c5 01 00 00 00"); a.jcc("84", "done")       # stricter data rule only: keep it
    a.b("c7 42 04"); a.d(MAGIC); a.jmp("done")          # restore the marker (save from this mode)
    a.label("build")
    a.b("85 db"); a.jcc("84", "fresh")
    a.b("8b 43 04 2b 03 83 f8 38"); a.jcc("83", "done") # 14+ rules: leave alone
    a.label("fresh")
    a.call(VEC_POOL)
    a.b("6a 10 8b c8"); a.call(POOL_ALLOC)
    a.b("85 c0"); a.jcc("84", "done")
    a.b("8b c8"); a.call(VEC_CTOR)
    a.b("85 c0"); a.jcc("84", "done")
    a.b("8b f8 56 85 db"); a.jcc("84", "add")          # edi = new list ; push group
    a.b("8b 43 0c 89 47 0c 8b 33")                      # copy the list's flags ; esi = old begin
    a.label("copy")
    a.b("3b 73 04"); a.jcc("83", "add")
    a.b("8b 06 50 54 8b cf"); a.call(VEC_PUSH_BACK)    # new.push_back(old rule)
    a.b("58 83 c6 04"); a.jmp("copy")
    a.label("add")
    a.b("f7 c5 01 00 00 00"); a.jcc("85", "magic")
    a.b(f"6a 00 6a {FOREIGN_TOTAL:02x}"); a.call(P32_ADDRULE)
    a.label("magic")
    a.b("68"); a.d(MAGIC); a.b(f"6a {FOREIGN_LIMIT:02x}"); a.call(P32_ADDRULE)
    a.b("5e 89 7e 34")                                  # pop group ; publish the new list
    a.label("done")
    a.b("61 55 8b ec 83 e4 f8")                         # popad + the replaced prologue
    a.jmp(GROUP_RULES_CONT)
    return a.build()


def p32_addrule():
    """stdcall ADDRULE(value, ref), EDI = rule list: append {tag 0, ref, value, type 0x04, maximum},
    allocated from the game's SQUAD_SELECTION_RULE pool."""
    a = Asm(P32_ADDRULE)
    a.call(RULE_POOL)
    a.b("6a 10 8b c8"); a.call(POOL_ALLOC)
    a.b("85 c0"); a.jcc("84", "full")
    a.b("33 c9 89 08 8b 4c 24 08 89 48 04 8b 4c 24 04 89 48 08")
    a.b("c7 40 0c 04 00 ff 00")                         # type 0x04, compare 0xff (maximum)
    a.b("50 54 8b cf"); a.call(VEC_PUSH_BACK); a.b("58")
    a.label("full")
    a.b("c2 08 00")
    return a.build()


_P32_COUNT = p32_count_cave()
_P32_STORE = p32_store_cave()
_P32_ADDRULE = p32_addrule()
assert P32_STORE_CAVE + len(_P32_STORE) <= CAVE_END
assert P32_ADDRULE + len(_P32_ADDRULE) <= 0x020C2000

_STATUS, STATUS_HOOK, KEEP7 = status_cave()
assert _STATUS[:4] == struct.pack("<I", IS_SURPLUS_SIG)
assert IS_SURPLUS + len(_STATUS) <= P32_COUNT_CAVE and P32_COUNT_CAVE + len(_P32_COUNT) <= AI_CAVE
UI_RULES_CAVE_START = 0x020C1840  # = UI_RULES_CAVE (nostalgia_3_plus_2_ui), defined further down
_CHECK = check_routine()
_AI_BLOCK = ai_cave(0)
_AI_RANK = ai_cave(RANK)
_OFFER = offer_cave()
_AI_OFFER = ai_offer_cave()
_JOIN = join_cave()
_SURPLUS = surplus_cave()
_INJECT = inject_cave()
# _AI_OFFER may run into JOIN_CAVE: that cave belongs to nostalgia_foreign_cap only, which can't be
# combined with nostalgia_foreign_cap_ai (they share CHECK and the AI site).
assert AI_CAVE + len(_AI_RANK) <= OFFER_CAVE and OFFER_CAVE + len(_AI_OFFER) <= UI_RULES_CAVE_START
assert SURPLUS_CAVE + len(_SURPLUS) <= CHECK and CHECK + len(_CHECK) <= 0x020C2000
assert OFFER_CAVE + len(_OFFER) <= JOIN_CAVE
assert JOIN_CAVE + len(_JOIN) <= 0x020C1840 and INJECT_CAVE + len(_INJECT) <= CAVE_END
assert 0x020C1C00 <= SURPLUS_CAVE and SURPLUS_CAVE + len(_SURPLUS) <= 0x020C2000

_AI_SITE = site(AI_SITE, "8b cb e8 92 eb f8 00 84 c0 74 4c", AI_CAVE,
                "make_transfer_decision_for_player 005181c7: mov ecx,ebx ; call 014a6d60 ; test al,al ;"
                " je 0051821e -> jmp AI_CAVE ; nop x6")

PATCHES = {
    "nostalgia_3_plus_2": [
        cave(P32_STORE_CAVE, _P32_STORE),
        cave(P32_ADDRULE, _P32_ADDRULE),
        cave(P32_COUNT_CAVE, _P32_COUNT),
        site(GROUP_RULES_FN, "55 8b ec 83 e4 f8", P32_STORE_CAVE,
             "FUN_01062190 entry: push ebp ; mov ebp,esp ; and esp,-8 -> jmp P32_STORE_CAVE ; nop"),
        site(COUNT_CASE, "8b 45 0c 85 c0 0f 84 c5 f5 ff ff", P32_COUNT_CAVE,
             "FUN_01605ae0 01606539: mov eax,[ebp+0xc] ; test eax,eax ; je 01605b09 -> jmp P32_COUNT_CAVE ; nop x6"),
    ],
    "nostalgia_foreign_cap_rules": [
        cave(INJECT_CAVE, _INJECT),
        site(RULES_FN, "55 8b ec 83 e4 f8", INJECT_CAVE,
             "FUN_01063090 entry: push ebp ; mov ebp,esp ; and esp,-8 -> jmp INJECT_CAVE ; nop"),
    ],
    "nostalgia_foreign_cap_ai": [
        cave(CHECK, _CHECK),
        cave(AI_CAVE, _AI_RANK),
        cave(OFFER_CAVE, _AI_OFFER),
        site(OFFER_SITE, "8b 6c 24 2c 85 ed 0f 84 84 00 00 00", OFFER_CAVE,
             "FUN_006f69f0 006f6a3d -> jmp OFFER_CAVE (AI buyers only)"),
        cave(SURPLUS_CAVE, _SURPLUS),
        _AI_SITE,
        site(REVIEW_SITE, "83 ec 10 53 55 56", SURPLUS_CAVE,
             "FUN_006296b0 entry: sub esp,0x10 ; push ebx ; push ebp ; push esi -> jmp SURPLUS_CAVE ; nop"),
        cave(IS_SURPLUS, _STATUS),
        site(STATUS_SETTER, "ff 74 24 08 8b d1", STATUS_HOOK,
             "FUN_015c8920 (contract set_squad_status) entry: push [esp+8] ; mov edx,ecx -> jmp STATUS_HOOK ; nop"),
    ],
    # Optional hard signing block (the first design); not in the nostalgia set.
    "nostalgia_foreign_cap": [
        cave(CHECK, _CHECK),
        cave(AI_CAVE, _AI_BLOCK),
        cave(OFFER_CAVE, _OFFER),
        cave(JOIN_CAVE, _JOIN),
        site(OFFER_SITE, "8b 6c 24 2c 85 ed 0f 84 84 00 00 00", OFFER_CAVE,
             "FUN_006f69f0 006f6a3d: mov ebp,[esp+0x2c] ; test ebp,ebp ; jz 006f6acd -> jmp OFFER_CAVE ; nop x7"),
        _AI_SITE,
        site(JOIN_SITE, "83 ec 18 53 8b 5c 24 20", JOIN_CAVE,
             "FUN_00b9c670 entry: sub esp,0x18 ; push ebx ; mov ebx,[esp+0x20] -> jmp JOIN_CAVE ; nop x3"),
    ],
}


# --- nostalgia_3_plus_2_ui ------------------------------------------------------------------------
# UI companion to nostalgia_3_plus_2 (whose rules live only in per-call fixture-list copies, so the UI,
# which reads the competition's stored rules, never saw them). See reports/fgn_badge/README.md.
#   badge  FUN_00dbc070 (GAME_PLAYER_STATUS_FLAGS vfunc +0x1c's rule part) sets status bit +4 0x1000000
#          only for foreign-type rules in the competition's stored list; the squad list then shows the
#          'Fgn' icon (text 0x37ac6 "Fgn", tooltip 0x37ac7 "Foreign", FUN_01e47ef7). After its rule loop
#          the cave sets that bit when the game's foreign test (FUN_015440e0(person; team, 1, 1), exactly
#          what FUN_01605ae0 does for rule type 0x04) says the player is foreign. Clubs only, and only
#          where the original code reached the loop (stored rule list present, no FM Classic unlock).
#   rules  FUN_01064160 builds the competition rules screen: a deep copy of the rule group's list with
#          match-day types removed is written as record 0x28 ("squad rules", FUN_011b3910). The cave
#          appends two display-only rules {0x04, <= 5} and {0x04, <= 3} to that local copy (pool-allocated
#          like the game's own; FUN_01064160 frees the copy's rules through the pool on exit), for
#          competitions with a nation (league/cup; [[comp]+0x44]). Shown as "Maximum of 5 foreign
#          players" and "Maximum of 3 foreign players".
# Neither touches saved data or rule evaluation: the status bit is an icon flag, the record a UI packet.
UI_BADGE_CAVE = 0x020C1FC8   # leaves 0x020C1F5B-0x020C1FC7 free for CHECK to grow
UI_RULES_CAVE = UI_RULES_CAVE_START   # unused gap between JOIN_CAVE (<= 0x020C1840) and INJECT_CAVE (0x020C18D0)
BADGE_SITE = 0x00DBC7AC      # FUN_00dbc070 after its rule loop: mov eax,[esp+0x10] ; cmp al,2
BADGE_CONT = 0x00DBC7B2      # jne 00dbc916 (flags from the replayed cmp)
RULES_SCREEN_SITE = 0x010642B2  # FUN_01064160: mov ebx,[esp+0x60] ; mov eax,esi (before the 0x28 write)
RULES_SCREEN_CONT = 0x010642B8  # sub eax,edi ; sar eax,2 ; test ; je ; ... call 011b3910
FGN_BIT = 0x01000000         # status +4: 'Fgn' icon (0x02000000 = 'Fgn' with the non-EU tooltip)


def ui_badge_cave():
    """FUN_00dbc070 at 00dbc7ac: EBX = player, EBP = team, EDI = status flags, ECX = rule list."""
    a = Asm(UI_BADGE_CAVE)
    a.b("51 52")                                        # keep ecx (the list, used next) and edx
    a.b("f7 47 04 00 00 00 03"); a.jcc("85", "done")    # already Fgn (data rule) or non-EU Fgn
    a.b(VBASE_ECX_EBX + " 6a 01 6a 01 55"); a.call(IS_FOREIGN)   # foreign for this team?
    a.b("84 c0"); a.jcc("84", "done")
    a.b("81 4f 04"); a.d(FGN_BIT)                       # status +4 |= Fgn
    a.label("done")
    a.b("5a 59 8b 44 24 10 3c 02")                      # pop edx, ecx + the replaced code
    a.jmp(BADGE_CONT)
    return a.build()


def ui_rules_cave():
    """FUN_01064160 at 010642b2: local rule list (copy) at [esp+0x48], cached begin/end in EDI/ESI
    (and [esp+0x10]); [esp+0x60] = the stage object whose +0x3c is the competition. EAX, ECX and EDX
    are dead here (reloaded before use)."""
    a = Asm(UI_RULES_CAVE)
    a.b("8b 5c 24 60 8b 43 3c 85 c0"); a.jcc("84", "back")   # competition
    a.b("83 78 44 00"); a.jcc("84", "back")             # with a nation (not international)
    a.b("8d 5c 24 48")                                  # ebx = the local list
    a.b(f"6a {FOREIGN_TOTAL:02x}"); a.call("addrule")
    a.b(f"6a {FOREIGN_LIMIT:02x}"); a.call("addrule")
    a.b("8b 7c 24 48 8b 74 24 4c 89 7c 24 10")         # reload begin/end (+ its [esp+0x10] copy)
    a.b("8b 5c 24 60")
    a.label("back")
    a.b("8b c6"); a.jmp(RULES_SCREEN_CONT)              # the replaced code (mov ebx,[esp+0x60] done)
    a.label("addrule")                                  # stdcall(value); ebx = list
    a.call(RULE_POOL)
    a.b("6a 10 8b c8"); a.call(POOL_ALLOC)
    a.b("85 c0"); a.jcc("84", "full")
    a.b("33 c9 89 08 89 48 04 8b 4c 24 04 89 48 08")   # tag 0, ref 0, value
    a.b("c7 40 0c 04 00 ff 00")                         # type 0x04, compare 0xff (maximum)
    a.b("50 54 8b cb"); a.call(VEC_PUSH_BACK); a.b("58")
    a.label("full")
    a.b("c2 04 00")
    return a.build()


VBASE_ECX_EBX = "8b 43 04 8d 4b 04 03 48 04"   # ecx = person (virtual base) of player in ebx
_UI_BADGE = ui_badge_cave()
_UI_RULES = ui_rules_cave()
assert CHECK + len(_CHECK) <= UI_BADGE_CAVE and UI_BADGE_CAVE + len(_UI_BADGE) <= 0x020C2000
assert JOIN_CAVE + len(_JOIN) <= UI_RULES_CAVE
assert UI_RULES_CAVE + len(_UI_RULES) <= min(INJECT_CAVE, P32_INJECT_CAVE)

# With 3+2 stored in the competitions' rule lists, FUN_00dbc070 (player status flags) sets the 'Fgn'
# badge natively from the stored type-0x04 rules, so the badge cave (ui_badge_cave, kept above for
# reference) is no longer part of the patch. The rules screen still needs the display lines:
# FUN_01064160 drops match-day types (0x04 included) from what it shows.
PATCHES["nostalgia_3_plus_2_ui"] = [
    cave(UI_RULES_CAVE, _UI_RULES),
    site(RULES_SCREEN_SITE, "8b 5c 24 60 8b c6", UI_RULES_CAVE,
         "FUN_01064160 010642b2: mov ebx,[esp+0x60] ; mov eax,esi -> jmp UI_RULES_CAVE ; nop"),
]


# =====================================================================================================
# Stripped-back nostalgia set (reports/transfer_ai/native_mode.md): the game's own "foreign-limited
# league" AI mode does the planning; these patches only add what it lacks.
#
#   nostalgia_3_foreigners     one stored rule per competition: all_foreign_players_in_match_squad
#                              (type 0x04) <= 3. Switches on the native mode (shortlist +0xea).
#   nostalgia_3_foreigners_ui  the rules screen shows "Maximum of 3 foreign players".
#   nostalgia_foreign_cap_ai   surplus ladder (senior foreigners outside the club's best 3 by CURRENT
#                              ABILITY are listed for sale and loan, marked Jan/Jul, released with a
#                              20-75% settlement Jun/Dec), the status hook keeping them "Not Needed",
#                              unlisting of under-21s listed by the old rule, and the anti-churn gate
#                              for foreign targets. No offer gate, no "short" switch.
# =====================================================================================================
SENIOR_AGE = 21              # surplus and anti-churn only look at foreigners of this age or older
BEST_FOREIGN = FOREIGN_LIMIT  # foreigners a club keeps (best by current ability)
CHURN_DAYS = 365             # anti-churn: a senior foreigner who joined within this many days
AGE_DATE = 0x023A01C4        # the date the game computes ages against (person vfunc +0xd0 argument)
CHECK_CA = CHECK             # 0x020C1E00: replaces the value-ranked CHECK in nostalgia_foreign_cap_ai
UNLIST_CAVE = 0x020C16C8     # freed by the 3+2 counter hook
# The anti-churn gate (about 520 bytes) lives in .text's raw data, in the 1074-byte zero run
# 0x02047956-0x02047D87 (the body of a function moved to helper.dll; no references, still zero at
# runtime; see reports/transfer_ai/README.md section 8.2). patches_transfer_ai.py uses 0x02047B80+.
CHURN_CAVE = 0x02047960
CHURN_CAVE_END = 0x02047B80
STORE3_CAVE = P32_STORE_CAVE
CHURN_MARK = b"CHRN"         # 4 data bytes before the anti-churn SINK, for the tracer to find it
UNLIST_MARK = b"UNLS"        # 4 data bytes before the unlist SINK

# person / player vfunc calls
AGE_CALL = "68 " + AGE_DATE.to_bytes(4, "little").hex(" ") + " 8b 01 ff 90 d0 00 00 00"  # push date ; age (ecx = person)
CA_CALL = "8b 01 ff 10 0f b7 c0"                                                        # eax = CA (ecx = player)


def check_ca_routine():
    """CHECK(ctx, player, flags), cdecl (flags ignored): AL = 1 when `player` is a SURPLUS foreigner of
    ctx's club: foreign to the club (type-0x15 test, FUN_015440e0 with ctx = a club team), aged
    SENIOR_AGE or older, and the club has BEST_FOREIGN or more other senior foreigners with a higher
    current ability (player vfunc +0; ties broken by object address, so exactly BEST_FOREIGN survive).
    Counts every team of the club (FUN_0149f3c0 / FUN_0149f260), skipping the players the game's squad
    counter skips (person vfunc +0x2bc, player vfunc +0x16c(0,0)). Used by the surplus ladder and
    IS_SURPLUS (status hook, bosman retain cave)."""
    a = Asm(CHECK_CA)
    a.b("55 8b ec 53 56 57 83 ec 18")   # locals: -0x10 his CA, -0x14 n, -0x18 team i, -0x1c cursor, -0x20 member
    a.b("8b 5d 08 8b 75 0c 33 c0")      # ebx = ctx ; esi = player
    a.b("85 db"); a.jcc("84", "out")
    a.b("85 f6"); a.jcc("84", "out")
    a.b("80 7b 23 00"); a.jcc("85", "out")              # club teams only
    a.b("83 7b 10 00"); a.jcc("84", "out")
    a.b(VBASE_ECX_ESI + " 6a 01 6a 01 53"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "out0")                   # domestic: never surplus
    a.b(VBASE_ECX_ESI + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8c", "out0")    # under SENIOR_AGE: left to the game
    a.b("8b ce " + CA_CALL + " 89 45 f0")               # his CA
    a.b("33 c0 89 45 ec 89 45 e8")                      # n = 0 ; team index = 0
    a.label("teams")
    a.b("8b 4b 10"); a.call(TEAM_COUNT)
    a.b("3b 45 e8"); a.jcc("86", "done")
    a.b("ff 75 e8 8b 4b 10"); a.call(TEAM_AT)
    a.b("ff 45 e8 85 c0"); a.jcc("84", "teams")
    a.b("8b f8 8b 47 24 89 45 e4")                      # edi = team ; cursor = players begin
    a.label("members")
    a.b("8b 45 e4 3b 47 28"); a.jcc("83", "teams")
    a.b("83 45 e4 04 8b 00 85 c0"); a.jcc("84", "members")
    a.b("3b c6"); a.jcc("84", "members")                # not the player himself
    a.b("89 45 e0")
    a.b(VBASE_ECX_EAX + " 8b 01 ff 90 bc 02 00 00 84 c0"); a.jcc("85", "members")
    a.b("8b 4d e0 6a 00 6a 00 8b 01 ff 90 6c 01 00 00 84 c0"); a.jcc("85", "members")
    a.b("8b 45 e0 " + VBASE_ECX_EAX + " 6a 01 6a 01 53"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "members")                # domestic member
    a.b("8b 45 e0 " + VBASE_ECX_EAX + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8c", "members") # junior member
    a.b("8b 4d e0 " + CA_CALL)
    a.b("3b 45 f0"); a.jcc("8f", "count")               # higher CA: ahead of him
    a.jcc("8c", "members")                              # lower CA
    a.b("8b 45 e0 3b c6"); a.jcc("83", "members")       # equal CA: lower address ranks first
    a.label("count")
    a.b("ff 45 ec"); a.jmp("members")
    a.label("done")
    a.b(f"33 c0 83 7d ec {BEST_FOREIGN:02x}"); a.jcc("8c", "out")
    a.b("b0 01")
    a.label("out")
    a.b("8d 65 f4 5f 5e 5b 5d c3")
    a.label("out0")
    a.b("33 c0"); a.jmp("out")
    return a.build()


def unlist_cave():
    """UNLIST_JUNIOR, called by the surplus ladder for a player who is not surplus (registers as in
    surplus_cave: EDI = contract, ESI = player, EBP = club's first team; everything preserved). The old
    rule (best 5 by value, or 3 while short, at any age) listed foreigners under SENIOR_AGE: a contract
    that is transfer- AND loan-listed (+0x32 bits 0 and 3, as the ladder sets them), "Not Needed" (7),
    of a foreigner under SENIOR_AGE is unlisted (bits 0, 3 and the ladder's mark 7 cleared). The game's
    daily re-rating then gives him a normal status (the status hook no longer applies: not listed)."""
    a = Asm(UNLIST_CAVE)
    a.b("60 85 ff"); a.jcc("84", "out")
    a.b("8a 47 32 24 09 3c 09"); a.jcc("85", "out")     # listed for sale and for loan
    a.b("80 7f 30 07"); a.jcc("85", "out")              # Not Needed
    a.b("85 ed"); a.jcc("84", "out")
    a.b("39 5d 10"); a.jcc("85", "out")                 # EBP is EBX's team (type check)
    a.b(VBASE_ECX_ESI + " 6a 01 6a 01 55"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "out")
    a.b(VBASE_ECX_ESI + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8d", "out")     # seniors: the ladder's business
    a.b("80 67 32 76")                                  # clear listed, loan-listed, mark
    a.call("sink")
    a.label("out")
    a.b("61 c3")
    a.b(UNLIST_MARK.hex())
    a.label("sink")                                     # UNLISTED(): no-op hook point for the tracer
    a.b("90 90 90 90 c3")
    return a.build()


def churn_cave():
    """Anti-churn gate at 005181c7 in make_transfer_decision_for_player (EBX = club, EDI = target
    player, EBP = shortlist; replaced: mov ecx,ebx ; call 014a6d60 ; test al,al ; je 0051821e).
    For an AI club and a FOREIGN target (type-0x15 test against the club's first team): walk the club's
    teams and count its senior foreigners (aged SENIOR_AGE+, skipping the game's skipped players, whose
    contract (person vfunc +0x1d8) belongs to this club (+0x8 == first team: no loans in), and which
    aren't listed surplus (+0x32 bit 0 with status +0x30 == 7)); note whether any of them joined
    (contract +0x28 date) within CHURN_DAYS. The target is dropped (remove_target, reason 0xb, no bid)
    when the club has BEST_FOREIGN or more such seniors AND one of them joined recently. Otherwise, and
    for domestic targets and human clubs, the original code runs.
    SINK(reason) for the tracer: 1 = dropped, 2 = allowed (fewer than BEST_FOREIGN seniors),
    3 = allowed (none joined recently)."""
    a = Asm(CHURN_CAVE)
    a.b("85 ff"); a.jcc("84", "orig")
    a.b("60 83 ec 14")                                  # pushad ; locals [esp] n, +4 recent, +8 team i, +0xc cursor, +0x10 member
    a.b("8b 43 10 85 c0"); a.jcc("84", "skip")          # club's teams
    a.b("3b 43 14"); a.jcc("84", "skip")
    a.b("8b 30 85 f6"); a.jcc("84", "skip")             # esi = first team
    a.b("80 7e 23 00"); a.jcc("85", "skip")             # club teams only
    a.b("39 5e 10"); a.jcc("85", "skip")                # ... of this club (type check: team+0x10 = club)
    a.b("6a 01 8b ce"); a.call(HUMAN_TEAM)
    a.b("84 c0"); a.jcc("85", "skip")                   # human clubs: never
    a.b("8b c7 " + VBASE_ECX_EAX + " 6a 01 6a 01 56"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "skip")                   # domestic target: unaffected
    a.b("33 c0 89 04 24 89 44 24 04 89 44 24 08")       # n = recent = team index = 0
    a.label("teams")
    a.b("8b 4e 10"); a.call(TEAM_COUNT)
    a.b("3b 44 24 08"); a.jcc("86", "decide")
    a.b("ff 74 24 08 8b 4e 10"); a.call(TEAM_AT)
    a.b("ff 44 24 08 85 c0"); a.jcc("84", "teams")
    a.b("8b e8 8b 45 24 89 44 24 0c")                   # ebp = team ; cursor = players begin
    a.label("members")
    a.b("8b 44 24 0c 3b 45 28"); a.jcc("83", "teams")
    a.b("83 44 24 0c 04 8b 00 85 c0"); a.jcc("84", "members")
    a.b("89 44 24 10")
    a.b(VBASE_ECX_EAX + " 8b 01 ff 90 bc 02 00 00 84 c0"); a.jcc("85", "members")
    a.b("8b 4c 24 10 6a 00 6a 00 8b 01 ff 90 6c 01 00 00 84 c0"); a.jcc("85", "members")
    a.b("8b 44 24 10 " + VBASE_ECX_EAX + " 6a 01 6a 01 56"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "members")
    a.b("8b 44 24 10 " + VBASE_ECX_EAX + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8c", "members")
    a.b("8b 44 24 10 " + VBASE_ECX_EAX + " 8b 01 ff 90 d8 01 00 00")  # contract
    a.b("85 c0"); a.jcc("84", "members")
    a.b("39 70 08"); a.jcc("85", "members")             # contract with this club (no loans in)
    a.b("f6 40 32 01"); a.jcc("84", "senior")
    a.b("80 78 30 07"); a.jcc("84", "members")          # listed surplus: not counted
    a.label("senior")
    a.b("ff 04 24")                                     # n++
    a.b("0f b7 48 28 81 e1 ff 01 00 00 0f b7 50 2a")    # ecx = joined day of year ; edx = joined year
    a.b("0f b7 05"); a.d(TODAY + 2); a.b("2b c2 69 c0 6d 01 00 00")  # eax = (year today - year) * 365
    a.b("0f b7 15"); a.d(TODAY); a.b("81 e2 ff 01 00 00 03 c2 2b c1")  # + day today - day
    a.b("3d"); a.d(CHURN_DAYS); a.jcc("8d", "members")
    a.b("c7 44 24 04 01 00 00 00"); a.jmp("members")    # a senior foreigner joined recently
    a.label("decide")
    a.b(f"b9 02 00 00 00 83 3c 24 {BEST_FOREIGN:02x}"); a.jcc("8c", "allow")
    a.b("b9 03 00 00 00 83 7c 24 04 00"); a.jcc("84", "allow")
    a.b("6a 01"); a.call("sink"); a.b("83 c4 18 61")    # dropped: pop arg + locals ; popad
    a.b("8b 47 04 8b 40 04 83 c0 04 03 c7")             # eax = person
    a.b("6a 00 50 53 8b cd"); a.call(REMOVE_TARGET)     # shortlist->remove_target(club, person, 0)
    a.b("b0 01"); a.jmp(AI_DROPPED)                     # *param_9 = 0xb ; return 1
    a.label("allow")
    a.b("51"); a.call("sink"); a.b("83 c4 04")
    a.label("skip")
    a.b("83 c4 14 61")
    a.label("orig")
    a.b("8b cb"); a.call(AI_GATE)                       # the replaced code
    a.b("84 c0"); a.jcc("84", AI_GATE_NO)
    a.jmp(AI_GATE_YES)
    a.b(CHURN_MARK.hex())
    a.label("sink")                                     # SINK(reason): no-op hook point for the tracer
    a.b("8b 44 24 04 90 c3")
    return a.build()


def store3_cave():
    """FUN_01062190 entry (thiscall: ECX = a competition's rule group; arg 1 = team, intact at the
    entry). Puts all_foreign_players_in_match_squad (type 0x04) <= 3 into the group's STORED
    squad-selection rule list ([group+0x34], saved with the competition), the first time the group is
    used for a club team:
      - a type-0x04 maximum <= 3 already there (data, or a save from this mode, marked or not): done;
      - else the first type-0x04 maximum above 3 is tightened to 3 in place (dword write);
      - else {0x04 <= 3} is added: the group gets a NEW vector (old rule pointers + the rule, from the
        game's own pools), published with one pointer write (the old vector is leaked, once per group).
    Saves from the 3+2 build keep their <= 5 and marked <= 3 rules (harmless: <= 3 decides).
    Lists with 14 or more rules are left alone (the counters hold 15). Competitions with no stored list
    get a new one."""
    a = Asm(STORE3_CAVE)
    a.b("60 8b 54 24 24 85 d2"); a.jcc("84", "done")    # pushad ; edx = team
    a.b("80 7a 23 00"); a.jcc("85", "done")             # club teams only
    a.b("8b 74 24 18 8b 5e 34")                         # esi = group ; ebx = stored list
    a.b("33 d2 85 db"); a.jcc("84", "build")            # edx = first maximum above 3
    a.b("8b 3b 8b 4b 04")                               # edi = begin ; ecx = end
    a.b("85 ff"); a.jcc("84", "build")
    a.label("scan")
    a.b("3b f9"); a.jcc("83", "decide")
    a.b("8b 07 83 c7 04 85 c0"); a.jcc("84", "scan")
    a.b("66 83 78 0c 04"); a.jcc("85", "scan")          # type 0x04
    a.b("80 78 0e ff"); a.jcc("85", "scan")             # maximum
    a.b(f"83 78 08 {FOREIGN_LIMIT:02x}"); a.jcc("8e", "done")  # <= 3 already: done
    a.b("85 d2"); a.jcc("85", "scan")
    a.b("8b d0"); a.jmp("scan")
    a.label("decide")
    a.b("85 d2"); a.jcc("84", "build")
    a.b("c7 42 08"); a.d(FOREIGN_LIMIT); a.jmp("done")  # tighten in place
    a.label("build")
    a.b("85 db"); a.jcc("84", "fresh")
    a.b("8b 43 04 2b 03 83 f8 38"); a.jcc("83", "done") # 14+ rules: leave alone
    a.label("fresh")
    a.call(VEC_POOL)
    a.b("6a 10 8b c8"); a.call(POOL_ALLOC)
    a.b("85 c0"); a.jcc("84", "done")
    a.b("8b c8"); a.call(VEC_CTOR)
    a.b("85 c0"); a.jcc("84", "done")
    a.b("8b f8 56 85 db"); a.jcc("84", "add")          # edi = new list ; push group
    a.b("8b 43 0c 89 47 0c 8b 33")                      # copy the list's flags ; esi = old begin
    a.b("85 f6"); a.jcc("84", "add")
    a.label("copy")
    a.b("3b 73 04"); a.jcc("83", "add")
    a.b("8b 06 50 54 8b cf"); a.call(VEC_PUSH_BACK)    # new.push_back(old rule)
    a.b("58 83 c6 04"); a.jmp("copy")
    a.label("add")
    a.b(f"6a 00 6a {FOREIGN_LIMIT:02x}"); a.call(P32_ADDRULE)
    a.b("5e 89 7e 34")                                  # pop group ; publish the new list
    a.label("done")
    a.b("61 55 8b ec 83 e4 f8")                         # popad + the replaced prologue
    a.jmp(GROUP_RULES_CONT)
    return a.build()


def ui_rules3_cave():
    """ui_rules_cave with one display rule: {0x04, <= 3} ("Maximum of 3 foreign players")."""
    a = Asm(UI_RULES_CAVE)
    a.b("8b 5c 24 60 8b 43 3c 85 c0"); a.jcc("84", "back")   # competition
    a.b("83 78 44 00"); a.jcc("84", "back")             # with a nation (not international)
    a.b("8d 5c 24 48")                                  # ebx = the local list
    a.call(RULE_POOL)
    a.b("6a 10 8b c8"); a.call(POOL_ALLOC)
    a.b("85 c0"); a.jcc("84", "reload")
    a.b(f"33 c9 89 08 89 48 04 c7 40 08 {FOREIGN_LIMIT:02x} 00 00 00")  # tag 0, ref 0, value 3
    a.b("c7 40 0c 04 00 ff 00")                         # type 0x04, compare 0xff (maximum)
    a.b("50 54 8b cb"); a.call(VEC_PUSH_BACK); a.b("58")
    a.label("reload")
    a.b("8b 7c 24 48 8b 74 24 4c 89 7c 24 10")         # reload begin/end (+ its [esp+0x10] copy)
    a.b("8b 5c 24 60")
    a.label("back")
    a.b("8b c6"); a.jmp(RULES_SCREEN_CONT)
    return a.build()


_CHECK_CA = check_ca_routine()
_UNLIST = unlist_cave()
_CHURN = churn_cave()
_STORE3 = store3_cave()
_UI_RULES3 = ui_rules3_cave()
_SURPLUS3 = surplus_cave(unlist=UNLIST_CAVE)
assert IS_SURPLUS + len(_STATUS) <= UNLIST_CAVE and UNLIST_CAVE + len(_UNLIST) <= UI_RULES_CAVE
assert 0x02047956 <= CHURN_CAVE and CHURN_CAVE + len(_CHURN) <= CHURN_CAVE_END
assert UI_RULES_CAVE + len(_UI_RULES3) <= STORE3_CAVE and STORE3_CAVE + len(_STORE3) <= CAVE_END
assert SURPLUS_CAVE + len(_SURPLUS3) <= CHECK_CA and CHECK_CA + len(_CHECK_CA) <= P32_ADDRULE
assert P32_ADDRULE + len(_P32_ADDRULE) <= 0x020C2000
assert _CHURN.count(CHURN_MARK) == 1 and _UNLIST.count(UNLIST_MARK) == 1

# The 3+2 patches are replaced (their names are gone from PATCHES; the builders above stay for
# reference). nostalgia_foreign_cap / nostalgia_foreign_cap_rules (optional, earlier designs) keep the
# value-ranked CHECK.
del PATCHES["nostalgia_3_plus_2"]
del PATCHES["nostalgia_3_plus_2_ui"]
PATCHES["nostalgia_3_foreigners"] = [
    cave(STORE3_CAVE, _STORE3),
    cave(P32_ADDRULE, _P32_ADDRULE),
    site(GROUP_RULES_FN, "55 8b ec 83 e4 f8", STORE3_CAVE,
         "FUN_01062190 entry: push ebp ; mov ebp,esp ; and esp,-8 -> jmp STORE3_CAVE ; nop"),
]
PATCHES["nostalgia_3_foreigners_ui"] = [
    cave(UI_RULES_CAVE, _UI_RULES3),
    site(RULES_SCREEN_SITE, "8b 5c 24 60 8b c6", UI_RULES_CAVE,
         "FUN_01064160 010642b2: mov ebx,[esp+0x60] ; mov eax,esi -> jmp UI_RULES_CAVE ; nop"),
]
PATCHES["nostalgia_foreign_cap_ai"] = [
    cave(CHECK_CA, _CHECK_CA),
    cave(IS_SURPLUS, _STATUS),
    site(STATUS_SETTER, "ff 74 24 08 8b d1", STATUS_HOOK,
         "FUN_015c8920 (contract set_squad_status) entry: push [esp+8] ; mov edx,ecx -> jmp STATUS_HOOK ; nop"),
    cave(UNLIST_CAVE, _UNLIST),
    cave(SURPLUS_CAVE, _SURPLUS3),
    site(REVIEW_SITE, "83 ec 10 53 55 56", SURPLUS_CAVE,
         "FUN_006296b0 entry: sub esp,0x10 ; push ebx ; push ebp ; push esi -> jmp SURPLUS_CAVE ; nop"),
    {"offset": off(CHURN_CAVE), "original": " ".join(["00"] * len(_CHURN)), "patched": _CHURN.hex(" ")},
    site(AI_SITE, "8b cb e8 92 eb f8 00 84 c0 74 4c", CHURN_CAVE,
         "make_transfer_decision_for_player 005181c7 -> jmp CHURN_CAVE ; nop x6"),
]


# =====================================================================================================
# Dec 2014 follow-up (reports/transfer_ai/investigation_dec2014.md):
#   - the anti-churn test becomes a shared routine CHURN_EVAL(club), used by
#       * the decision gate at 005181c7 (make_transfer_decision_for_player),
#       * the route gate at the two add_transfer_offer calls of the "offer a player to interested clubs"
#         route (FUN_01f33610 -> FUN_0094b700: 0094bf45, 0094b78f), which bypassed the decision,
#       * the candidate filter at 006f4706 (FUN_006f4290 adding a purchase candidate, FUN_016e6110);
#     the route gate and the candidate filter also apply the native brake (buyer's shortlist +0xea with
#     +0xb8 > 0: make_transfer_decision drops every foreign target then anyway);
#   - DOMESTIC_PRICE_FACTOR replaces the native x1.5 domestic valuation in FUN_009327d0.
# =====================================================================================================
DOMESTIC_PRICE_FACTOR = 1.2   # native foreign-limited mode: AI sellers' domestic key/first/rotation x this (vanilla 1.5)
CHURN_EVAL = 0x02047960       # cdecl CHURN_EVAL(club, target player or 0) -> EAX: 0 n/a (human, no teams, bad
                              # object), 1 drop (anti-churn), 2 allow (< BEST_FOREIGN seniors), 3 allow (none
                              # joined within CHURN_DAYS), 4 drop (anti-churn allows, target not an upgrade)
CHURN_GATE = 0x020C1740       # decision gate (005181c7)
ROUTE_GATE = 0x02047C60       # route gate (0094bf45 / 0094b78f), in the zero run
CAND_CAVE = 0x02047BC0        # candidate filter (006f4706)
PRICE_CONST = 0x02047D78      # the factor as a double (8 bytes, inside the zero run)
ZERO_RUN_END = 0x02047D88
ADD_OFFER = 0x00E65550        # TRANSFER_MANAGER::add_transfer_offer, thiscall, 4 args, ret 0x10
ADD_TARGET = 0x016E6110       # FUN_016e6110, thiscall, 7 args, ret 0x1c (target record)
ROUTE_SITES = (0x0094BF45, 0x0094B78F)   # call add_transfer_offer in FUN_0094b700 (both test eax == -1 next)
CAND_SITE = 0x006F4706        # call FUN_016e6110 in FUN_006f4290 (result unused)
PRICE_SITE = 0x009328C4       # FUN_009327d0: mulsd xmm0,[0x022d2348] -> operand address
ROUTE_MARK = b"ROUT"
CAND_MARK = b"CAND"


def first_team_checks(a, out_label):
    """EBX = club -> ESI = its first team, validated: team vector non-empty, first team a club team
    (+0x23 == 0) whose +0x10 is EBX (type check). Jumps to out_label on any failure."""
    a.b("8b 43 10 85 c0"); a.jcc("84", out_label)       # eax = teams begin
    a.b("3b 43 14"); a.jcc("84", out_label)             # empty
    a.b("8b 30 85 f6"); a.jcc("84", out_label)          # esi = first team
    a.b("80 7e 23 00"); a.jcc("85", out_label)          # club team
    a.b("39 5e 10"); a.jcc("85", out_label)             # team+0x10 == club


def churn_eval_routine():
    """One walk over the club's squads computes both the anti-churn state and the upgrade test.
    Upgrade: the target's CA (player vfunc +0) must be greater than the club's BEST_FOREIGN-th best
    senior foreigner's CA, over CHECK_CA's set (every team, foreign to the first team, SENIOR_AGE+,
    not retired-like or away; listed and loaned-in players included; the target himself excluded).
    Counted as: fewer than BEST_FOREIGN of them have a CA >= his (so a club with fewer than
    BEST_FOREIGN senior foreigners takes any foreigner). Target 0: no upgrade test."""
    a = Asm(CHURN_EVAL)
    a.b("55 8b ec 53 56 57 83 ec 1c")   # locals [esp] n, +4 recent, +8 team i, +0xc cursor, +0x10 member,
                                        # +0x14 target CA, +0x18 seniors with CA >= target CA
    a.b("8b 5d 08 85 db"); a.jcc("84", "out0")          # ebx = club
    first_team_checks(a, "out0")
    a.b("6a 01 8b ce"); a.call(HUMAN_TEAM)
    a.b("84 c0"); a.jcc("85", "out0")                   # human clubs: n/a
    a.b("c7 44 24 14 ff ff ff 7f")                      # target CA = INT_MAX (no target: nobody ahead)
    a.b("8b 4d 0c 85 c9"); a.jcc("84", "zero")
    a.b(CA_CALL + " 89 44 24 14")                       # target CA
    a.label("zero")
    a.b("33 c0 89 04 24 89 44 24 04 89 44 24 08 89 44 24 18")   # n = recent = team index = ahead = 0
    a.label("teams")
    a.b("8b cb"); a.call(TEAM_COUNT)
    a.b("3b 44 24 08"); a.jcc("86", "decide")
    a.b("ff 74 24 08 8b cb"); a.call(TEAM_AT)
    a.b("ff 44 24 08 85 c0"); a.jcc("84", "teams")
    a.b("8b f8 8b 47 24 89 44 24 0c")                   # edi = team ; cursor = players begin
    a.label("members")
    a.b("8b 44 24 0c 3b 47 28"); a.jcc("83", "teams")
    a.b("83 44 24 0c 04 8b 00 85 c0"); a.jcc("84", "members")
    a.b("89 44 24 10 3b 45 0c"); a.jcc("84", "members")  # the target himself (if in the squad)
    a.b(VBASE_ECX_EAX + " 8b 01 ff 90 bc 02 00 00 84 c0"); a.jcc("85", "members")   # retired-like
    a.b("8b 4c 24 10 6a 00 6a 00 8b 01 ff 90 6c 01 00 00 84 c0"); a.jcc("85", "members")  # away
    a.b("8b 44 24 10 " + VBASE_ECX_EAX + " 6a 01 6a 01 56"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "members")
    a.b("8b 44 24 10 " + VBASE_ECX_EAX + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8c", "members")
    a.b("8b 4c 24 10 " + CA_CALL + " 3b 44 24 14"); a.jcc("8c", "behind")   # upgrade set (= CHECK_CA's)
    a.b("ff 44 24 18")                                  # ahead++ (CA >= target's)
    a.label("behind")
    a.b("8b 44 24 10 " + VBASE_ECX_EAX + " 8b 01 ff 90 d8 01 00 00")  # contract
    a.b("85 c0"); a.jcc("84", "members")
    a.b("39 70 08"); a.jcc("85", "members")             # contract with this club (no loans in)
    a.b("f6 40 32 01"); a.jcc("84", "senior")
    a.b("80 78 30 07"); a.jcc("84", "members")          # listed surplus: not counted
    a.label("senior")
    a.b("ff 04 24")                                     # n++
    a.b("0f b7 48 28 81 e1 ff 01 00 00 0f b7 50 2a")    # ecx = joined day of year ; edx = joined year
    a.b("0f b7 05"); a.d(TODAY + 2); a.b("2b c2 69 c0 6d 01 00 00")
    a.b("0f b7 15"); a.d(TODAY); a.b("81 e2 ff 01 00 00 03 c2 2b c1")
    a.b("3d"); a.d(CHURN_DAYS); a.jcc("8d", "members")
    a.b("c7 44 24 04 01 00 00 00"); a.jmp("members")
    a.label("decide")
    a.b(f"b8 02 00 00 00 83 3c 24 {BEST_FOREIGN:02x}"); a.jcc("8c", "upgrade")
    a.b("b8 03 00 00 00 83 7c 24 04 00"); a.jcc("84", "upgrade")
    a.b("b8 01 00 00 00"); a.jmp("out")                 # anti-churn drop takes precedence
    a.label("upgrade")
    a.b(f"83 7c 24 18 {BEST_FOREIGN:02x}"); a.jcc("8c", "out")
    a.b("b8 04 00 00 00"); a.jmp("out")                 # not better than the BEST_FOREIGN-th
    a.label("out0")
    a.b("33 c0")
    a.label("out")
    a.b("8d 65 f4 5f 5e 5b 5d c3")
    return a.build()


def churn_gate_cave():
    """005181c7 in make_transfer_decision_for_player (EBX = club, EDI = target player, EBP = shortlist;
    replaced: mov ecx,ebx ; call 014a6d60 ; test al,al ; je 0051821e). Foreign target of an AI club and
    CHURN_EVAL == 1: drop it (remove_target, reason 0xb). SINK(CHURN_EVAL result) for the tracer."""
    a = Asm(CHURN_GATE)
    a.b("85 ff"); a.jcc("84", "orig")
    a.b("60")
    first_team_checks(a, "skip")
    a.b("8b c7 " + VBASE_ECX_EAX + " 6a 01 6a 01 56"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "skip")                   # domestic target: unaffected
    a.b("57 53"); a.call(CHURN_EVAL); a.b("83 c4 08")   # CHURN_EVAL(club, target)
    a.b("85 c0"); a.jcc("84", "skip")                   # n/a (human club etc.)
    a.b("50"); a.call("sink"); a.b("83 c4 04")
    a.b("83 f8 01"); a.jcc("84", "drop")                # anti-churn
    a.b("83 f8 04"); a.jcc("85", "skip")                # not an upgrade
    a.label("drop")
    a.b("61")                                           # dropped
    a.b("8b 47 04 8b 40 04 83 c0 04 03 c7")             # eax = person
    a.b("6a 00 50 53 8b cd"); a.call(REMOVE_TARGET)
    a.b("b0 01"); a.jmp(AI_DROPPED)
    a.label("skip")
    a.b("61")
    a.label("orig")
    a.b("8b cb"); a.call(AI_GATE)
    a.b("84 c0"); a.jcc("84", AI_GATE_NO)
    a.jmp(AI_GATE_YES)
    a.b(CHURN_MARK.hex())
    a.label("sink")                                     # SINK(CHURN_EVAL result): hook point
    a.b("8b 44 24 04 90 c3")
    return a.build()


def route_gate_cave():
    """Called instead of add_transfer_offer(offer, a, b, c) (thiscall, ret 0x10) at 0094bf45 / 0094b78f
    (FUN_0094b700: the "offer a listed / unslotted player to interested clubs" route). The offer's buying
    team is offer+8 (a club team). For an AI buyer and a player foreign to it, the offer isn't created
    (return -1, which both call sites handle) when the buyer's shortlist has the native brake on
    (+0xea and +0xb8 > 0; reason 2) or CHURN_EVAL(club) == 1 (reason 1). Otherwise, and for human
    buyers and domestic players, add_transfer_offer runs as before. SINK(reason) for the tracer."""
    a = Asm(ROUTE_GATE)
    a.b("60 8b 7c 24 24 85 ff"); a.jcc("84", "go")      # pushad ; edi = offer
    a.b("8b 47 08 85 c0"); a.jcc("84", "go")            # buyer team
    a.b("80 78 23 00"); a.jcc("85", "go")
    a.b("8b 40 10 85 c0"); a.jcc("84", "go")            # its club
    a.b("8b d8")                                        # ebx = club
    first_team_checks(a, "go")
    a.b("6a 01 8b ce"); a.call(HUMAN_TEAM)
    a.b("84 c0"); a.jcc("85", "go")                     # human buyer
    a.b("8b cf"); a.call(OFFER_PERSON)                  # person (FUN_008f8840, thiscall offer)
    a.b("85 c0"); a.jcc("84", "go")
    a.b("8b e8 8b c8 6a 01 6a 01 56"); a.call(IS_FOREIGN)   # ebp = person
    a.b("84 c0"); a.jcc("84", "go")                     # domestic player
    a.b("8b 43 50 85 c0"); a.jcc("84", "churn")         # native brake: [[club+0x50]+0x24] shortlist
    a.b("8b 40 24 85 c0"); a.jcc("84", "churn")
    a.b("80 b8 ea 00 00 00 00"); a.jcc("84", "churn")
    a.b("83 b8 b8 00 00 00 00"); a.jcc("8e", "churn")
    a.b("6a 02"); a.jmp("skip")
    a.label("churn")
    a.b("8b cd 8b 01 ff 90 78 03 00 00")                # player = person->vfunc_0x378() (0: no upgrade test)
    a.b("50 53"); a.call(CHURN_EVAL); a.b("83 c4 08")
    a.b("83 f8 01"); a.jcc("84", "drop")
    a.b("83 f8 04"); a.jcc("85", "go")
    a.label("drop")
    a.b("50")                                           # reason 1 (anti-churn) / 4 (not an upgrade)
    a.label("skip")
    a.call("sink"); a.b("83 c4 04 61")
    a.b("83 c8 ff c2 10 00")                            # return -1 (no offer)
    a.label("go")
    a.b("61"); a.jmp(ADD_OFFER)
    a.b(ROUTE_MARK.hex())
    a.label("sink")
    a.b("8b 44 24 04 90 c3")
    return a.build()


def cand_cave():
    """Called instead of FUN_016e6110 (thiscall: ECX = shortlist; player, score, type, x, slot, club, his
    team; ret 0x1c) at 006f4706, where FUN_006f4290 adds a purchase candidate (result unused there).
    A candidate foreign to the club (the game's type-0x15 test against its first team, so home-nation and
    long-serving players count as domestic) is not added when the club's shortlist has the native brake
    on (+0xea and +0xb8 > 0; reason 2) or CHURN_EVAL(club) == 1 (reason 1): such a target would be dropped
    at the decision anyway, and skipping it also avoids registering interest (which feeds the offer-to-
    interested-clubs route). Domestic candidates and other clubs are unaffected. SINK(reason)."""
    a = Asm(CAND_CAVE)
    a.b("60 8b 7c 24 24 85 ff"); a.jcc("84", "go")      # pushad ; edi = player
    a.b("8b 5c 24 38 85 db"); a.jcc("84", "go")         # ebx = club (arg 6)
    first_team_checks(a, "go")
    a.b("8b c7 " + VBASE_ECX_EAX + " 6a 01 6a 01 56"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "go")                     # domestic candidate
    a.b("8b 44 24 18 85 c0"); a.jcc("84", "churn")      # shortlist (saved ECX)
    a.b("80 b8 ea 00 00 00 00"); a.jcc("84", "churn")
    a.b("83 b8 b8 00 00 00 00"); a.jcc("8e", "churn")
    a.b("6a 02"); a.jmp("skip")
    a.label("churn")
    a.b("57 53"); a.call(CHURN_EVAL); a.b("83 c4 08")   # CHURN_EVAL(club, candidate)
    a.b("83 f8 01"); a.jcc("84", "drop")
    a.b("83 f8 04"); a.jcc("85", "go")
    a.label("drop")
    a.b("50")                                           # reason 1 (anti-churn) / 4 (not an upgrade)
    a.label("skip")
    a.call("sink"); a.b("83 c4 04 61")
    a.b("33 c0 c2 1c 00")                               # not added
    a.label("go")
    a.b("61"); a.jmp(ADD_TARGET)
    a.b(CAND_MARK.hex())
    a.label("sink")
    a.b("8b 44 24 04 90 c3")
    return a.build()


OFFER_PERSON = 0x008F8840
_CHURN_EVAL = churn_eval_routine()
_CHURN_GATE = churn_gate_cave()
_ROUTE_GATE = route_gate_cave()
_CAND = cand_cave()
_PRICE = struct.pack("<d", DOMESTIC_PRICE_FACTOR)
assert CHURN_EVAL + len(_CHURN_EVAL) <= CHURN_CAVE_END
assert CHURN_GATE + len(_CHURN_GATE) <= UI_RULES_CAVE
assert CAND_CAVE + len(_CAND) <= ROUTE_GATE and ROUTE_GATE + len(_ROUTE_GATE) <= PRICE_CONST
assert CHURN_CAVE_END <= 0x02047B80 and 0x02047B80 + 0x40 <= CAND_CAVE   # eligible cave (patches_transfer_ai)
assert PRICE_CONST + 8 <= ZERO_RUN_END
assert all(x.count(m) == 1 for x, m in ((_CHURN_GATE, CHURN_MARK), (_ROUTE_GATE, ROUTE_MARK), (_CAND, CAND_MARK)))


# --- Transition period (careers start in July 2014) -------------------------------------------------
# Until TRANSITION_END (exclusive):
#   (a) FUN_0047ca40, the release payout (rest of contract; used by the release itself when no amount
#       is agreed, the AI's release-candidate evaluation, the "can the club afford it" check, the
#       release dialog / news and the UI packets), returns 0 for a player foreign to his club (the
#       game's type-0x15 test against his contract's team), so every such release is free, the human's
#       included;
#   (b) the surplus ladder releases listed senior surplus foreigners of AI clubs during
#       AUG_RELEASE_FIRST..AUG_RELEASE_LAST (TRANSITION_YEAR) at its squad review without the Jan/Jul
#       mark (the settlement is a percentage of the payout, so 0 given (a)).
# From TRANSITION_END on the normal Jan/Jul mark and Jun/Dec settlement apply and the payout is vanilla.
import datetime as _dt

TRANSITION_END = _dt.date(2014, 9, 1)            # first day with normal rules
AUG_RELEASE_FIRST = _dt.date(2014, 8, 15)        # transition release window (inclusive)
AUG_RELEASE_LAST = _dt.date(2014, 8, 31)
TRANSITION_YEAR = AUG_RELEASE_FIRST.year
assert AUG_RELEASE_LAST.year == TRANSITION_YEAR and AUG_RELEASE_LAST < TRANSITION_END


def _date_key(d):
    """TODAY's packing: word0 low 9 bits = day of year (1-based), word1 = year -> year << 9 | day."""
    return d.year << 9 | d.timetuple().tm_yday


TRANSITION_KEY = _date_key(TRANSITION_END)
AUG_DOY0_FIRST = AUG_RELEASE_FIRST.timetuple().tm_yday - 1   # 0-based, as the surplus ladder's eax
AUG_DOY0_LAST = AUG_RELEASE_LAST.timetuple().tm_yday - 1
JUNE_DOY0 = 0x97                                 # a day in the ladder's June release band (0x97..0xb4)
PAYOUT_CAVE = 0x020C1AAA                         # free 0x020C1AAA-0x020C1C00 (after the bosman retain cave)
TRANSITION_DOY = 0x020C1FB8                      # after P32_ADDRULE (nostalgia_3_foreigners), to the end of .text
PAYOUT_SITE = PAYOUT                             # FUN_0047ca40 entry
PAYOUT_CONT = 0x0047CA48                         # after sub esp,8 ; push esi ; mov esi,[esp+0x10]
PAYOUT_MARK = b"PAYZ"
PERSON_PLAYER = "ff 90 78 03 00 00"              # person vfunc +0x378: player (0 for non-players)


def payout_cave():
    """FUN_0047ca40(person) entry (cdecl). Before TRANSITION_KEY, for a player (person vfunc +0x378
    non-zero) with a contract (vfunc +0x1d8) whose team (+8) is a club team (+0x23 == 0, +0x10 set)
    and who is foreign to it (FUN_015440e0(team, 1, 1)): return 0 (SINK(person) first, for the tracer).
    Otherwise (and from TRANSITION_END on, after a 6-instruction date test) the original function runs.
    0 is a value the original already returns (no contract, contract flags 0xc), so every caller
    handles it: the release books nothing, the affordability tests (00677090, 00f3283b) pass, the
    release dialog and news (0043fc20, 01e2b5d0, 00adf2e0) and the UI packet (008bb290) show 0."""
    a = Asm(PAYOUT_CAVE)
    a.b("0f b7 05"); a.d(TODAY + 2); a.b("c1 e0 09")   # eax = year << 9
    a.b("0f b7 0d"); a.d(TODAY); a.b("81 e1 ff 01 00 00 0b c1")   # | day of year
    a.b("3d"); a.d(TRANSITION_KEY); a.jcc("83", "orig")
    a.b("60 8b 74 24 24 85 f6"); a.jcc("84", "skip")    # pushad ; esi = person
    a.b("8b ce 8b 06 " + PERSON_PLAYER + " 85 c0"); a.jcc("84", "skip")   # players only
    a.b("8b ce 8b 06 ff 90 d8 01 00 00 85 c0"); a.jcc("84", "skip")      # contract
    a.b("8b 58 08 85 db"); a.jcc("84", "skip")          # ebx = his team
    a.b("80 7b 23 00"); a.jcc("85", "skip")             # club team
    a.b("83 7b 10 00"); a.jcc("84", "skip")
    a.b("6a 01 6a 01 53 8b ce"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "skip")
    a.b("56"); a.call("sink"); a.b("83 c4 04")
    a.b("61 33 c0 c3")                                  # popad ; return 0
    a.label("skip")
    a.b("61")
    a.label("orig")
    a.b("83 ec 08 56 8b 74 24 10"); a.jmp(PAYOUT_CONT)  # the replaced code
    a.b(PAYOUT_MARK.hex())
    a.label("sink")                                     # SINK(person): hook point for the tracer
    a.b("8b 44 24 04 90 c3")
    return a.build()


def transition_doy():
    """Called by the surplus ladder's listed branch (EDI = contract of a listed senior surplus foreigner
    of an AI club) instead of computing the day of year: EAX = day of year (0-based). In
    AUG_RELEASE_FIRST..AUG_RELEASE_LAST of TRANSITION_YEAR it marks the contract (+0x32 bit 7, as Jan/Jul
    does) and returns JUNE_DOY0, so the ladder takes its release branch now; SINK(contract) first."""
    a = Asm(TRANSITION_DOY)
    a.b("0f b7 05"); a.d(TODAY); a.b("25 ff 01 00 00 48")
    a.b("66 81 3d"); a.d(TODAY + 2); a.b(TRANSITION_YEAR.to_bytes(2, "little").hex(" "))
    a.jcc("85", "ret")
    a.b("3d"); a.d(AUG_DOY0_FIRST); a.jcc("82", "ret")
    a.b("3d"); a.d(AUG_DOY0_LAST); a.jcc("87", "ret")
    a.b("80 4f 32 80")                                  # mark
    a.b("57"); a.call("sink"); a.b("83 c4 04")
    a.b(f"b8 {JUNE_DOY0:02x} 00 00 00")
    a.label("ret")
    a.b("c3")
    a.b(b"TRAN".hex())
    a.label("sink")                                     # SINK(contract): hook point for the tracer
    a.b("8b 44 24 04 90 c3")
    return a.build()


# --- All-team daily sweep -----------------------------------------------------------------------------
# The surplus ladder used to run only inside the AI squad review FUN_006296b0 (driven by FUN_00e723b0 from
# FUN_007c7bf0 <- FUN_00dc4650 <- FUN_00f5a1d0 modes 1/2 with no team argument). That review runs rarely:
# about 365 reviews for 219 clubs in Jul-Sep 2014 (trace_sweep.txt), so a club could go weeks without one
# and miss the Aug 15-31 window or a Jun/Dec settlement entirely (Man City and Chelsea did, with their
# surplus moved to the Under 21s). Its team list (FUN_00793140 / FUN_009f7b30) excludes only type 0x16 and
# the types FUN_01589610 flags (4-7, 23-26); the types seen at live clubs (0, 1, 10, 11, 12, 15, 30) are
# all included, so team type was not the cause.
# Now FUN_00e175f0, the AI's daily per-club routine (the scheduler FUN_00ad5da0 calls it for every AI club
# with a planning object; its decision passes ran ~680 times a day), starts with SWEEP(planning object),
# which at most once per club per game day runs SURPLUS_ONE (the ladder as a call) for every member of
# every team of the club (teams whose +0x10 is the club; affiliates' teams are their own clubs'). The
# review still runs SURPLUS_ONE for the players it reviews (a second pass the same day is idempotent:
# listing, keep-7 and the mark are re-applied, and the release unmarks first).
# The once-per-day guard is a direct-mapped table (SWEEP_SLOTS x {club, date key}) in memory the loader
# allocates read-write: the loader writes its address to SWEEP_TABLE_PTR (WRITABLE below). Without it
# (pointer 0, e.g. a patched exe on disk) SWEEP runs on every call of FUN_00e175f0. A collision only costs
# a repeat sweep. SWEEP is split in two for space: the head (checks and the guard) and the walk.
REVIEW_STUB = 0x020C19A0      # free 0x020C199F-0x020C1A00 (before the bosman retain cave)
SWEEP_TABLE_PTR = 0x020C19DC  # dword, 0 in the image; the loader stores the table address here
SWEEP_CAVE = 0x020C17DC       # SWEEP head: after CHURN_GATE, before UI_RULES_CAVE
SWEEP_WALK = 0x020C1B38       # SWEEP walk: after PAYOUT_CAVE, up to SURPLUS_CAVE
DAILY_SITE = 0x00E175F0       # FUN_00e175f0 entry: push ecx ; push ebp ; push esi ; mov esi,[esp+0x10]
DAILY_CONT = 0x00E175F7
DAILY_STUB = 0x020C18A0       # free 0x020C189D-0x020C18D0 (between UI_RULES3 and STORE3)
SWEEP_SLOTS = 16              # power of two
SWEEP_TABLE_SIZE = SWEEP_SLOTS * 8
TEAM_SKIPPED = 0x01589610     # thiscall team: AL = 1 for types 4-7 and 23-26 (FUN_009f7b30 also skips 0x16)
SWEEP_MARK = b"SWEP"
# Loader feature: patch name -> [(pointer VA, bytes)]: the loader allocates zeroed read-write memory of
# that size and writes its address into the pointer (a 4-byte zero cave of the same patch). Code pages
# stay as they are (a writable code page could be reset to read-execute by later Frida hooks).
WRITABLE = {"nostalgia_foreign_cap_ai": [(SWEEP_TABLE_PTR, SWEEP_TABLE_SIZE)]}


def review_stub():
    """FUN_006296b0 entry (thiscall ECX -> {club, ...}; member, ai manager, team, team index, count,
    flag, index, list): SURPLUS_ONE for the reviewed player, then the replaced code. Arguments are read
    at the entry only; every register is preserved. (No sweep from here: releasing players of the teams
    the review is walking, from inside it, is avoided.)"""
    a = Asm(REVIEW_STUB)
    a.b("ff 74 24 08 ff 74 24 08"); a.call(SURPLUS_CAVE)   # SURPLUS_ONE(member, ai manager)
    a.b("83 ec 10 53 55 56"); a.jmp(REVIEW_CONT)        # the replaced code
    return a.build()


def sweep_walk():
    """Entered by jmp from the head with its frame (EBP; [esp] club slot, +4 team i) and EBX = club.
    ESI = member index in the loop. Label "out" is the common exit (ret 4)."""
    a = Asm(SWEEP_WALK)
    first_team_checks(a, "out")                         # ESI = first team (validated)
    a.b("6a 01 8b ce"); a.call(HUMAN_TEAM)
    a.b("84 c0"); a.jcc("85", "out")                    # human clubs: never
    a.b("89 1c 24 33 c0 89 44 24 04")                   # club slot ; team index = 0
    a.call("sink")                                      # SWEPT() with EBX = club
    a.label("teams")
    a.b("8b cb"); a.call(TEAM_COUNT)
    a.b("3b 44 24 04"); a.jcc("86", "out")
    a.b("ff 74 24 04 8b cb"); a.call(TEAM_AT)
    a.b("ff 44 24 04 85 c0"); a.jcc("84", "teams")
    a.b("8b f8 39 5f 10"); a.jcc("85", "teams")         # edi = team of this club (affiliates' teams: no)
    a.b("33 f6")                                        # esi = member index (SURPLUS_ONE preserves it)
    a.label("members")                                  # by index, re-reading the vector (releases shrink it)
    a.b("8b 47 24 8b 4f 28 2b c8 c1 f9 02 3b f1"); a.jcc("83", "teams")
    a.b("8b 04 b0 46 85 c0"); a.jcc("84", "members")
    a.b("ff 75 08 50 8d 4c 24 08"); a.call(SURPLUS_CAVE)  # SURPLUS_ONE(member, ai manager), ECX -> club
    a.jmp("members")
    a.label("out")
    a.b("8d 65 f4 5f 5e 5b 5d c2 04 00")
    a.b(SWEEP_MARK.hex())
    a.label("sink")                                     # SWEPT(): hook point for the tracer (EBX = club)
    a.b("90 90 90 90 c3")
    code = a.build()
    return code, a.labels["out"]


def daily_stub(sweep=SWEEP_CAVE):
    """FUN_00e175f0 entry (thiscall; arg 1 = club): the AI's daily per-club routine, called by the
    scheduler FUN_00ad5da0 for every AI club with a planning object (its decision passes, planning run
    FUN_00f5a1d0 mode 3, ...). Runs SWEEP(club's planning object [[club+0x50]+0x24], as FUN_0149c780)
    with ECX -> the club argument, then the replaced code. Every register is preserved."""
    a = Asm(DAILY_STUB)
    a.b("60 8b 44 24 24 85 c0"); a.jcc("84", "skip")    # pushad ; eax = club
    a.b("8b 48 50 85 c9"); a.jcc("84", "skip")
    a.b("8b 49 24 85 c9"); a.jcc("84", "skip")          # planning object (AI clubs only)
    a.b("51 8d 4c 24 28"); a.call(sweep)                # SWEEP(planning object), ECX -> club
    a.label("skip")
    a.b("61 51 55 56 8b 74 24 10"); a.jmp(DAILY_CONT)   # popad + the replaced code
    return a.build()


def sweep_head(out):
    """SWEEP(planning object), stdcall, ECX -> {club}. EBX/ESI/EDI/EBP preserved (the stub saves all)."""
    a = Asm(SWEEP_CAVE)
    a.b("55 8b ec 53 56 57 83 ec 0c")   # locals [esp] club (SURPLUS_ONE's ECX target), +4 team i
    a.b("85 c9"); a.jcc("84", "fail")
    a.b("8b 19 85 db"); a.jcc("84", "fail")                # ebx = club
    a.b("83 7d 08 00"); a.jcc("84", "fail")                # ai manager
    a.b("8b 15"); a.d(SWEEP_TABLE_PTR); a.b("85 d2"); a.jcc("84", SWEEP_WALK)   # no table: once per review
    a.b("0f b7 05"); a.d(TODAY + 2); a.b("c1 e0 09")
    a.b("0f b7 0d"); a.d(TODAY); a.b("81 e1 ff 01 00 00 0b c1")          # eax = date key
    a.b(f"8b cb c1 e9 04 83 e1 {SWEEP_SLOTS - 1:02x} 8d 14 ca")           # edx = slot of this club
    a.b("39 1a"); a.jcc("85", "store")
    a.b("39 42 04"); a.jcc("84", "fail")                   # already swept today
    a.label("store")
    a.b("89 1a 89 42 04"); a.jmp(SWEEP_WALK)
    a.label("fail")
    a.jmp(out)
    return a.build()


_REVIEW_STUB = review_stub()
_DAILY_STUB = daily_stub()
_SWEEP_WALK, SWEEP_OUT = sweep_walk()
_SWEEP = sweep_head(SWEEP_OUT)
assert REVIEW_STUB + len(_REVIEW_STUB) <= SWEEP_TABLE_PTR and SWEEP_TABLE_PTR + 4 <= 0x020C1A00   # bosman retain cave
assert SWEEP_CAVE + len(_SWEEP) <= UI_RULES_CAVE
assert DAILY_STUB + len(_DAILY_STUB) <= 0x020C18D0
assert SWEEP_WALK + len(_SWEEP_WALK) <= SURPLUS_CAVE and _SWEEP_WALK.count(SWEEP_MARK) == 1


_PAYOUT = payout_cave()
_TRANSITION_DOY = transition_doy()
_SURPLUS3 = surplus_cave(unlist=UNLIST_CAVE, doy=TRANSITION_DOY, as_function=True)   # SURPLUS_ONE
assert PAYOUT_CAVE + len(_PAYOUT) <= SWEEP_WALK
assert CHURN_GATE + len(_CHURN_GATE) <= SWEEP_CAVE
assert TRANSITION_DOY >= P32_ADDRULE + 0x38 and TRANSITION_DOY + len(_TRANSITION_DOY) <= 0x020C2000
assert SURPLUS_CAVE + len(_SURPLUS3) <= CHECK_CA
assert _PAYOUT.count(PAYOUT_MARK) == 1 and _TRANSITION_DOY.count(b"TRAN") == 1


def zero(va, code):
    return {"offset": off(va), "original": " ".join(["00"] * len(code)), "patched": code.hex(" ")}


def recall(va, target):
    """call rel32 at va (original: call to the same function's original target, checked by the caller)."""
    return (b"\xe8" + (target - (va + 5)).to_bytes(4, "little", signed=True)).hex(" ")


# --- Performance: ranked once per club per day, weekly sweeps ----------------------------------------
# CHECK used to walk every team of the club for each player it judged, so a sweep (one CHECK per foreign
# senior) cost O(seniors x members) per club. The cached CHECK ranks the club once: one walk keeps the
# BEST_FOREIGN best senior foreigners by (CA desc, address asc), and only the BEST_FOREIGN-th {CA, address}
# is stored in RANK_CACHE (in the loader's writable block), keyed by ctx (the first team) and
# day number | first-team size << 20, so a new day or a first-team arrival/departure re-ranks. A player is
# surplus when that rank is filled and he ranks below it: exactly "BEST_FOREIGN or more others ahead of
# him" (he is either in the ranked set or ranks against it like any other member). Every caller benefits:
# the sweep, the review stub, IS_SURPLUS (status hook, bosman retain). Without the block it ranks on
# every call (one walk, as before).
# The sweep runs weekly per club (SWEEP_DAYS), daily during the 15-31 Aug 2014 transition window.
assert BEST_FOREIGN == 3                # the ranking keeps exactly three slots
SWEEP_DAYS = 7
RANK_SLOTS = 64                         # direct-mapped by ctx; a collision only costs a re-rank
RANK_CACHE = SWEEP_TABLE_SIZE           # offset in the writable block (after the sweep guard)
WRITABLE_SIZE = RANK_CACHE + RANK_SLOTS * 16
WRITABLE["nostalgia_foreign_cap_ai"] = [(SWEEP_TABLE_PTR, WRITABLE_SIZE)]
ZERO_RUN2 = 0x02047E16                  # 2nd helper.dll-moved body (stub 02047e10 jmp [0246b848], unreferenced)
ZERO_RUN2_END = 0x02048248
CHECK2 = 0x02047E20                     # the cached CHECK; CHECK_CA (0x020C1E00) becomes jmp CHECK2
SWEEP_CAVE2 = 0x02048070                # weekly SWEEP head (replaces the daily one at 0x020C17DC)
AUG_FIRST_DOY1 = AUG_RELEASE_FIRST.timetuple().tm_yday
AUG_LAST_DOY1 = AUG_RELEASE_LAST.timetuple().tm_yday


def _daynum(a):
    """eax = year * 365 + day of year (1-based); clobbers ecx."""
    a.b("0f b7 05"); a.d(TODAY + 2); a.b("69 c0 6d 01 00 00")
    a.b("0f b7 0d"); a.d(TODAY); a.b("81 e1 ff 01 00 00 03 c1")


def check_cached():
    """CHECK(ctx, player, flags), cdecl, AL = 1 when `player` is a surplus senior foreigner of ctx's club
    (same definition as check_ca_routine; flags ignored)."""
    a = Asm(CHECK2)
    a.b("55 8b ec 53 56 57 83 ec 30")
    # locals: [0] ca3 [4] ad3 [8] ca2 [0xc] ad2 [0x10] ca1 [0x14] ad1 [0x18] team i [0x1c] cursor
    #         [0x20] his CA [0x24] cache entry (0: none) [0x28] key [0x2c] member
    a.b("8b 5d 08 8b 75 0c 33 c0")      # ebx = ctx ; esi = player
    a.b("85 db"); a.jcc("84", "out")
    a.b("85 f6"); a.jcc("84", "out")
    a.b("80 7b 23 00"); a.jcc("85", "out")              # club teams only
    a.b("83 7b 10 00"); a.jcc("84", "out")
    a.b(VBASE_ECX_ESI + " 6a 01 6a 01 53"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "out0")                   # domestic: never surplus
    a.b(VBASE_ECX_ESI + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8c", "out0")    # under SENIOR_AGE: left to the game
    a.b("8b ce " + CA_CALL + " 89 44 24 20")            # his CA
    a.b("33 c0 89 44 24 24")                            # no cache entry yet
    a.b("8b 15"); a.d(SWEEP_TABLE_PTR); a.b("85 d2"); a.jcc("84", "rank")
    _daynum(a)
    a.b("8b 4b 28 2b 4b 24 c1 e1 12 0b c1 89 44 24 28")  # key = daynum | first-team size << 20
    a.b(f"8b cb c1 e9 04 83 e1 {RANK_SLOTS - 1:02x} c1 e1 04")
    a.b("8d 94 0a"); a.d(RANK_CACHE)                    # edx = entry
    a.b("89 54 24 24")
    a.b("39 1a"); a.jcc("85", "rank")
    a.b("39 42 04"); a.jcc("85", "rank")
    a.b("8b 42 08 8b 4a 0c"); a.jmp("compare")          # cached: eax = ca3, ecx = ad3
    a.label("rank")
    a.b("83 c8 ff 89 04 24 89 44 24 08 89 44 24 10")    # ca1..3 = -1 (empty)
    a.b("33 c0 89 44 24 04 89 44 24 0c 89 44 24 14 89 44 24 18")   # ad1..3 = 0 ; team index = 0
    a.label("teams")
    a.b("8b 4b 10"); a.call(TEAM_COUNT)
    a.b("3b 44 24 18"); a.jcc("86", "ranked")
    a.b("ff 74 24 18 8b 4b 10"); a.call(TEAM_AT)
    a.b("ff 44 24 18 85 c0"); a.jcc("84", "teams")
    a.b("8b f8 8b 47 24 89 44 24 1c")                   # edi = team ; cursor = players begin
    a.label("members")
    a.b("8b 44 24 1c 3b 47 28"); a.jcc("83", "teams")
    a.b("83 44 24 1c 04 8b 00 85 c0"); a.jcc("84", "members")
    a.b("89 44 24 2c")
    a.b(VBASE_ECX_EAX + " 8b 01 ff 90 bc 02 00 00 84 c0"); a.jcc("85", "members")   # retired-like
    a.b("8b 4c 24 2c 6a 00 6a 00 8b 01 ff 90 6c 01 00 00 84 c0"); a.jcc("85", "members")  # away
    a.b("8b 44 24 2c " + VBASE_ECX_EAX + " 6a 01 6a 01 53"); a.call(IS_FOREIGN)
    a.b("84 c0"); a.jcc("84", "members")
    a.b("8b 44 24 2c " + VBASE_ECX_EAX + " " + AGE_CALL)
    a.b(f"3c {SENIOR_AGE:02x}"); a.jcc("8c", "members")
    a.b("8b 4c 24 2c " + CA_CALL + " 8b 4c 24 2c")      # eax = CA, ecx = member: insert into the top 3
    for ca, ad, nxt in ((0x10, 0x14, "s2"), (0x08, 0x0c, "s3"), (0x00, 0x04, "members")):
        a.b(f"3b 44 24 {ca:02x}"); a.jcc("8f", "x" + nxt)        # higher CA: ahead
        a.jcc("8c", nxt)                                        # lower CA
        a.b(f"3b 4c 24 {ad:02x}"); a.jcc("83", nxt)             # equal: lower address ranks first
        a.label("x" + nxt)
        if nxt == "members":
            a.b(f"89 44 24 {ca:02x} 89 4c 24 {ad:02x}"); a.jmp("members")
        else:
            a.b(f"87 44 24 {ca:02x} 87 4c 24 {ad:02x}")         # swap, carry the displaced one down
            a.label(nxt)
    a.label("ranked")
    a.b("8b 04 24 8b 4c 24 04 8b 54 24 24 85 d2"); a.jcc("84", "compare")
    a.b("8b 7c 24 28 89 1a 89 7a 04 89 42 08 89 4a 0c")  # store {ctx, key, ca3, ad3}
    a.label("compare")                                   # eax = ca3 (-1: fewer than 3), ecx = ad3
    a.b("83 f8 ff"); a.jcc("84", "out0")
    a.b("8b 54 24 20 3b d0"); a.jcc("8c", "yes")         # his CA below the 3rd
    a.jcc("8f", "out0")
    a.b("3b f1"); a.jcc("86", "out0")                    # equal CA: surplus if his address is higher
    a.label("yes")
    a.b("b0 01"); a.jmp("out")
    a.label("out0")
    a.b("33 c0")
    a.label("out")
    a.b("8d 65 f4 5f 5e 5b 5d c3")
    return a.build()


def sweep_head2(out):
    """SWEEP(planning object), stdcall, ECX -> {club}: weekly per club (daily in the Aug 2014 window)."""
    a = Asm(SWEEP_CAVE2)
    a.b("55 8b ec 53 56 57 83 ec 0c")   # locals [esp] club (SURPLUS_ONE's ECX target), +4 team i
    a.b("85 c9"); a.jcc("84", "fail")
    a.b("8b 19 85 db"); a.jcc("84", "fail")                # ebx = club
    a.b("83 7d 08 00"); a.jcc("84", "fail")                # planning object
    a.b("8b 15"); a.d(SWEEP_TABLE_PTR); a.b("85 d2"); a.jcc("84", SWEEP_WALK)   # no table: every call
    a.b(f"be {SWEEP_DAYS:02x} 00 00 00")                   # esi = interval
    a.b("66 81 3d"); a.d(TODAY + 2); a.b(TRANSITION_YEAR.to_bytes(2, "little").hex(" ")); a.jcc("85", "interval")
    a.b("0f b7 05"); a.d(TODAY); a.b("25 ff 01 00 00")
    a.b("3d"); a.d(AUG_FIRST_DOY1); a.jcc("82", "interval")
    a.b("3d"); a.d(AUG_LAST_DOY1); a.jcc("87", "interval")
    a.b("be 01 00 00 00")                                  # transition window: daily
    a.label("interval")
    _daynum(a)                                             # eax = day number
    a.b(f"8b cb c1 e9 04 83 e1 {SWEEP_SLOTS - 1:02x} 8d 14 ca")   # edx = slot of this club
    a.b("39 1a"); a.jcc("85", "store")
    a.b("8b c8 2b 4a 04"); a.jcc("8c", "store")            # earlier day (another save loaded): sweep
    a.b("3b ce"); a.jcc("8c", "fail")                      # swept within the interval
    a.label("store")
    a.b("89 1a 89 42 04"); a.jmp(SWEEP_WALK)
    a.label("fail")
    a.jmp(out)
    return a.build()


_CHECK_CACHED = check_cached()
_CHECK_JMP = jmp_patch(CHECK_CA, CHECK2, 5)             # callers (and tracers) keep using 0x020C1E00
_SWEEP2 = sweep_head2(SWEEP_OUT)
assert ZERO_RUN2 <= CHECK2 and CHECK2 + len(_CHECK_CACHED) <= SWEEP_CAVE2
assert SWEEP_CAVE2 + len(_SWEEP2) <= ZERO_RUN2_END
_DAILY_STUB = daily_stub(SWEEP_CAVE2)


PATCHES["nostalgia_foreign_cap_ai"] = [
    cave(CHECK_CA, bytes.fromhex(_CHECK_JMP.replace(" ", ""))),
    zero(CHECK2, _CHECK_CACHED),
    cave(IS_SURPLUS, _STATUS),
    site(STATUS_SETTER, "ff 74 24 08 8b d1", STATUS_HOOK,
         "FUN_015c8920 (contract set_squad_status) entry: push [esp+8] ; mov edx,ecx -> jmp STATUS_HOOK ; nop"),
    cave(UNLIST_CAVE, _UNLIST),
    cave(SURPLUS_CAVE, _SURPLUS3),
    cave(REVIEW_STUB, _REVIEW_STUB),
    site(REVIEW_SITE, "83 ec 10 53 55 56", REVIEW_STUB,
         "FUN_006296b0 entry: sub esp,0x10 ; push ebx ; push ebp ; push esi -> jmp REVIEW_STUB ; nop"),
    zero(SWEEP_CAVE2, _SWEEP2),
    cave(SWEEP_WALK, _SWEEP_WALK),
    cave(DAILY_STUB, _DAILY_STUB),
    site(DAILY_SITE, "51 55 56 8b 74 24 10", DAILY_STUB,
         "FUN_00e175f0 entry: push ecx ; push ebp ; push esi ; mov esi,[esp+0x10] -> jmp DAILY_STUB ; nop x2"),
    cave(SWEEP_TABLE_PTR, bytes(4)),   # the loader writes the sweep table's address here (WRITABLE)
    # anti-churn: shared evaluation + decision gate
    zero(CHURN_EVAL, _CHURN_EVAL),
    cave(CHURN_GATE, _CHURN_GATE),
    site(AI_SITE, "8b cb e8 92 eb f8 00 84 c0 74 4c", CHURN_GATE,
         "make_transfer_decision_for_player 005181c7 -> jmp CHURN_GATE ; nop x6"),
    # route gate: the two add_transfer_offer calls of FUN_0094b700
    zero(ROUTE_GATE, _ROUTE_GATE),
    {"offset": off(ROUTE_SITES[0]), "original": "e8 06 96 51 00", "patched": recall(ROUTE_SITES[0], ROUTE_GATE)},
    {"offset": off(ROUTE_SITES[1]), "original": "e8 bc 9d 51 00", "patched": recall(ROUTE_SITES[1], ROUTE_GATE)},
    # candidate filter at FUN_006f4290's add
    zero(CAND_CAVE, _CAND),
    {"offset": off(CAND_SITE), "original": "e8 05 1a ff 00", "patched": recall(CAND_SITE, CAND_CAVE)},
    # domestic price factor: FUN_009327d0's mulsd operand -> our constant
    zero(PRICE_CONST, _PRICE),
    {"offset": off(PRICE_SITE), "original": "48 23 2d 02", "patched": PRICE_CONST.to_bytes(4, "little").hex(" ")},
    # transition period: free release of foreigners (payout 0) and the August surplus release
    cave(PAYOUT_CAVE, _PAYOUT),
    site(PAYOUT_SITE, "83 ec 08 56 8b 74 24 10", PAYOUT_CAVE,
         "FUN_0047ca40 entry: sub esp,8 ; push esi ; mov esi,[esp+0x10] -> jmp PAYOUT_CAVE ; nop x3"),
    cave(TRANSITION_DOY, _TRANSITION_DOY),
]
