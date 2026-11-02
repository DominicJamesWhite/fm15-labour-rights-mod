# Squad status of surplus foreigners (nostalgia mode)

`nostalgia_foreign_cap_ai` lists every surplus foreigner of an AI club, and listing sets his squad status to 7 "Not Needed". In game, most of them were back at Key, First Team, Rotation and so on within a day. This write-up explains why and describes the fix. Addresses are Ghidra VAs in fm.exe 15.3.

## The problem, measured

Squad snapshots (`tools/squad_snapshot.py`) of a new save on 16 Nov 2014, before the fix. "Listed surplus" means transfer-listed (contract `+0x32` bit 0) and beyond the club's keep limit.

| Club | Listed surplus foreigners | Not at "Not Needed" |
|---|---|---|
| Arsenal | 23 | 21 |
| Chelsea | 43 | 36 |
| Manchester City | 43 | 39 |

## How the AI re-rates squad status

**When it runs.** `FUN_00f5a1d0` is the AI club's periodic squad routine (it also builds the shortlist). It calls `FUN_00dc4650`, which runs only for AI clubs (`FUN_0149f3e0(1)` false, manager flag `+0xc4 & 0x8000` clear). That calls `FUN_007c7bf0`, which does two things in order:
1. **Re-rating.** It calls `FUN_00b59850` once for each of the AI squad plan's four player groups (`+0x28`, `+0x34`, `+0x40`, `+0x4c`). The fourth group gets a floor of 4 ("Backup"), or 7 in the case gated by `FUN_014a6d60`/`FUN_014a6d80`; the others get a floor of 1 (or 2 in that gated case).
2. **Squad review.** It calls `FUN_00e723b0`, which calls `FUN_006296b0` per player. That is where `surplus_cave` hooks in.

**How a status is picked.** For each player, `FUN_00b59850` asks `FUN_0163e2b0(first team, 0, 4, 0)`, which is `[0x024260a8]` vfunc `+0x2c` = `FUN_00a013d0`. That function finds the best status from 1 to 7 whose ability threshold the player meets, relative to the club's squad (`FUN_0160b360`/`FUN_0160b380`, with a per-club cache `FUN_01740010`/`FUN_017400e0`). A few tweaks follow (a 7 becomes 3 or 4 for the first two players of the group in some cases, and players found by `FUN_004edaf0` are adjusted to 3 or 4), then `max(status, group floor)` is written. The write goes through contract vfunc `+0x84` with club 0, at `00b599be`, return address `00b599c4`.

**Nothing in the re-rating looks at transfer listing.** `FUN_00a013d0` and `FUN_00b59850` never read contract `+0x32`. Only the valuation `FUN_0045c3f0` adjusts the importance step for listed players, and that is a price calculation, not a status write.

**What vanilla does with a player the AI lists.** The status leads and the listing follows. In `FUN_006296b0`, a player whose status is 7 gets `FUN_0089bbf0` (listed). Both come from the same ability calculation, so vanilla never sees a listed player rated Key. Nothing in vanilla keeps a listed player at 7. Our surplus listings broke that assumption: their reason is nationality, which the calculation doesn't know about.

**Other status writers** (all through the same setter; counts from the earlier trace):

| Caller | Function | What it is |
|---|---|---|
| `00b599c4` | `FUN_00b59850` | The re-rating above. By far the most writes (statuses 1 to 7) |
| `00a5532c`, `00a552f5` | `FUN_00a55190` | Initial ratings for every club at game creation (`FUN_00d83890`; also `FUN_00ad5da0`). It writes `min(rating, 2)`, or the rating when 5 or 6 |
| `008e7712` | `FUN_008e7560` | Contract setup after a move or a new contract (accept offer `FUN_00ca6360` and others). Includes `0xff`, unset |
| `00636e88`, `00636fee` | `FUN_00636db0` | From `FUN_00be8c00` |
| `006d2be5` | `FUN_006d2190` | Contract changes (15 callers, including expiry `FUN_00478070`) |

**The setter.** Contract vfunc `+0x84` is `FUN_015c8920` in all five contract vtables (`020d5850`, `020d5940`, `0210b610`, `0210cb5c`, `0210ccf4`), and nothing calls it directly. It forwards `(contract, status, club)` to `[0x024260d4]` vfunc `+0xc` = `FUN_008dd520`, which clamps the value and applies side effects. So hooking `FUN_015c8920` covers every status write.

## Why there is no marker bit

The task suggested claiming a spare bit of contract `+0x32`. **There is none.**
- **Bits 1 and 6** are used by the transfer-status setter `FUN_00b76880`: it clears with masks `0xb`, `3`, `2` and `1` (via `FUN_015bef50`), and sets `0x40`.
- **Bit 4** is tested by the bid evaluation (`01f327db`, on the contract from `FUN_01545810`) and at `006ba885` and `00b058ff`.
- **Bits 0, 2, 3 and 5** are the game's known flags.
- **Bit 7** is already `surplus_cave`'s January/July mark.
- **The live game confirms it.** Contracts read `0x44`, `0x6` and `0x2` ([contract_probe.txt](contract_probe.txt)).

The scan of every test on the vfunc `+0x8c` result is in [flags_vfunc8c_tests.txt](flags_vfunc8c_tests.txt).

**Padding is no better.** Byte `+0x3b` looks like padding in the `0x3c`-byte base contract: the constructor `015bcd70` never sets it, and subclasses add fields from `+0x3c`. But padding isn't saved, isn't initialised (pool memory gets reused), and one live contract had `0x3b` there.

**So the setter asks a live test instead of reading a marker.** Being "surplus-listed" is recomputed exactly as `surplus_cave` decides it.

## The fix

### `nostalgia_foreign_cap_ai`: status cave at `020c1600`–`020c16c5` (was free; the old checker location)

**`IS_SURPLUS(contract)`**, cdecl, returns AL. It is 1 only when all of these hold:
- the contract is transfer-listed (`+0x32` bit 0)
- its team `[contract+8]` is a club team (`+0x23 == 0`, `+0x10 != 0`). The live probe confirmed that `+8` is the club's first team and `+4` the person.
- that team is AI-managed (`FUN_0158a9e0(team, 1)` false)
- `CHECK(team, player, RANK|SKIP_CONTRACT)` says the player is surplus

That is `surplus_cave`'s own test, so it switches off the moment the player stops being surplus: the club gains enough domestic players (KEEP goes from 3 to 5), better foreigners leave, or his value climbs into the top places.

**Setter hook (`STATUS_HOOK`, `020c165d`).** Site `FUN_015c8920`: `ff 74 24 08 8b d1` (`push [esp+8] ; mov edx,ecx`) becomes `e9 38 8d af 00 90` (`jmp 020c165d ; nop`).
- **Which writes it checks:** only new statuses 1 to 6. Writes of 7 or `0xff` (unset), and writes for unlisted players, go straight through.
- **What it changes:** if `IS_SURPLUS(contract)` is true, the status argument becomes 7.
- **Tracer hook:** each change calls the no-op `KEPT(original status)` (`020c16be`).
- **Return path:** the replaced instructions, then `jmp 015c8926`.
- **Branch check:** no game branch targets `015c8921`–`015c8925`.

**`KEEP7(contract, club)`**, stdcall, at `020c1695`. `surplus_cave`'s "already listed" path now calls it (`push ebx ; push edi ; call KEEP7`, 7 bytes; the cave now ends at `020c1ded`). If the status is 1 to 6, it sets 7 through the setter with the club, as `FUN_006296b0` itself does. This fixes saves rated before the hook, and anything that writes `+0x30` directly, at the next review.

**Effect.** A listed surplus foreigner stays "Not Needed" from listing until he is sold, loaned, released, or stops being surplus. Once he stops being surplus, the next re-rating sets his normal status. He stays transfer-listed: the mod has never delisted, and vanilla AI review doesn't either, as far as I've seen. Human clubs and unlisted players are untouched.

### `nostalgia_retain_on_expiry`: retain cave `020c1a00`–`020c1aa9` (size limit raised to `0xC0`)

For an AI club, a player's contract now expires instead of rolling over if any of these is true:
- his status is 7 (as before)
- his contract `+0x32` has bits `0x81` (listed, plus the January/July surplus mark)
- `IS_SURPLUS(contract)` is true

**The cross-module call is guarded.** The cave checks that `nostalgia_foreign_cap_ai` is applied by comparing the first dword at `020c1600` with `0x53EC8B55` (`push ebp ; mov ebp,esp ; push ebx`); that memory is zero otherwise. `patches_foreign_cap.py` asserts the signature, and `patches_bosman.py` mirrors the constants.

## Verification

- **Original bytes** of `FUN_015c8920` were checked against `original/fm.exe`.
- **Disassembly** of every new or changed cave and site was checked with capstone ([verify_capstone.txt](verify_capstone.txt)).
- **Overlaps:** the NOSTALGIA set has none (the loader's check, mirrored: 1764 bytes). Cave original bytes are all zero and lie inside `0x020C1600`–`0x020C1FFF`. The only bytes shared with any other patch are the existing `nostalgia_foreign_cap`/`_ai` pair, which can't be combined anyway.

## Confidence and risks

- **High: the cause.** The re-rating overwrites 7 and ignores listing.
- **High: the hook catches every status write.** The setter is reached only through vfunc `+0x84`, which is the same function in every contract vtable.
- **Medium-high: the behaviour.** It reuses `CHECK` and the same team as `surplus_cave`. It hasn't run in game yet.
- **Cost.** Every rating of a listed player at an AI club (1 to 6) now runs `CHECK`, which walks the club's players. At clubs with 40 or more listed foreigners, that roughly doubles the work the foreign-cap patch already does in the daily squad review. The tracer shows how often it happens.
- **Matches.** "Not Needed" surplus foreigners may get fewer appearances for their clubs. That is intended under 3+2, but clubs that are short of domestic players (City has 5 domestic first-teamers) may field more reserves.
- **Loans.** A surplus foreigner loaned out keeps 7 on his parent club's contract. The loan club's contract is separate and normally unlisted, so it's unaffected.
- **Status side effects.** `FUN_008dd520` may post news or change morale on a status change. The hook removes the daily 7 → Key → 7 flip-flop, so there should be fewer such events than before.
- **Other routes.** `FUN_00b76880` writes `+0x30 = 4` directly, but only while clearing the listing bits. `KEEP7` repairs any other direct write at the next review.

## In-game test steps

1. Start with the launcher in nostalgia mode, which applies the updated `nostalgia_foreign_cap_ai` and `nostalgia_retain_on_expiry`. Load the save and continue for 2–3 days.
2. Run `python tools/squad_snapshot.py reports/squad_status "Manchester City" "Arsenal" "Chelsea"`. In each file, the `listed surplus foreigners not Not Needed` line should be 0. Players labelled `#n SURPLUS` (the label now uses keep 3 for clubs with fewer than 15 domestic first-teamers) with `+0x32` bit 0 set should show `NotNeeded`. Players labelled `keep` should have normal statuses.
3. Run `python tools/trace_foreign_cap.py reports/foreign_cap/trace.txt 15` while continuing for a week. Expect:
   - `mode: ... ai ON (status hook ON)`
   - plenty of `status hook: re-rating to N kept at 7 (listed surplus) from AI re-rating 0xb599c4`
   - `review: listed surplus player at status N, set back to 7` only in the first days of an old save
   - **no** `status N written for a listed SURPLUS player` lines
4. Bid for a surplus foreigner at about 15% of his value. The selling club should reply with a counter-offer (factor 0.1 for Not Needed) rather than reject; before the fix, a listed Key player needed 40%.
5. Let an unsold surplus foreigner reach the end of his contract, around 30 June. He should leave as a free agent, not roll over.
6. Your own squad: listing one of your foreigners must not lock his status. Set it by hand and it should stay.
7. If a club becomes able to keep a player (it signs domestic players, or better foreigners leave), his status should return to a normal rating after the club's next squad review (a day or two).

## Files

These are raw dumps and are gitignored.

| File | Contents |
|---|---|
| `setters.c` | Decompiled status writers and their callers (`FUN_00b59850`, `FUN_00a55190`, `FUN_008e7560`, `FUN_00636db0`, `FUN_006d2190`) |
| `calc.c` | `FUN_00a013d0` (the status calculation) and `FUN_007c7bf0` |
| `rerate_callers.c` | `FUN_00dc4650` and `FUN_00f5a1d0` |
| `flagbits.c` | Writers of `+0x32` bits (`FUN_00727590` is a UI object, not a contract) |
| `flags_vfunc8c_tests.txt` | Every test on a vfunc `+0x8c` result |
| `contract_probe.txt`, `contract_probe.js` | Read-only live check of contract `+4`, `+8` and the flags |
| `squads_*.txt` | Snapshots before the fix |
| `verify_capstone.txt` | Disassembly of the patch |
