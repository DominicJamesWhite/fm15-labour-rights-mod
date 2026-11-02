# FM15 Bosman, pre-contracts and out-of-contract compensation

Research for the "nostalgia" (pre-Bosman, 1990s) mode: clubs keep a player when his contract ends, a fee is due for an out-of-contract player at any age, and there are no pre-contract deals. fm.exe 15.3; addresses are Ghidra VAs (image base 0x400000). Everything here comes from static analysis. Nothing has been tested in the game. **Guess** marks inferences that aren't confirmed.

The patches are in [patcher/patches_bosman.py](../../patcher/patches_bosman.py). None of them are in DEFAULT.

## How FM15 implements it

### The pre-contract ("Bosman") check

**`FUN_00640ad0(person, buying club, &kind, &date, &compensation, flag, flag)`** (cdecl, plain `ret`) answers "can this club agree a move with this contracted player, to happen when his contract ends?"

It first zeroes the kind and compensation outputs. It then requires all of the following:
- The player has a contract with a club.
- The contract has a real end date. `FUN_015c10a0` tests for "no end date".
- He isn't in a blocked state (various checks).

**The time window:**
- `FUN_015c0cb0` gives the days left on the contract.
- The window is the larger of two values, `FUN_0103a840(person)` and `FUN_0103a8a0(person, club)`. Both call **`TRANSFER_RULES` vtable slot `+0x3c`**, which is `bosman_number_days`:
  - Base: `01030320` returns field `+0x94`. That field comes from the `tbnd` tag, which no record in `comps.dbc` sets.
  - `ENG_TRANSFER_RULES`: `010cee10(a, b)` returns 31 when `a && !b`. `a` means "the player's club is in this nation", and `b` distinguishes the selling side's call from the buying side's.
- At `00640e2b`: `cmp days_left, window ; jle ok`. If the days left exceed the window and the flag is set, it fails. If the flag is 0, the window is ignored.

**Compensation:** if `FUN_00ea7fc0` says compensation is due, the compensation output is filled from the player's vfunc `+0x2c`.

Users of the check:
- **AI planning.** `FUN_00db28b0` turns a shortlist "buy" target (type 4) into a "free transfer" target (type 5) when this check passes.
- **AI budgeting.** `TC_SHORTLIST::calculate_cost_of_transfer` prices type 5 as compensation plus contract cost (`FUN_00e785f0`).
- **AI bids.** `FUN_01e4c5f0` drops a target when the check fails, otherwise it bids through `FUN_00cb9e40`, which also calls the check.
- **Human.** `FUN_00ee8530`, a "can this manager offer this player a contract" check, accepts the player if this check **or** `FUN_00d454a0` passes.
- Others: `00c109d0`, `00f20a90`, `00e86b20`, `006ad350`, `00b9c670`, `00c71800`, `00bb1260` and `009efc80`. **Guess:** UI and AI variants.

### Free agents and special contracts

**`FUN_00d454a0(person, club, flag, &kind, &compensation, ...)`** (`ret 0x28`) handles three kinds of player:
- Players with no contract (free agents).
- Contracts with no end date.
- Contract type 3 (`contract vfunc +0x60`; **guess:** youth/scholar).

For a normal contracted player, it only passes in special cases: contract types 0, 2 and 4, or nation `0x307`. **Guess:** non-contract and amateur deals.

**Compensation on this path:**
- It's computed only when the player still has a contract object. A real free agent, whose contract is gone (`person vfunc +0x1d8` returns 0), gets **no** compensation.
- `make_free_transfer_offer` (`0057dcc0`) uses this function and passes the compensation as the offer fee: `FUN_00919690` → `FUN_00abeba0`.
- For contract type 3, the fee is split into instalments (`FUN_00efe880`).
- `calculate_cost_of_transfer` type 7 budgets compensation × 3 for type 3 contracts.

### "Is compensation due": `FUN_00ea7fc0(person, contract, buying club)`

It returns true only when all of these hold:
1. The selling club is a real club (club vfunc `+0xb8`; `EXTERN_CLUB` returns 0).
2. The player's age is below the selling nation's limit, `FUN_015e9560`: 21 for nation id `0x2f3`, 22 for `0x317`, otherwise **24**.
3. The nation isn't `0x317`, or contract flag bit 1 is set.
4. `FUN_00cceed0(FUN_0157f410(selling nation))` passes. This is called on the buying club, so it's the destination condition. **Guess:** same nation or same federation zone.

It also returns true for nation `0x2fb` with contract type 1.

### The amount: `FUN_006d4d20`

This is `GAME_ACTUAL_PLAYER` vfunc `+0x74`, reached through `FUN_0163e480` and the `DAT_024260a8` interface ('eapl').

- **Per-nation special cases** for nation ids `0x59b`, `0x317`, `0x2f3`, `0x300`, `0x314`, `0x2fb`, `0x2fc` and `0x312`. Each returns a fixed amount or a formula, or 0 for some contract types.
- **The general formula** then runs only if **age < 24** (`006d55d7`), the player status bit (`person vfunc +0x20c`, bit 0) is set, and the buying club type (`+0xa8`) isn't 3:
  - reputation/ability terms plus 156 weeks' wages, times constants
  - halved by a factor for some clubs
  - clamped to 5,000–3,000,000
  - nation `0x307` takes a tenth

### `uses_bosman_rules` (`usbs`, TRANSFER_RULES `+0x8a`)

- Only `CHN_TRANSFER_RULES` sets it to 0 (`FUN_010c37a0`). Everyone else, and the base constructor, use 1. The one `usbs` record in `comps.dbc` is `true`.
- Its only reader found is `GAME_NATION` vfunc `+0x4c` (`00acefe0`): `nation→vfunc 0xd0 → +0x20 → +0x4c (rules) → +0x8a`.
- Callers of that virtual weren't found statically. There are 174 `call [reg+0x4c]` sites and none was identifiable as a nation call.
- So what it switches is **unknown**. It wasn't used as a lever.

### Offer types

`vfunc +0x48` gives the offer type, checked against each class's getter:

| Type | Class |
|---|---|
| 1 | `TRANSFER_OFFER` |
| 2 | `FULL_TRANSFER_OFFER` |
| 3 | `LOAN_OFFER` |
| 4 | `TRIAL_OFFER` |
| 6 | `COOWN_OFFER` |
| **7** | **`ENQUIRY_OFFER`** |
| 8 | `DRAFT_OFFER` |
| 9 | `TRADE_OFFER` |
| 10 | `B_CLUB_MOVE_OFFER` |
| 11 | `AGENT_OFFER` |

- **Type 7 is an enquiry, not a compensation offer.** The `no_compensation` patch in `patches_fees.py` therefore changes how the AI answers *enquiries*: it skips the asking-price counter-offer.
- Out-of-contract compensation travels as the fee of a `FULL_TRANSFER_OFFER` whose byte `+0x3a` is 3 (free transfer).

### Contract expiry

- **`FUN_00b04f30(person)`** runs daily for each person (from `009cc2f0`) and calls **`FUN_007cb2d0(contract, person)`** (`ret 8`).
- The contract's end date is stored at `+0x24` and `+0x26`:
  - `+0x24` is a word: day of year in bits 0–8, 1-based, plus other bits.
  - `+0x26` is the year.
  - "No end date" is the sentinel `DAT_0239eb64`/`66`.
  - `FUN_015c0cb0` gives the days left. It returns 0 both on expiry day and for "no end date".
- **`FUN_007cb2d0` decides, in this order:**
  1. **Release flag** (contract `+0x32` bit `0x20`) set and days ≤ 0: clear the flag, then call `FUN_00478070(person, contract, 1)`, which releases the player.
     - The flag is set when the human picks "release" on the contracts-expiring news response (`CONTRACT_EXPIRING_RELEASE_PLAYERS_RESPONSE_OBJECT`, `01f6ccf0`).
     - `01ebcd40` (network option 7) also sets it.
  2. **Contract types other than 2, 4 and `0x10`** (`FUN_016dd350`, at `007cb5b3`), meaning full, youth and similar contracts:
     - if days == 0, call `FUN_00478070(person, contract, 0)`
     - if the contract has no end date, check weekly.
  3. **Types 2, 4 and `0x10`** (non-contract and amateur): age-based checks, then `FUN_00478070(…, 1)`.
- **`FUN_00478070` does the actual expiry:**
  - an agreed future move is executed (`FUN_0088e720`)
  - or the player is released with `FUN_00ebf920` (reason 3, 6 or `0xb`)
  - `CONTRACT_EXPIRES_NEWS` is posted for the human
  - plus some end-of-career handling. **Guess:** `vfunc 4(1) >= 0x83` then `FUN_0163e210`.

## Retain and transfer: very long contracts (A) or rollover at expiry (B)

**A. Very long contracts.** Not recommended. The reasons below come from the code:
- **No single lever.**
  - There's no league-rule tag for contract length.
  - End dates are per person (`+0x24`/`+0x26`), so existing contracts would need a pass over every person when a game loads. I found no hook for that.
  - New contracts would need the human offer UI, the AI offer length and the player-demands code all changed. None of their length limits were found in code.
- **Releasing becomes unaffordable.** `FUN_0047ca40` pays wage × days left ÷ 7, plus a second weekly amount. A contract running to retirement (15–20 years) costs about 800–1,000 weeks of wages to release, whether the human releases (`00ebf920`) or the AI does (`00f32700`, which ignores cost). AI clubs would bankrupt themselves releasing squad players, and the human couldn't release anyone.
- **Valuations distort.** **Guess:** contract length (days left) feeds the selling valuation (`person vfunc +0x28`) and the AI's "would sell" checks. Every player would look locked in and too valuable.
- **Other effects:**
  - The compensation formula (`FUN_006d4d20`) uses 156 weeks' wages, not contract length, so it's unaffected.
  - The days-left helper clamps at 29,999 days and the year is a u16, so FM's date range is fine.
  - Wage rises and renegotiation would effectively stop: players would only renegotiate through the happiness/"wants new contract" mechanics, which weren't traced.
  - Retirement at contract end would rarely happen.

**B. Rollover at expiry, only if the club wants him.** Recommended and implemented as `nostalgia_retain_on_expiry`. Historically a club could keep an out-of-contract player only if it had offered him a renewal; otherwise he was free.
- **What it does:** a hook at `007cb5b3` catches only "full contract, days left == 0, real end date", and only when the club wants to keep the player (see "Who counts as wanted" below). It adds one year to the end date in place: year +1, and day 366 becomes 365 when the new year isn't a leap year, the same adjustment the game makes in `016db110`. Then `FUN_007cb2d0` returns 0, as on any non-expiry day.
  - Wages, clauses and the rest of the contract are untouched ("on equal terms").
  - The next day the player simply has a contract running a year longer. He can be sold for a fee as usual, and he gets `CONTRACT_EXPIRES_SOON` news again the next season.
- **Who counts as wanted:**
  - **Human club** (the club's first team is human-controlled: `FUN_0158a9e0(team, 1)`, the same test `FUN_007cb2d0` uses at `007cb55c`): wanted, unless the human chose "release" on the contracts-expiring news. That choice sets contract flag `0x20`, and its branch runs before the hook.
  - **AI club:** wanted unless the player's contract squad status is **7, "Not Needed"** (contract `vfunc +0x80` = byte `+0x30`).
- **Still released or handled as vanilla:**
  - **AI players marked "Not Needed"** and **human players marked for release**, exactly as before: release, `CONTRACT_EXPIRES_NEWS`, free agent.
  - **Players with a move already agreed** (player `vfunc +0xe8(0,0)`): pre-contracts and future transfers. The move still happens, with the compensation agreed when it was made.
  - **Staff:** non-players have no player part (`person vfunc +0x378` returns 0), so their contracts expire as before.
  - **Non-contract and amateur deals** (types 2, 4 and `0x10`) and contracts without an end date.
- **How the human is informed:**
  - `CONTRACT_EXPIRES_SOON` news and the "release" option work as before.
  - At expiry there's no news for a rolled-over player: `CONTRACT_EXPIRES_NEWS` comes from `FUN_00478070`, which is skipped. The squad screen just shows the new date.
  - To let a player go after a rollover, the human uses the normal release, which costs the remaining contract (up to a year's wages; `notice_club_side` would cap it at 2 weeks but belongs to the labour-rights set), or sells him.
- **Why squad status is the AI signal.** I looked for a stored "would renew" decision and found none that's usable:
  - FM keeps a renewal **negotiation** record only while an offer is pending (`person vfunc +0x1b4(club, 0)` with an offer at `+0x38`). `FUN_007cb2d0` already keeps such a player while the offer is pending: if a response is due within 14 days, his contract is made open-ended at `007cb465`.
  - A refused offer leaves no per-player trace. `FAILED_CONTRACT_NEGOTIATION_INFO` records are kept per club for staff/manager negotiations.
  - The AI release routine `00f32700` is a squad-trimming pass with a caller-supplied rating threshold, not a per-player opinion.
  - Squad status, by contrast, is the AI's own standing judgement of each player, stored on his contract.
  - **The enum** is taken from the game's own parser (`017a81c0`: `KEY_PLAYER`=1, `FIRST_TEAM`=2, `ROTATION`=3, `BACKUP`=4, `HOT_PROSPECT`=5).
  - **Value 7 is "Not Needed"**, inferred from the AI's bid evaluation `FUN_01f325f0`. It switches on this status to set the fraction of a player's value the club will accept: 1 → 0.6, 2/3 → 0.5, 4/6 → 0.4, 5 → 0.5 (lower when another condition holds), and **7 → 0.1 always**, i.e. the club would dump him. Status 6 is then "Youngster", FM15's remaining status.
- **AI clubs in practice:**
  - Players the AI has marked "Not Needed" leave free, as in vanilla.
  - Everyone else whose contract runs out is kept on the same terms.
  - Transfer listing alone does not count as unwanted. I couldn't locate the listed flag reliably, and historically a listed player at contract end still cost a fee.
  - The AI's release routine (`00f32700`) and transfer listing still work.
- **Why one year, not "until he moves":** a one-year extension keeps every date valid, keeps release costs bounded at a year's wages, and repeats every season.

## Patches

| Patch | What it does | Confidence |
|---|---|---|
| `nostalgia_compensation_any_age` | **(1)** `00ea7feb`: `FUN_00ea7fc0` returns true as soon as the selling club is a real club, so there's no age limit and no destination condition. **(2)** `006d55dc`: NOP the `jge` after `cmp age,24` in `FUN_006d4d20`, so the general compensation formula applies at every age. | Medium-high that compensation becomes due and non-zero for players of any age approached at the end of their contract. Low-medium on how the settlement then plays out (see risks). |
| `nostalgia_no_pre_contracts` | `00640b0e`: after zeroing its outputs, `FUN_00640ad0` jumps to its own "no" exit. No club, AI or human, can agree a move with a contracted player whose deal is running out. | Medium-high for the AI, which plans and bids through this function. Medium for the human: the "can offer contract" check `FUN_00ee8530` uses it, but the actual button or action wasn't traced end to end. |
| `nostalgia_retain_on_expiry` | `007cb5b3`: `jmp 020c1a00`. The cave at `020c1a00`–`020c1a7f` (128 bytes, `"va"` key, so it can only be applied in memory) rolls an expiring full contract over by one year when the club wants the player (human: not marked for release; AI: squad status isn't 7 "Not Needed"), keeping vanilla behaviour otherwise. | **Medium-high** that wanted players' contracts stop expiring and that the date write is valid: it uses the game's own field and leap-year logic, and the hook reproduces the original branch exactly. **Medium** on the AI signal: 7 = "Not Needed" is inferred, and how consistently the AI marks unwanted players "Not Needed" before expiry wasn't measured. Medium on side effects: no expiry news, and old players who would have retired at contract end. |

The original bytes were checked against `original/fm.exe`. Every patch was disassembled after patching (capstone):
- No rel32 or short jump targets the replaced hook tails.
- Every call in the cave cleans up its own arguments: `FUN_015c10a0` takes none (fastcall), player `vfunc +0xe8` ends in `ret 8`, `FUN_0158a9e0` ends in `ret 4`, contract `vfunc +0x80` takes none, and `FUN_01c1ea50` ends in `ret 4`.
- ESI and EDI are preserved, and the cave exits through the function's own epilogues.
- No byte or VA overlaps any `patches_*.py`, including `patches_clauses.py` and `patches_foreign_cap.py`, whose caves end at `020c1a00`.
- `patch.py` applies the two offset-only patches. It refuses `nostalgia_retain_on_expiry` because of the `"va"` cave, as intended, so that one needs `tools/fm15_loader.py`.

Cave space: `020c1a00`–`020c1a7f` is used. `020c1a80`–`020c1bff` is free.

## How the patches work together

The user's set is `nostalgia_retain_on_expiry` + `nostalgia_compensation_any_age`. Pre-contracts stay allowed, as they did historically, but the new club pays compensation. **`nostalgia_no_pre_contracts` stays out.**

- **Wanted players can only leave for a fee.** Their contracts roll over, so they never become free agents. The ways out are:
  - a normal bid (types 1 and 2, AI selling evaluation `FUN_01f325f0`)
  - a pre-contract in his final months
- **A pre-contract costs compensation:**
  - `FUN_00640ad0` fills the compensation output from player `vfunc +0x2c`, called with `param_3` = 0 (`00640fd9`), whenever `FUN_00ea7fc0` says it's due.
  - `nostalgia_compensation_any_age` makes it due for any real selling club and removes the age-24 gate on the amount.
  - The AI bid code `FUN_00cb9e40` then creates the offer with the compensation as its fee: `FUN_00919690(person, club, kind, target, 0, compensation)`.
  - The AI buyer budgets it (`calculate_cost_of_transfer` type 5 = compensation + contract cost).
  - The human sees it in the contract offer.
- **Retention and pre-contracts don't conflict:**
  - When the contract end date arrives, a player with an agreed move has player `vfunc +0xe8` true. The cave then hands him to vanilla expiry (`FUN_00478070` → `FUN_0088e720`), which executes the move.
  - A player whose renewal negotiation is still pending is made open-ended by vanilla code before the hook is reached.
  - I found no path where a wanted player is both kept and moved, or where retention turns a pre-contract into a free move.
- **Remaining ways a move can be free:**
  - **Unwanted players:** AI "Not Needed" or human "release". They leave as free agents, as historically.
  - **Nation and contract-type special cases** in `FUN_006d4d20` that return 0 (e.g. nation ids `0x2fc`/`0x314` with contract types 2/3/4), and buying-club type 3 (`club +0xa8`).
  - **Pre-contracts agreed before the patches.**
- **No code interaction:** the patches touch different functions. The rollover hook doesn't call `FUN_00640ad0`, `FUN_00ea7fc0` or `FUN_006d4d20`.
- **`nostalgia_no_pre_contracts`** remains available on its own. With it, rollover makes wanted players leave only through bids.

## Risks and what wasn't done

- **The labour-rights patches cancel these.**
  - `no_transfer_fees` zeroes every fee, including compensation.
  - `notice_player_side` auto-accepts type 1 and 2 offers and zeroes their money.
  - Don't combine either with nostalgia mode.
  - `notice_club_side` would also make releasing a rolled-over player cheap (2 weeks' wages).
- **Rollover side effects (B):**
  - AI players reaching expiry without "Not Needed" status are kept even if the AI simply never got round to deciding about them.
  - There's no news when a contract rolls over.
  - Players in their mid-30s whose retirement FM handles at contract end may play on. **Guess:** retirement announcements are processed separately and still happen.
  - Player happiness about contract status wasn't traced.
- **Per-nation special cases in `FUN_006d4d20` still apply.** For example, nations `0x2fc` and `0x314` return 0 for some contract types in the same nation. Nation ids weren't mapped to names.
- **Settlement of the compensation isn't verified.** It's unclear whether the selling AI accepts the computed amount or sends it to a tribunal or counter-offer. **Guess:** it's handled as the fee of a type 2 offer with `+0x3a = 3`, evaluated by `FUN_01f325f0`.
- **Pre-contracts already agreed in a save still complete.** These are `FUTURE_TRANSFER`, `PLAYER_IS_LEAVING_ON_BOSMAN` = transfer status flag `0x26`. The rollover deliberately lets them through.
- **Some AI "his contract is running down" reasoning may change**, because `00640ad0` now always says "no approach possible": `00b9c670`, `006ad350` and others call it. **Guess:** this only removes urgency.
- **`FUN_01637730` isn't covered.** It's behind the `PLAYER_CAN_PLAYER_ASK_FOR_BOSMAN` filter: an under-16 high-reputation academy player at a club in a qualifying competition. It's unrelated to adult pre-contracts and wasn't patched.
- **`uses_bosman_rules` effect is unknown** (see above).

## What to test in game

Use the in-memory loader:

```
python tools/fm15_loader.py nostalgia_retain_on_expiry nostalgia_compensation_any_age
```

…plus any non-fee patches you want. Don't include the labour-rights fee/notice patches, or `nostalgia_no_pre_contracts`.

1. **Rollover, own squad.**
   - Before 30 June, note a few players whose contracts end on 30 June. On the contracts-expiring news, choose "release" for one of them.
   - Advance past 1 July:
     - The released player should have left.
     - The others should still be at the club, with the same wage and a contract ending June next year (29 or 30 June).
   - Check the finances show no release payment for the retained ones.
2. **Rollover, AI, wanted players.**
   - Before 1 July, use the player search (squad status column) to note AI players whose contracts end this season, split into "Not Needed" and others.
   - After 1 July:
     - The "Not Needed" ones should be free agents.
     - The others should still be at their clubs, with dates a year later.
3. **Squad status enum check.** Pick an AI player shown as "Not Needed" with a contract ending on 30 June and confirm he becomes a free agent on 1 July. If instead "Youngster" or another status leaves, the inferred value 7 is wrong.
4. **Fee to leave.** Bid for a rolled-over AI player. It should be a normal fee negotiation, with no free-transfer option.
5. **Pre-contract with compensation, human.**
   - From January, offer a contract to a 29-year-old at an AI club, whose contract ends in June and who isn't "Not Needed".
   - The offer should show compensation to his club.
   - On 1 July he should join you, the compensation should be paid, and he should **not** be retained by his old club.
6. **Pre-contract, AI.** Holiday January to July. "Agreed to join … at the end of the season" news should appear, and the 1 July moves should show a compensation fee rather than "free".
7. **Exceptions.** Staff contracts should still expire, and non-contract players should behave as before.
8. **Stability.** Advance through several 30 June / 1 July boundaries, including a leap year (2016). Also check a contract ending 31 December in a leap year if one exists.

## Files

- `README.md`: this file
- `precontract.c`: `FUN_00640ad0`, `FUN_0103a840`, `FUN_0103a8a0`, `FUN_00ea7fc0` and their callers
- `can_sign.c`: `FUN_00d454a0` and its callers, including `calculate_cost_of_transfer`
- `compensation.c`: `FUN_006d4d20`
- `comp_parts.c`: compensation helpers
- `expiry.c`: `FUN_007cb2d0`, `FUN_00b04f30`, `FUN_00a9cd70`, `FUN_00ee5da0`, `FUN_006d2190`, `FUN_0088e720` and `FUN_00eba950`
- `expiry_news.c`: `FUN_00478070`, `FUN_00ea9060` and the free-transfer news users
- `flag20.c`: the release-flag setters (`01f6ccf0`, `01ebcd40`)
- `renewal.c`, `renew_callers.c`, `failed_neg.c`, `failed_neg2.c`: the search for an AI "would renew" signal (renewal rules, callers of `FUN_006d2190`, `FAILED_CONTRACT_NEGOTIATION_INFO`)
- `readers_8a.c` and `member_8a.txt`: `uses_bosman_rules` readers and writers
- `bosman_filters.c` and `rtti.txt`: Bosman filter classes and vtables
- `slot3c_near.txt` and `rules_slot3c.c`: unsuccessful searches for slot `0x3c` callers
- New scripts: `ghidra_scripts/BosmanDecompileCallers.java` (decompiles callers, filtered by a substring) and `ghidra_scripts/BosmanSlotNear.java` (finds vtable-slot calls near a given call or operand)
