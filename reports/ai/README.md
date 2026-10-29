# AI squad-building and team selection vs the new rules

This report checks where AI clubs' own logic still assumes the old rules: transfer fees, loans, transfer windows and squad quotas. Everything here comes from reading the code statically. None of it has been tested in the game. The optional patches are in [patcher/patches_ai.py](../../patcher/patches_ai.py), and none of them are in DEFAULT. The runtime check is `tools/trace_ai.py`.

Addresses are Ghidra virtual addresses (image base 0x400000).

## How the AI builds a squad

1. **Building the shortlist.** `FUN_00b86c00` builds the shortlist (called from `FUN_00f5a1d0`; `TC_SHORTLIST::create_shortlist` is `0073d650`).
   - It adds transfer targets through `FUN_006f4290`.
   - It adds loan targets through `FUN_0059a330`, but only if `TC_SHORTLIST::should_attempt_loans` says yes. With `no_loans` it never does.
   - Each target has a type byte (`+0x25`): 4 = buy a contracted player, 5 = free agent, 3/0x11/1 = loan-style, 8 = co-ownership-like, 13 = another purchase type.
2. **Deciding on each target.** `TC_SHORTLIST::make_transfer_decision_for_player` (`00517b20`) handles this.
   - It calls `TC_SHORTLIST::calculate_cost_of_transfer` (`0095cfe0`) twice: once for the fee alone, and once for the fee plus the contract and wage cost (`FUN_00e785f0`).
   - For type 4 and type 13, the fee estimate is the player's release clause (`FUN_0163e8c0`). If there's no clause, it's the selling club's valuation (`player vfunc +0x28`), with multipliers.
   - If the estimate is above the transfer budget, or above the target's maximum fee (`target +0x38`), the target is dropped. The reason codes are 2 ("costs too much") and 5.
   - A further check gives up when the buying club's reputation is well below the selling club's (`sVar7 < sVar6 * DAT_022d21f8`, when `FUN_0155ded0(0) > 4`).
   - Survivors are dispatched by type:
     - 1/3/0x11: `FUN_00cb5360`, which makes a loan offer (`FUN_00f26870`), or for 0x11 sometimes a purchase.
     - 2/4/6: `TC_SHORTLIST::make_transfer_offer`
     - 5: `make_free_transfer_offer`
3. **Releasing players.** `FUN_00f32700` (called from `FUN_01f08430`) releases squad members whose rating is between 500 and a threshold, paying them through `FUN_0047ca40`/`FUN_004a7790`. That payout is already capped at 14 days by `notice_club_side`.
   - The decision itself never looks at cost.
   - So the AI doesn't avoid releases because of large payouts. It only releases weak players, as before.

## How the AI picks teams

- **Matchday squad.** `SQUAD_SELECTOR::select_squad_of_players` (`00e43340`) uses constraints built by `FUN_00852050`. Hook B in `squad_rules_core` makes it skip disabled rule types.
- **Starting XI and other rule checks.** These go through `FUN_00f8a750`, which hook A makes return "satisfied" for disabled types:
  - `FUN_0097eea0`: starting-XI rule checks, including selection warnings
  - `FUN_00c93440`: matchday and XI rule checks plus warning text
  - `FUN_00f8c8b0`: "would adding this player still satisfy the rules"
- **The selectors themselves** (`TEAM_SELECTOR_RECURSIVE::*`, `GAME_SQUAD_TEAM_SELECTOR`, `GAME_MATCH_TEAM_SELECTOR`) don't read the rules directly. I found no rule lookups in them.
- **Conclusion:** team selection already follows the disabled groups. No extra patch is needed.

## Mismatches, ranked by impact

| # | Mismatch | Where | Impact | Fix |
|---|---|---|---|---|
| 1 | **AI prices contracted targets at their valuation.** It drops good players as "too expensive" even though every transfer now costs £0. Rich clubs are unaffected, but most clubs never try for players above their budget. | `calculate_cost_of_transfer` type 4 (`0095d02a`) and type 13 (`0095d223`) | High: it shapes who the whole AI market targets | **`ai_fee_free_targets`** (high confidence). Treats every player as having a £0 release clause, in this function only, and keeps the contract and wage cost. Better than the fees fork's `ai_ignores_valuations`, which drops the wage part too; use one or the other, not both. |
| 2 | **Agreed moves wait 30 days.** With windows off, "next window date" (`FUN_00b9dc30`) returns today + 30 days, and that date becomes the offer's completion or response date (`add_transfer_offer` → `FUN_0063b120`). It's effectively a 30-day notice period, where the design is 14. | `00b9dc53` `push 0x1e` | Medium. Consistent, but not the intended length. It also makes the AI think a window is always 30 days away (see #5). | **`transfer_notice_14_days`** (medium confidence that the date really is the completion date; the change itself is a 1-byte constant). Check in game: an agreed transfer should complete about 2 weeks later instead of 30 days. |
| 3 | **Squad-cap readers ignore `no_squad_size_cap`.** Planning and UI still see a 25 or 28 cap. | `FUN_00f8ba60` (rule lookup) and `FUN_00f8bab0` (value lookup) | Medium. The AI keeps planning to the old cap. When "places left" is computed from the cap, minimum rules get a different slack. | **`squad_rules_counters`** (high confidence). See below. |
| 4 | **The AI keeps trying to arrange loans.** Shortlist targets of type 1/3/0x11 still produce loan offers (`FUN_00cb5360` → `FUN_00f26870`), all rejected. Loan-listed youngsters stay at their clubs. | `FUN_00cb5360`, `FUN_00f07d50` | Low. About 250 loan offers per 15 minutes against 1,600 to 3,800 accepted transfers; those slots are wasted until the target is dropped. | Not patched. A fix would make `FUN_00cb5360`'s loan branch drop the target straight away; the payoff is small. |
| 5 | **"Window more than N days away" branches always fire.** In `make_free_transfer_offer`, more than 13 days means the AI offers a *trial* (`FUN_00579410`) instead of a contract (`FUN_00919690`) to some weak free agents (rating below 25, not an international, and so on). In `make_transfer_offer`, more than 9 days with a human seller goes to `FUN_006d6010` instead of a normal bid (`FUN_00cb9e40`). | `0057dcc0`, `00b7c870` | Low to medium | Not patched. With `transfer_notice_14_days` both still fire. Setting the constant to 9 days would switch both off at the cost of a 9-day notice period. The trace counts trials against contracts. |
| 6 | **Big clubs are "unapproachable".** The AI gives up on targets at clubs with much higher reputation, a habit from when those clubs would refuse to sell. Now the player decides, and may still refuse a smaller club in contract talks. | `00517b20` (reputation check before the type switch) | Medium, a design question | Not patched. It's realism the user may want to keep, and I'm not certain what `FUN_0155ded0(0) > 4` gates. |
| 7 | **The non-EU signing limit bypasses hook A.** `GAME_ACTUAL_PLAYER` vfunc `+0x188` (`FUN_005bc880`, the "can this player join or register" check) reads type 0x53 directly and counts with `FUN_01605ae0`, giving reason 0x23. | `005bc880` | Only matters if `no_non_eu_limit` is used, which the user treats as tied to national law | Not patched. Noted for the non-EU group. |
| 8 | **Homegrown reminders and text.** `SQUAD_SELECTION_WARNING_NEWS` (`004f68f0` / `01f97b20`) and `SQUAD_SELECTION_INFO_PANEL` (`00ac3f50`) read the homegrown and squad-size rules directly to build text. | UI | Cosmetic. They may still mention quotas. | Not patched. |

Not mismatches:
- **Release decisions** (see above).
- **Team selection** (see above).
- **The AI's response to bids:** bypassed by `notice_player_side`.
- **`FUN_0149f3e0(1)`:** this is "is this club human-managed", not a window check.

## `squad_rules_counters`

**What the readers do:**
- `FUN_00f8ba60` (thiscall: ECX = rule list, one argument `byte* index_out`, `ret 4`) finds the **max_squad_size (type 9)** rule and returns it, or 0 with `*index_out = 0xff`.
- `FUN_00f8bab0` (fastcall: ECX = rule list, plain `ret`) returns that rule's value, or -1.
- For both, "no cap" is the not-found answer, exactly as for a competition that has no squad cap.

**The patch:**
- Each function's 5-byte prologue jumps to a stub that tests bit 9 of the `no_squad_size_cap` bitmap: `bt dword [0x020c1480], 9`.
- If the bit is set, the stub takes the function's own not-found exit. Otherwise it runs the replaced instructions and jumps back.
- Stubs are at `020c14e0` (26 bytes) and `020c15e8` (24 bytes).

**Why not call the shared checker (`020c1570`):** these readers only ever ask about type 9, and calling the checker would crash if `squad_rules_core` weren't applied, because that address would be zeros. Testing the group's own bitmap means the patch does nothing unless `no_squad_size_cap` is applied, and can't crash.

**Dependency:** use it together with `squad_rules_core` and `no_squad_size_cap`. With the bitmap but no core, the counters would say "no cap" while enforcement still applies it.

**Call sites:** there are **6 call sites of `FUN_00f8ba60`**, not 16 as the squad README says, plus 8 of `FUN_00f8bab0`.

| Caller | Function | What it does with the cap | Guess |
|---|---|---|---|
| `007d274f` (+ `007d275d` value) | `FUN_007d2420` (from `00c77960`) | Copies squad-selection settings and stores the cap value | Settings snapshot (UI or competition setup) |
| `007f8871` | `FUN_007f85f0` | Slack = cap minus registered players, used when testing *minimum* rules | **Registration legality check.** With no cap the slack is 1, the game's own behaviour for uncapped competitions. If you disable the cap but keep homegrown minimums, minimums are tested more strictly. |
| `00d2f120` | `FUN_00d2f120` (from `00ae58a0`) | If there's no cap rule, adds one from a default value (`FUN_00f8c270` mode 0, which appends) | Selection or registration setup. With the patch it may append extra (disabled) type 9 rules when its settings change. These are harmless because the patch hides them, but the list can grow. |
| `00de01db` | `FUN_00de0100` (from `01f24b30`, `008670f0`) | Excess = registered players minus cap (at most 50) | AI or registration: "players to deregister or release" |
| `00f8c997` | `FUN_00f8c8b0` (from `005bc880`, `00d10c50`, `00a2a710`, `01e14a90`) | Places left = cap minus count, or 100 if there's no cap | **Signing eligibility** for AI and human: "would this signing break the squad rules" |
| `01f85f2e` | `FUN_01f85e60` (from `01f84e60`) | Removes the cap rule's entry from a working list | Selection or UI rule list |
| `00a24aff`, `01061031`, `01061301`, `010618a5`, `0109d17c`, `011557ca`, `011806c3` | (value lookup `FUN_00f8bab0`) | Read the cap value directly | Not decompiled one by one. UI counters and planning; they now see -1 ("no cap"). |

## Code caves

The zero padding at the end of `.text` (`020c1414`–`020c15ff`) is now mostly used:

| Range | Used by |
|---|---|
| `1420`–`14df` | squad bitmaps |
| `14e0`–`14f9` | this patch |
| `1500`–`1569` | notice cave |
| `1570`–`15ab` | squad checker |
| `15b0`–`15d0` | squad hook A |
| `15d4`–`15e7` | squad hook B |
| `15e8`–`15ff` | this patch |

**Still free:** `1414`–`141f`, `14fa`–`14ff`, `156a`–`156f`, `15ac`–`15af` and `15d1`–`15d3`, about 30 bytes in fragments.

**For future patches:** there are no `0xCC` or `0x90` padding runs in `.text`. There are 127 other zero runs of at least 48 bytes (for example 170 bytes at `0051f6e6`), but those may be data tables inside `.text`, so they'd need checking before use. Another option is a new section.

## Runtime check: `python tools/trace_ai.py reports/ai/trace.txt 15`

The tracer is read-only. It counts the following:

| Measurement | What to look for |
|---|---|
| AI cost estimates by target type | With `ai_fee_free_targets`, type 4/13 should be wages only (the `withContract=0` lines should be 0) |
| Transfer decisions by reason code | Reason 2 ("too expensive") should almost disappear with the patch |
| `make_transfer_offer`, free-transfer offers and trial-instead-of-contract offers | Mismatch #5 |
| Loan offers created | Mismatch #4 |
| AI release batches and each release payment (amount) | Club-side notice: payments should be about 2 weeks' wages |
| Squad-cap lookups with their found/none/value result | `squad_rules_counters` should show "none" and value -1 when `no_squad_size_cap` is on |

Run it once on the current build for a baseline, then again with the AI patches.

Squad sizes over time aren't hooked. Compare a few AI squads at the start and end of a season by hand.
