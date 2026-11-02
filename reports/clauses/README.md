# Release clauses (nostalgia mode: clubs can refuse any move)

> **Not part of the nostalgia set.** Nostalgia mode keeps release clauses as vanilla FM has them: they existed before Bosman, and Spain has required them since 1985. `nostalgia_no_release_clauses` stays available as an optional patch you have to name. The negotiation-side work below was stopped before any patch was written.

Research for the pre-Bosman "nostalgia" mode: a player can only leave if his club agrees, so release clauses must stop forcing sales. fm.exe 15.3; addresses are Ghidra VAs (image base 0x400000). Static analysis only. Nothing here has been tested in game. The patch is `nostalgia_no_release_clauses` in [patcher/patches_clauses.py](../../patcher/patches_clauses.py). It isn't in DEFAULT and doesn't need the labour-rights patches.

## How release clauses work in FM15

**Storage.** A player's club contract is a `FULL_CONTRACT@DB` (vftable `0x020d5940`). Its clause list is a vector of 8-byte `{int amount, byte kind}` entries at `+0x3c`/`+0x40`, with these accessors:

| vfunc | Role |
|---|---|
| `+0x98` / `+0x9c` | Get entry *i* / count |
| `+0xa0` / `+0xa4` | Find / remove by kind |
| `+0xa8`–`+0xb4` | Set or copy clauses |
| `+0xb8` | **The release-clause lookup.** `016dc550`, thiscall, 1 argument (the buying club), `ret 4` |

**The `+0xb8` lookup.** It returns the cheapest entry that applies to the buyer, or NULL. These kinds count as release clauses:

| Kind | Applies to |
|---|---|
| `0x00` | Any club |
| `0x10` | Clubs from another nation |
| `0x12` | Clubs from the same nation |
| `0x11` | Clubs in a higher division (compares division byte `+0xdd`) |
| `0x1b` | Clubs in a given competition (`FUN_015c7430(0x1b, …)`) |
| `0x27`, `0x28` | Always |

`B_CLUB_CONTRACT` forwards `+0xb8` to the main contract. `CONTRACT`, `LOAN_CONTRACT` and the trial contracts return NULL (`008d94a0`).

**The "must sell" fee.** `FUN_00c2f780(player, buying team, &kind, &amount, &flag)` (`ret 0x14`) returns the lowest fee the seller is obliged to accept. It checks these sources in order:

| Kind | Source | Meaning |
|---|---|---|
| `'%'` (0x25) | Seller-club relation (`FUN_014bd1d0`, flag 2) with the buyer, for AI clubs | Affiliate deal, fee 0 |
| `'$'` (0x24) | Player's loan arrangement (`player vfunc +0x36c`, `FUN_007152e0`, `+0x14`) | Pre-agreed fee for the loan clubs |
| contract kind | **Contract `+0xb8`** (`00c2f928`) | **Release clause** |
| `'!'` (0x21) | Player's `LOAN_CONTRACT` (type 1) with the buyer (`FUN_01545810`), `+0x3c` | Loan option-to-buy fee |
| `'#'` (0x23) | Selling club's agreement list (`+0x50`, entry kind 7) for this player and buyer (`FUN_014c0620`) | Club-to-club agreement |
| `0x10`/`0x11`/`0x12`/`0x1b` | Nation or competition rule list (`FUN_00fd83b0` → `FUN_010376d0`, kind mapped by `FUN_015c6f80`) | **Rule-imposed release fee.** `FUN_00d1ace0` also syncs contract clause amounts from it. |

`FUN_00e2c200` (bid UI logic) treats `! # $ %` as agreed prices and the others as clauses, which confirms this split.

**"Meets the clause".** `FUN_00ab1cf0(offer)` calls `FUN_00c2f780(offer[1], offer[2])` and compares the offer's value against the amount, using `FUN_0043dec0`, which also rejects offers with extras. It has 22 callers, including these:

| Caller | Who | Effect of meeting the clause |
|---|---|---|
| `FUN_01f325f0` | AI evaluation of incoming offers | Accepts at once, skipping every valuation check |
| `TRANSFER_OFFER_RESPONSE` vfunc `+0x50` (`01fa9050`) | Human seller | Auto-accepts (`00ca6360`); state 7 or 8 drives the "bid met the release clause" message |
| `FUN_004d8b20` | Human auto-response settings | Uses it, and reads contract `+0xb8` directly for the threshold |
| `FUN_01f38750`, `FUN_00be8c00`, `FUN_02031890`, `FUN_00505770`, `FUN_00eda560` | Counter-offers, offer screens, AI decisions | `00e82380`, `006ad350` and `00f20a90` also cap counter-offer fees at the amount |

`CLAUSE_BUYOUT_NEWS` (vftable `0x021208bc`, ctor `00baa690`) is built by the message handler `00a71d20`, which is dispatched from `009483cd`. It's downstream of the acceptance.

**Not release clauses:**
- `FULL_TRANSFER_OFFER` vfunc `+0xfc` (`00cb50e0`) makes the AI accept offers its finances can't refuse. That's the club's own decision.
- Offers with `+0x54 == 7` come from `MATCH_BID_RESPONSE`, a club exercising a match-the-offer right.
- `+0x43 == 2` marks agreed counter-offers.

These are all agreements the selling club made itself, so they stay.

**`FUN_0163e8c0` is the asking price, not a release clause.** The AI README says calculate_cost_of_transfer prices targets "at their release clause". It's a forwarder (`DAT_024260a8` vfunc `+0x224`) to `GAME_ACTUAL_PLAYER` vfunc `+0x224` = `0077b100(player, team)`, which works like this:
- It returns -1 unless the team is human-managed (`FUN_0158a9e0(team, 1)`, same shape as `FUN_0149f3e0`).
- If the player's loan agreement with that club has a fee, it returns that (`+0x18`).
- Otherwise it returns `player+0xc4`.

`FUN_004d8b20` (the human's auto-response to offers) compares offers against this value. So it's the **asking price a human manager sets**, and it never reads contract clauses. TC_SHORTLIST::calculate_cost_of_transfer therefore already prices AI-owned targets at the club's valuation, and human-owned ones at the human's asking price when one is set. Both are club decisions, so **task 3 needs no patch.** Don't use `ai_fee_free_targets` in this mode, because it replaces that price with £0.

## The patch: `nostalgia_no_release_clauses`

| Site | Bytes | Change |
|---|---|---|
| `016dc550` (file `0x12dc550`) | `83 ec 08 53 8b` → `33 c0 c2 04 00` | `FULL_CONTRACT` `+0xb8`: `xor eax,eax ; ret 4`. No contract release clause ever applies to any buyer. |
| `00c2fa7e` (file `0x82fa7e`) | `85 f6 0f 84 83 00 00 00` → `e9 86 00 00 00 90 90 90` | `FUN_00c2f780`: always skip the nation/competition rule source (`jmp 00c2fb09`, the existing tail of the `esi == 0` path) |

Together these make `FUN_00c2f780` find no release clause, so `FUN_00ab1cf0` is false for any clause-matching bid. AI sellers then run their normal valuation in `FUN_01f325f0`, and a human seller gets the normal accept/reject flow. No code caves are used. Neither site overlaps any existing patch, including the labour-rights set (`00e66038`, `020c1500` cave, `0095d02a`, `0095d223`) and the evaluator patches at `01f32b52`/`01f328c7`. I checked by script that the original bytes match and that no branch lands inside either patched range.

**Confidence:**
- **High** that contract release clauses no longer force acceptance anywhere `FUN_00c2f780`/`FUN_00ab1cf0` is asked. I read both and the `+0xb8` implementation instruction by instruction.
- **Medium** on what the rule-list source is, beyond its clause kinds. Skipping it is harmless either way.
- **Medium-high** that no other path force-accepts a clause bid. I found none among the 22 callers, but the message-bus path around `CLAUSE_BUYOUT_NEWS` wasn't traced end to end.

**Risks:**
- Clauses still show in contract screens, which is cosmetic.
- Any other reader of contract `+0xb8` (for example, AI reasoning about whether it could "trigger" a clause) now sees none. That's intended.
- The AI buyer branch in `00e82380` that only proceeded when a clause was affordable now withdraws (`FUN_01f31560`), as it already did for players without clauses.

## Not achieved: new contracts without release clauses (task 2)

Not patched. With the patch above, stored clauses are inert, so the rule holds. The remaining effect is in contract talks: players and agents still ask for release clauses, and a human can still offer them as a sweetener that now costs nothing.

**Leads:**
- `016db200` is `FULL_CONTRACT` "apply clause request" (a switch over request kinds; table at `0x016dbf8c`). The release-clause cases are:
  - request 3 → kind `0x00`
  - request `0xf` → kind `0x10`
  - request `0x10` → kind `0x11`
  - request `0x1d` → kind `0x12`

  Pointing those table entries at `016db269` ("done, nothing added") would drop them. However, its only caller is `FUN_00acf530` (batch from `01f35c00`, apparently stored or future deals), not the normal signing path.
- Normal signings seem to copy clauses with the contract `+0xa8`–`+0xb4` setters, and push directly through the vector helper `016df800`, which has 28 callers.
- The fix belongs in the negotiation code that proposes or demands those request kinds. It isn't located yet.

## In-game test steps

1. Start the loader with only `nostalgia_no_release_clauses` (plus whatever nostalgia set), with no labour-rights patches. Check that `track_mods` or the loader reports both sites patched.
2. **AI seller.** Find an AI-owned player with a minimum-fee release clause (Contract tab, Clauses), ideally at a Spanish club. Bid exactly the clause amount, with no add-ons.
   - Before: the club accepts at once ("bid meets release clause") and you go to contract talks.
   - Now: it should respond like any bid, often rejecting it or asking for more, especially for key players.
3. **Clause variants.** Repeat with a "foreign clubs" clause as a foreign club, and a "higher division" clause from a lower-division player while you manage a higher-division club. Neither should be forced.
4. **Human seller.** Give one of your players a release clause in a renewal, or pick one who already has one. Wait for or provoke an AI bid at that amount. It should arrive as a normal offer with Accept/Reject/Negotiate, not "the release clause has been met". AI clubs may also stop bidding exactly the clause figure.
5. **Kept behaviour (regression).**
   - A loan with an agreed future fee or option to buy still completes at that fee.
   - A club's "accept offers above asking price" auto-response still works, now at the asking price alone.
6. **AI planning.** AI clubs should still sign plenty of contracted players: shortlisting prices AI-owned targets at valuation. There's no change to expect here, since the shortlist never used clauses.

## Files

Raw material in this folder (gitignored):
- `c2f780.c`: clause lookup, `00ab1cf0`, `0043dec0`, `01f38750`
- `helpers.c`: `0077b100`, `0158a9e0`, `0073dbb0`, `00d1ace0`, `01545810`, `014c0620`, `010376d0`, `015c6f80`, `007152e0`, `014bd1d0`, `00fd83b0`, …
- `callers.c`: all callers of `00c2f780` and `00ab1cf0`
- `apply_clauses.c`: `00acf530` and `01f35c00`

## Negotiation-side findings (work stopped, nothing patched)

- **Where the player's demand comes from.** `PLAYER_CAN_REQUEST_MINIMUM_RELEASE_FEE` (vftable `0x0210489c`) is a condition class. Its test, `00983f10`, calls player vfunc `+0x22c`, which is forwarded through `DAT_024260e8` (a `GAME_PERSON` instance) to vfunc `+0xf4` = `00aea2a0`. That function is true only when the player's league has `release_fee_rules` (`FUN_00fd83b0` → `FUN_010376d0`) and player vfunc `+0x230` (`GAME_PERSON` `+0xf8` = `00785c10`) agrees. So players only *ask* for a release clause in leagues whose rules provide one, such as Spain. Patching the entry `56 8b 74 24 08` to `32 c0 c2 04 00` would stop the demand.
- **One point every new clause passes through.** Every insertion into a `FULL_CONTRACT` clause list (`+0x3c`) found so far goes through the generic 8-byte `vector::push_back` at `016df800` (thiscall, `ret 4`). It has 28 callers, and the contract ones all use `lea ecx,[obj+0x3c]` and never touch the pushed element afterwards. That includes:
  - the UI/scripting "set clause by kind" (`FULL_CONTRACT` `+0xac` = `016d2840`, push at `016d28a2`);
  - the "apply clause request" switch `016db200`;
  - the default/generator pushes in `016d24ce`–`016d7ffe`, among them a default kind-0 clause of 200,000 at `016d24ce`.

  A hook at `016df800` would drop release kinds `{0x00, 0x10, 0x11, 0x12, 0x1b, 0x27, 0x28}` when `[ecx-0x3c] == 0x020d5940` (the `FULL_CONTRACT` vftable). It would replace the 8-byte entry `56 8b f1 57 8b 7c 24 0c` with a jump to a cave and `ret 4` on a match. That would cover UI additions, AI offers and generated contracts, and probably the database load too.
- **Not checked:** whether the negotiation term widgets keep their own copy of the terms, and how saved-game clause vectors are loaded. Existing clauses are already inert under `nostalgia_no_release_clauses`, because the `+0xb8` getter returns NULL.
- Raw material: `switches.c` (`00aea2a0` and the clause-kind text map `00821e90`) and `demand.c`.
