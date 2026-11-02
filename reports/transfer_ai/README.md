# How AI clubs plan transfers (and why they ignore the foreign allowance)

Research for nostalgia mode's foreign-player limits: UEFA 3+2 in every league, plus `nostalgia_foreign_cap_ai` (see [../foreign_cap/README.md](../foreign_cap/README.md)). fm.exe 15.3; addresses are Ghidra VAs (image base 0x400000).

This is mostly static analysis. **Guess** marks inferences. A read-only pipeline tracer is included (`trace_plan.py` / `trace_plan.js`, below), but the game was paused for the whole session, so it recorded no live data. Section 5 says what to run.

> **Update 2: superseded by the stripped-back set (section 10).** The native foreign-limited mode does the planning; R1 and R3 were removed. **Update 1:** R1 and R3 were implemented. Section 8 covers them. Since this analysis, `nostalgia_3_plus_2` stores its rules in every competition's rule list. As a result, `+0xea` is now set natively for about 96% of AI shortlists (section 8.1). The TL;DR and sections 2–6 describe the state before that change.

## TL;DR

- **The AI plans around a depth chart, not around nationality.** A club's `TC_SHORTLIST` holds about 30 to 40 **slots** (position × squad status). Every few days the AI fills the slots with its own players. Each slot that is empty or weakly held is a **need**.
  - For each need, the AI pulls up to 10 candidates from a global, position-sorted **player pool**.
  - It registers "interest" in all of them and queues them as target decisions.
  - At least 4 days later, `make_transfer_decision_for_player` turns a decision into a bid.
- **Nothing in this pipeline knows about 3+2.** The game does have nationality-aware levers, and all of them are switched by the club's **competition rule list** or by staff attributes. 3+2 is injected only into fixture rule lists, so none of the levers turns on:
  - "foreign-limited league" flag `+0xea`
  - nation-only candidate pools
  - an affiliate "domestic only" mode `+0xe6`
  - ×1.5 valuation of domestic first-teamers
- **City.** All 40 of City's foreigners still sit in its depth chart, including the listed "Not Needed" ones, so City has almost no needs.
  - The few needs it has draw foreign candidates, which our target gate drops one by one. That produces endless interest and rumours, but no bids.
  - **Milner** (contract ending 30 Jun 2015, cheap to value) probably lost his slot to higher-rated foreigners. The AI then actively hawks unslotted players at value → 50% → 10% → free (`FUN_00809590` → `FUN_01f263b0`). No step considers that he is one of City's 3 domestic first-teamers. Section 3 has the full chain.
- **Last-minute pull-outs.**
  - Our offer gate re-runs `CHECK` every time an offer is processed, including on the **completion date** (`FUN_00daf4f0`). With windows open, that date is about 30 days after agreement, and by then the club's foreign ranking or domestic count may have changed.
  - **Likely bug:** the offer gate counts domestic players in the *destination team*. Any foreign signing headed for an U21 or U18 team then looks "short" and is killed with reason `0x29`, even though the decision gate (which counts the first team) allowed it.
- **Recommendations (section 6), from most to least robust:**
  - **R1.** Switch on the game's own levers for "short" clubs. Compute the domestic first-team count once per shortlist rebuild, then:
    - set the transfer attribute `+0xcc` = 20 (nation-only candidate pools)
    - set `+0xea` (one foreign signing per cycle, domestic valuations ×1.5)
    - drop listed "Not Needed" foreigners from the depth chart, which opens slots
  - **R3.** Fix the offer gate: count the club's first team, and don't re-check agreed deals.
  - **R2.** A precise candidate filter ("only foreigners who'd rank top-5"), if R1 isn't enough. It needs per-club caching in RW memory.
  - The CPU cost of R1 is one first-team scan per club per rebuild (about weekly).

## 1. Data structures

**Club** (`piVar2` in most functions):
- `+0x10..+0x14` vector of teams; `[+0x10][0]` is the first team
- vfunc `+0xcc` nation
- vfunc `+0x104` main competition
- `FUN_0149c780(club)`, `FUN_0149c790(club)` return the club's `TC_SHORTLIST` (stored at `club[0x14]+0x24`)

**`TC_SHORTLIST`.** One per club, AI only in practice. It's the `this` of every `TC_SHORTLIST::*` function. The fields that matter:

| Offset | Meaning | Set by |
|---|---|---|
| `+0x00/+0x04` | dates: last decision pass / last rebuild | `FUN_014be080`, `FUN_00471cf0` |
| `+0x18..+0x1c` | **the first team's competition rule list** (copy) | `FUN_00829760` → `FUN_01062190(team, list, fixture=0, 1, 1, 0)` |
| `+0x28` | competition | `FUN_00829760` |
| `+0x38..+0x3c` | own players still to be slotted ("eligible array") | `create_shortlist` |
| `+0x44..+0x48` | own players (wage accounting) | |
| `+0x50..+0x54` | **slots** (vector of slot pointers) | `FUN_01e4bdc0` and others |
| `+0x5c..+0x60` | **target decisions** queue (≤ 10000) | `add_target_decision` |
| `+0x68..+0x6c` | non-player (staff) slots | |
| `+0x98` | float 0.95 or 1.0 (probability-like gate for `FUN_0159db50`) | `FUN_00b86c00` |
| `+0xa4` / `+0xa8` | weekly wage budget / remaining (`FUN_00f8b280`/0x34) | `create_shortlist`, `FUN_004446a0` |
| `+0xb0` | club nation id | `FUN_00471cf0` |
| `+0xb8` / `+0xbc` | foreign / non-EU signings this cycle | `target_signs` ++; reset by `FUN_016e3f70` |
| `+0xc4` | flags (bit 0 AI-managed, `0x2000` …) | `FUN_00471cf0` |
| `+0xcc..+0xd4` | attributes 1–6, 0x18, 0x19 of the person who runs transfers (DoF `FUN_0149c930(7)`, else manager or chairman), 1–20 | `FUN_00815530` |
| `+0xcc` | attribute #1; **== 20 means "recruit domestically"** (see section 2) | |
| `+0xde` | club "transfer status" (100 default; `<11` → 30-day decision period) | `FUN_00829760` |
| `+0xe6` | **affiliate mode**: club has a parent club (`FUN_014bf240`) → domestic-only candidates, fill empty slots only | `FUN_00471cf0` |
| `+0xea` | **foreign-limited competition**: the rule list has a foreign-type rule (`FUN_00f8a050` types `2,3,4,0x15,…`) with no age bound below 22 | `FUN_00829760` → `FUN_00f8af70(3)` |
| `+0xeb` | non-EU-limited competition (`FUN_00f8a240` types) | `FUN_00f8b120(3)` |

**Slot** (`0x50` bytes; `param_7` / "wanted staff" of `make_transfer_decision`, `piVar1` in `FUN_00b86c00`):

| Offset | Meaning |
|---|---|
| `+0x00..+0x04` | candidate target records (≤ 10, sorted) |
| `+0x10/+0x14` | age bounds or role pair used by the rating functions |
| `+0x18` | **squad rule this slot exists for** (0 = ordinary slot) |
| `+0x24` | current holder's rating |
| `+0x30` | position bit (1 = GK, 2, 4 … 0x10000) |
| `+0x34` | **required rating** (about 30000–37000 for first-team statuses; `FUN_009c0290`) |
| `+0x38` | max fee |
| `+0x3c` | holder person id (−1 = unfilled, which makes it a need) |
| `+0x40` | offer in progress |
| `+0x49` | squad status wanted: 1 Key, 2 First team, 3 Rotation, 4 Backup, 5 Hot prospect, 6 Youngster |
| `+0x4a/+0x4b` | max / min age |
| `+0x4c` | search reason tag (`0x16` domestic hot prospect, `':'`/`';'` widened search, `'8'` keeper, …) |

**Target record** (`0x30` bytes, `FUN_016e6110`):
- `[0]` person id
- `[1]` score
- `[2]` slot requirement
- `+0x25` transfer type: 4 buy, 5 free, 7 trial/contract, 1/3/0x11 loans, 8, 0xd
- `[3]` buyer nation
- `[4]`/`[5]` the player's nation ids
- `+0x26/+0x29/+0x28` copies of the shortlist's attributes

**Target decision** (`0x20` bytes, `add_target_decision`):
- `+0` date queued
- `+4` person id
- `+0x10`, `+0x18` slot position
- `+0x1c` status
- `+0x14` flags

## 2. The buying pipeline

```
daily club tick (FUN_00ad5da0 / FUN_00675cf0 / FUN_0064b370 ...)
 └─ FUN_00e175f0(club)                         per club + its affiliates
     └─ FUN_00a71080(shortlist, club)  ── "decision pass", returns what to do next:
         │   only on days where (dayOfYear + club id) % FUN_016e5fa0() == 0 (period: 2 days default,
         │   30 if transfer status +0xde < 11, 90 for some EPL clubs, else (21-attr)/4+1)
         │   also: generate_transfer_speculation (rumours about queued type-4 targets, first 30 days)
         ├─ for each target decision older than 3 days ─► make_transfer_decision_for_player  (C)
         ├─ return 1 ─► FUN_00f5a1d0(mode 3)  = refill candidates                       (B)
         ├─ return 2 ─► FUN_014be080 = rebuild if ≥ 6 days and no offers pending          (A)
         └─ return 0/5 ─► staff recruitment (FUN_0093ba10)
```

### (A) Rebuild: needs and the depth chart

`FUN_00f5a1d0` runs mode 1 or 2. It is also triggered by events: about 25 callers of `FUN_014be080`, including squad changes, offers and `FUN_006f69f0` itself.

1. `FUN_00471cf0`: reset (`FUN_016e3f70`), staff attributes (`FUN_00815530`), then **`FUN_00829760`**:
   - copy the competition rule list into `+0x18`
   - set `+0xde`
   - **`+0xea` / `+0xeb` from the rule list**
2. `TC_SHORTLIST::create_shortlist` (`0073d650`):
   - wage budget (`FUN_00f8b280`/52)
   - slot creation (`FUN_01e4bdc0`): `FUN_00a21890` (EPL), `FUN_006ae6b0` (comp `0x1fbc1`), `FUN_007620a0`, `FUN_01e4b970`, **`FUN_00a636b0(club, 0/1)`**, `FUN_005b20e0`, `FUN_00e0e860`, `FUN_00cfea70`, `FUN_016e55c0`
   - **rule-linked slots:** `FUN_00a636b0` creates `rule.value` extra slots for every *minimum*-type rule (`rule+0xe` ∈ {1,2}, `FUN_00f8a840`) in `+0x18`, and sets `slot+0x18 = rule`
3. `FUN_009c0290`: the required rating per status (`FUN_014bae30(status)`), with floors and caps of 29500–37000 and multipliers 0.75–1.75 (constants below). `+0xea` changes the status-3 rule.
4. `FUN_0050cb80`: the **depth chart**. Up to six passes call `TC_SHORTLIST::select_player_for_this_slot` (`00f51fc0`).
   - Each slot takes the best *own* player from `+0x38`, ranked by `FUN_0160b380` position rating against `slot+0x34` × {0.8 … 1.02}.
   - Eligibility is `FUN_009ed420`: position rating, wages, youth age, and the rule for rule-linked slots.
   - **It does not exclude listed or "Not Needed" players, and it does not look at nationality.**
5. Every own player left unslotted goes through **`FUN_00809590`** → **`FUN_01f263b0`**: the AI offers him around (`FUN_00d80870`) at valuation, then 50%, then 10%, then free. This is the AI's *active* selling.
6. EPL only (`FUN_014a6d60` = league `0x28`): `FUN_006f5f60` counts non-homegrown players for the 25-man squad.

### (B) Candidates

Mode 3 runs `FUN_00b86c00`, then `FUN_00c36710`, `FUN_005c85c0` and `FUN_00c38390`.

**`FUN_00b86c00`** loops over each slot that has no candidates and is a need: the holder is missing, or rated ≤ 0.75 × required.
- `uStack_24 = FUN_016e6d20(club, FUN_014dfe00(), status)`, the **nation-only pool switch**. It is true if:
  - a global flag is set, or
  - **`shortlist+0xcc == 20`**, or
  - status > 2 and the club's nation is `0x303`
- `FUN_006f4290(nationOnly, club, slot)` fills the slot. If that finds nothing, it retries with reason `0x3a` (`':'`). Hot-prospect slots (status 5) at clubs with reputation < 8250 first try reason `0x16` (the player's nation must match the club's, `FUN_016e69e0`).
- Loans: `should_attempt_loans` → `FUN_0059a330`. Free agents and trials: `FUN_00578420`, `FUN_009ca910`, `FUN_005fab40`.

**`FUN_006f4290`** is the candidate generator.
1. Pool: `FUN_00916560(position, status, nationOnly ? clubNation : 0)` returns the global pool for the position (or the youth pool), or **the pool of players of that nationality** (`FUN_00c0ebc0`). Pools are built in `FUN_00de3d60`, keyed by the player's nationalities. Each entry is `{person id, rating}`, sorted by rating.
2. Start at a binary search (`FUN_007ea780`), then for each entry:
   - rating window `FUN_009278c0`: roughly 0.75–1.3 × the slot requirement (0.7 / 0.5 for rule slots; ×10, ×5 or ×2 caps for cheap slots)
   - not his own club; free agents only for reason `'='`
   - position familiarity ≥ `FUN_016e6ea0(status, position)`
   - `FUN_016e69e0` (reason-specific exclusions)
   - `FUN_00c804a0` (reputation sanity, when the game's world level `FUN_0155ded0` > 4)
   - **`FUN_00603640`**: age bounds; **affiliate mode `+0xe6` rejects foreigners** (`FUN_01543dd0`, the type-0x15 test); interest and availability checks
   - score `FUN_0048e1f0` must beat the threshold `FUN_0160b380(position, …, status)`
   - **`FUN_00c109d0`**: feasibility and transfer type. Its checks:
     - asking price (`FUN_0163e8c0` clause, else vfunc `+0x28` valuation) against `slot+0x38`
     - pre-contract (`FUN_00640ad0`) and wages (`FUN_00d454a0`)
     - **join check `FUN_00b9c670`** (work permit `0xfc` → counts rule `0x6e`)
     - **rule-linked slot:** `FUN_01605ae0(slot.rule.type, player)`
     - **`+0xea`/`+0xb8` and `+0xeb`/`+0xbc` (foreign / non-EU already signed this cycle)**
     - **`+0xcc == 20` with status > 2 rejects foreigners**
3. `FUN_016e6110` creates the target record. The slot keeps the best 10 (`FUN_014e0850`); `FUN_016e5f30` trims weak ones.

**`FUN_005c85c0` → `FUN_00d65a40`**, for every candidate of every slot:
- `FUN_01558be0(club)` registers **interest**, which is visible to other clubs and in the news
- `add_target_decision` queues it

**This is all before any foreign gate.**

### (C) Decision → bid

**`TC_SHORTLIST::make_transfer_decision_for_player`** (`00517b20`, 5 callers: `FUN_00a71080`, `FUN_00c88af0`, `FUN_01f260a0`, `FUN_00db28b0` (listing prompt), `FUN_0086fdb0`). Its checks:
- slot still open; an offer in progress (`slot+0x40`) blocks
- `+0xe6` drops targets for filled slots
- **`+0xea`: if the player is foreign and `+0xb8` is set, drop; otherwise set `+0xb8 = 1`. So there's at most one foreign target in flight per cycle.** `+0xeb` does the same for non-EU.
- **005181c7: our target gate (`CHECK`, `RANK`)**, then the original EPL registration check `FUN_00f14fc0` → `FUN_005e4050` (25-man/homegrown legality, `FUN_007f85f0`)
- cost: `calculate_cost_of_transfer` ×2 (fee alone, and fee + contract). Cost > 0.9 × budget → reason 2; > `slot+0x38` → 5
- reputation gate: the buyer's reputation must be ≥ 0.9 × the player's when the world level > 4

Dispatch by type: `make_transfer_offer` (`00b7c870`) → **`FUN_00cb9e40`** builds the bid from the asking price (`FUN_00d454a0`) or compensation (`FUN_00640ad0`), capped at `slot+0x38`, then calls `add_transfer_offer`.
- free agents: `FUN_00919690` (contract offer) or `FUN_00579410` (trial)
- loans: `FUN_00cb5360`
- type 5: `FUN_01e4c5f0`
- type 0xd: `FUN_01e4c4a0`

Rejection: `TC_SHORTLIST::target_bid_rejected` (`0086d650`) clears `slot+0x40` and either retries (`FUN_01e4da90`) or removes the candidate and the interest (`FUN_01e4d1a0`, `FUN_01558e00`). `target_signs` (`00ea2890`) increments `+0xb8`/`+0xbc` for foreign or non-EU signings.

### (D) The offer lifecycle

Offer validity is **`FUN_006f69f0`** (our offer gate is at `006f6a3d`). It runs at every step:

| Caller | Stage |
|---|---|
| `FUN_00855e90` (8 callers, recursive) | offer progression and responses |
| `FUN_00f084a0` | negotiation and response handling |
| **`FUN_00daf4f0`** | **the completion queue:** entries whose date has arrived, offer state `0x13` (agreed). Valid: the move completes. Invalid: `FUN_004b8580` cancels with the reason |
| `FUN_006d5880`, `FUN_0092af60`, `FUN_006a05e0`, `FUN_00dde2a0` | status and UI queries |

With `always_open_windows`, the completion date is today + 30 (`FUN_00b9dc30`, reports/ai #2).

### Key constants (doubles, read from `original/fm.exe`)

| Constant | Value | Use |
|---|---|---|
| `022d2170` | 0.75 | rating window low; "weak holder" |
| `022d22e0` | 1.3 | rating window high |
| `022d21f8` | 0.9 | budget factor; reputation factor |
| `022d2208` | 0.95 | |
| `022d2278` | 1.05 | trim |
| `022d2190` | 0.8 | |
| `022d20d0` | 0.5 | |
| `022d2348` | **1.5** | domestic-player valuation in foreign-limited leagues, `FUN_009327d0` |
| `022d2220` | 0.98 | bid accept |
| `022d2118` | 0.6 | |
| `022d2058` | 0.4 | |
| `022d1ee8` | 0.2 | |
| `022d1fb0` | 0.3 | |
| `022d1df8` | 0.1 | |

## 3. Selling

| Path | Function | Nationality-aware? |
|---|---|---|
| Unslotted players hawked: value → 50% → 10% → free | `FUN_00809590` → `FUN_01f263b0` → `FUN_00d80870` (from `create_shortlist`) | No. Driven purely by the depth chart. |
| Per-player review: re-rates status, lists (`FUN_0089bbf0`), sets the reason (`FUN_01e751e0`) | `FUN_006296b0` (from `FUN_00e723b0`); our surplus cave is at its entry | Only our cave |
| Bid evaluation | `FUN_01f325f0`: accept at ≥ 98% of the valuation (or within £1000); counter at ≥ valuation × status factor (0.6/0.5/0.4; listed 0.4/0.2/0.1); "not for sale" `0x200` at the £200m sentinel | No |
| Valuation | `FUN_009efc80`: contract days left (`FUN_015c0cb0`) → `FUN_0163e4f0`; status factors; **`FUN_009327d0`**: if the *seller's* shortlist has `+0xea` and the player is **domestic** with status < 4, ×1.5 (cap £200m) | **Yes, dormant:** only when `+0xea` is set |
| Weak-player release | `FUN_00f32700` (from `FUN_01f08430`) | No |

**Why City sold Milner** (inference; the in-game transfer record wasn't read):
- City's depth chart ranks own players only by position rating, so roughly 40 foreigners (all still eligible, listed or not) took the slots ahead of him.
- An unslotted Milner is hawked by `FUN_01f263b0` at falling prices.
- His contract ran to 30 Jun 2015, so the valuation (days left → `FUN_0163e4f0`) was low, and so was the bid evaluation's accept line.
- Nothing in the chain knows that City field at most 3 non-assimilated foreigners.
- `FUN_009327d0`'s ×1.5 "keep your domestic players" rule exists exactly for this case, but it is gated on `+0xea`, which is 0 because the shortlist's rule list has no 3+2 rule.
- **Alternative (if he left after 30 June):** a pre-contract with compensation, which `nostalgia_compensation_any_age` allows. The player decides that, not City. `squad_snapshot.py` on his new club shows his contract's joined date (`+0x28`) and settles it.

**Where "don't sell domestic players when short" fits:**
- **(a)** Keep domestic players in the depth chart. R1 does this by taking surplus foreigners *out* of it.
- **(b)** Set `+0xea` (×1.5 valuation of domestic key, first-team and rotation players).
- **(c)** For a hard rule, in the `FUN_006296b0` cave, skip listing domestic first-teamers of short clubs. In `FUN_01f325f0`, return "not for sale" (`FUN_008fad90(offer, 0x200, …)`) for them.

## 4. Match selection vs planning

- **Match selection is fine.** The AI selector (`FUN_00852050` → `FUN_00f8c270` constraints, `SQUAD_SELECTOR::select_squad_of_players`) gets 3+2 from fixture lists; the earlier trace shows `AI selector rules: 0x4<=5, 0x4[non-assimilated]<=3`.
- **Planning never sees match eligibility.**
  - The only rule input to planning is the shortlist's `+0x18` list. It is built **without a fixture** (`FUN_01062190(team, list, 0, 1, 1, 0)` at `0082989a`/`00829942`), so the 3+2 injection (fixture lists only) never reaches it.
  - The EPL registration checks (`FUN_00f14fc0` / `FUN_005e4050`, `FUN_006f5f60`) are about the 25-man registered squad, not match squads.
- In vanilla leagues with a data foreign rule (e.g. Russia), `+0xea` is set and the levers in section 2 operate.

## 5. "Pull out at the last minute": which gate fires where

| Stage | What the human sees | Gate that applies |
|---|---|---|
| Candidate + interest + speculation (B, `FUN_00d65a40`, `generate_transfer_speculation`) | "X are interested in Y", rumours | **None.** Foreign candidates are generated and advertised. |
| Decision (C) | nothing, or a bid | **Our target gate** `005181c7` drops the target (`remove_target`, reason `0xb`). The slot is refilled from the same pool on the next mode-3 pass, mostly with foreigners again, so the cycle repeats. |
| Offer processing (D, `FUN_00855e90` / `FUN_00f084a0`) | bid, then "talks" | **Our offer gate**, every time |
| Completion (`FUN_00daf4f0`, about 30 days after agreement) | "deal collapsed" | **Our offer gate again**, reason `0x29` |

**Why a deal that passed the decision gate fails later:**
1. **Ctx mismatch (likely bug).**
   - The offer gate calls `CHECK(ctx, …)` with the validity function's `ctx`, which may be the offer's **destination team** (`FUN_00d9fc00`).
   - `CHECK` counts domestic players of *that* team. For an U21 or U18 destination the count is far below 15, so any foreigner is blocked.
   - The decision gate counts the first team. Foreign youngsters (status 5/6 slots) therefore pass the decision and die later.
2. **The state changes in the 30 days before completion.**
   - Other foreigners arrive. Each bid passed the "top-5" ranking alone, and there's no reservation of pending signings, because `CHECK` counts only current players.
   - A domestic first-teamer leaves (Milner) and the club turns "short", which kills every pending foreign deal at once.
3. **Routes outside `make_transfer_decision_for_player`** (`FUN_00cb9e40`'s other callers, contract offers) are caught only by the offer gate.

**To confirm in game:**
- Run `python reports/transfer_ai/trace_plan.py reports/transfer_ai/trace_live.txt 30` while the game advances.
- `valid from FUN_00daf4f0 … our-gate BLOCK` lines are completion-day kills; `valid from FUN_00855e90/FUN_00f084a0` are mid-negotiation kills.
- `OFFER KILLED (0x29) … <team> -> <player>` events name the team. An "Under 21s" or "Under 18s" team name confirms point 1.
- `decide F -> … our-gate BLOCK` counts decision-time drops. `cand: candidate added F/D` shows how foreign the candidate stream is.
- `pool: nation-restricted = yes/no` should be almost all "no" today.

## 6. Recommendations

### R1: switch on the game's own levers for short clubs (most robust, low to medium effort)

**Hooks:**

| # | Site | Change | Effect |
|---|---|---|---|
| R1a | `00829a37` in `FUN_00829760`, at its tail after `+0xea`/`+0xeb` are computed: `88 87 eb 00 00 00` (`mov [edi+0xeb],al`) → `jmp cave` + nop | Redo the store. If the club is AI (`FUN_0158a9e0(team, 1)` = 0), count its first team's domestic players once (vfuncs `+0x2bc`/`+0x16c` skips, `FUN_015440e0`, like `CHECK`). If fewer than `DOMESTIC_MIN`, set `byte [edi+0xcc] = 20`. Club = `[esp+0x38]` at that point. Return through `00829a3d`. | Nation-only candidate pools for every slot (`FUN_016e6d20`), and foreign candidates rejected for rotation, backup and youth slots (`FUN_00c109d0`, `FUN_0072e950`, `FUN_00579f40`). Reset on every rebuild (`FUN_00815530` reloads `+0xcc`), so it tracks the count. |
| R1b | `00829a20`: `e8 4b 15 76 00` (`call FUN_00f8af70`) → `b0 01 90 90 90` (`mov al,1`), or only when short (inside the R1a cave) | `+0xea = 1` | At most one foreign target in flight per cycle (`make_transfer_decision` and `target_signs`). **Domestic key, first-team and rotation players valued ×1.5** (`FUN_009327d0`), which protects Milners. Slot-requirement tweak (`FUN_009c0290`). |
| R1c | `FUN_009ed420` entry `51 55 56 8b 74 24 10` → `jmp cave` + 2 nops | If the player's contract (person vfunc `+0x1d8`) is listed (`+0x32` bit 0), at status 7, and foreign to `param_5` (team), return 0 (`xor al,al ; ret 0x14`) | Surplus foreigners leave the depth chart, which opens slots, so the club gets needs. With R1a those needs are filled from the domestic pool. Unslotted surplus players are also hawked by `FUN_01f263b0`, which speeds up their sale. |

**Why it's robust:**
- It reuses code paths the game already runs for foreign-limited leagues and affiliate clubs.
- The domestic pool is keyed by nationality, so candidates are domestic by construction, before interest or rumours are generated.
- The target and offer gates stay as backstops.

**Risks:**
- `+0xcc` is a staff attribute copy. It is read in a few more AI places (`FUN_0048e1f0` uses `+0xcf`, not `+0xcc`; target record `+0x26`), so verify there's no other use of `+0xcc == 20`.
- Nation-only pools are smaller, so some slots stay empty when a nation is thin. The game handles empty results with its reason `':'` retry.
- Wage budget: `+0xa4` still counts surplus foreigners' wages, so poor clubs may not afford replacements until the surplus leave.
- Wales/Scotland players count as domestic in England (type-0x15 test) but aren't in the English pool.
- R1c changes vanilla behaviour for listed foreign "Not Needed" players everywhere. In vanilla those are leaving anyway.

**CPU:**
- R1a: one first-team scan (about 25–35 `IS_FOREIGN` calls) per club per rebuild, which happens every ≥ 6 days.
- R1c: one vcall and two byte reads per eligibility test. The extra `IS_FOREIGN` runs only for listed status-7 players.
- No per-candidate or per-day cost.

**Cave space:** about 100 bytes for R1a and 40 for R1c. Free fragments in the nostalgia set:
- `020c1aaa`–`020c1c00` (342 bytes, inside bosman's range; coordinate)
- `020c17ee`–`020c1840` (82)
- `020c1fb8`–`020c2000` (72)
- `020c170c`–`020c1740` (52)

### R3: fix the offer gate (low effort; do it with R1 or R2)

- **Ctx.** In `ai_offer_cave`, replace `ctx` with the club's first team (`[[ctx+0x10]+0x10][0]`, the same expression the AI cave uses) before `CHECK`.
- **Don't re-litigate agreed deals.** Skip the gate when the offer is already agreed (offer byte `+0x28` == `0x13`, the state `FUN_00daf4f0` checks), or apply it only before agreement. Keeping the decision gate plus a creation-time check removes the completion-day collapses.
- **Optional: reserve pending signings.** Add agreed incoming foreigners to `CHECK`'s count. This needs a walk of the club's offers, so it's more cost; alternatively, R1b's `+0xb8` "one at a time" rule already serialises foreign buys.

**Risk:** a foreigner agreed while the club wasn't short still arrives after it turns short. That's acceptable, because the surplus ladder lists the weakest foreigner later.

### R2: precise candidate filter (most precise, highest effort)

- At `006f4706` (`call FUN_016e6110`, adding a candidate in `FUN_006f4290`) and in the free-agent and loan builders, drop a foreign candidate unless the club has the domestic minimum and he'd rank top-`KEEP` by value.
- No interest or rumours are generated for unusable foreigners, and the slot keeps searching.

**Cost:** it needs per-club numbers (domestic count, `KEEP`-th foreign value) per pass, cached.
- `.text` caves are read-only at runtime (`Memory.patchCode`).
- `.data` has no safe slack.
- So the loader would need to allocate an RW page and patch its address into the caves (a new loader feature), or compute once at `FUN_00b86c00` entry into a verified-unused shortlist field.
- Per candidate: one `IS_FOREIGN` plus a compare.

**Risk:** more code. Rank R2 below R1 unless R1's nation-only pools prove too thin.

### What not to do

- Don't hook `FUN_016e6d20` or `FUN_00603640` with a live domestic count. They run per slot or per candidate, which multiplies the cost by about 40 slots × pool size per pass.
- Don't inject 3+2 into the shortlist's `+0x18` list as a type-`0x04` rule just to get `+0xea`. That list also feeds rule-linked slots and the EPL counters. R1b gets the same flag without touching rule lists.

## 7. Function table

| Address | Name / role |
|---|---|
| `00e175f0` | per-club daily transfer AI driver (club + affiliates) |
| `00a71080` | decision pass: cadence, speculation, `make_transfer_decision` for queued decisions |
| `014be080` | rebuild-or-refill dispatcher (about 25 event callers) |
| `00f5a1d0` | planning run: mode 1 full, 2 rebuild, 3 refill candidates |
| `00471cf0` | shortlist reset and setup (`+0xc4`, `+0xe6`, `+0xb0`) |
| `016e3f70` | shortlist reset (`+0xb8`/`+0xbc` = 0, attributes = 10) |
| `00815530` | transfer staff attributes → `+0xcc..+0xdd` |
| `00829760` | rule list `+0x18`, `+0xde`, **`+0xea`/`+0xeb`** |
| `00f8af70` / `00f8b120` | "list has a foreign / non-EU limit" |
| `0073d650` | `TC_SHORTLIST::create_shortlist` |
| `01e4bdc0` | slot creation (calls `00a636b0` rule-linked slots) |
| `009c0290` | slot required ratings |
| `0050cb80` / `00f51fc0` | depth chart / `select_player_for_this_slot` |
| `009ed420` | own-player eligibility for a slot |
| `00809590` → `01f263b0` | hawk unslotted players (value, 50%, 10%, free) |
| `00b86c00` | candidate refill per slot |
| `016e6d20` | nation-only pool switch |
| `00916560` / `00c0ebc0` | position pool / nationality pool; built in `00de3d60` |
| `006f4290` | candidate generator |
| `009278c0` | rating window |
| `00603640` | candidate checks (affiliate domestic-only `+0xe6`) |
| `00c109d0` | feasibility and transfer type (`+0xea`/`+0xb8`, `+0xcc==20`, join check, rule slots) |
| `0048e1f0` / `0160b380` | score / threshold |
| `016e6110` | target record |
| `00d65a40` | interest (`01558be0`) + `add_target_decision` |
| `006acd10` | `generate_transfer_speculation` |
| `00517b20` | `make_transfer_decision_for_player` (our gate at `005181c7`) |
| `00f14fc0` → `005e4050` | EPL registration check |
| `0095cfe0` | `calculate_cost_of_transfer` |
| `00b7c870` → `00cb9e40` | `make_transfer_offer` → bid |
| `00919690` / `00579410` | contract offer / trial |
| `0086d650` / `00ea2890` | `target_bid_rejected` / `target_signs` |
| `006f69f0` | offer validity (our offer gate at `006f6a3d`) |
| `00daf4f0` | completion queue |
| `004b8580` | cancel offer with reason |
| `01f325f0` / `009efc80` / `009327d0` | bid evaluation / valuation / domestic ×1.5 |
| `006296b0` / `0089bbf0` / `00e5f250` | squad review / listing |

## Files (raw dumps, gitignored)

| File | Contents |
|---|---|
| `tree1.c`, `tree2.c` | shortlist subsystem and depth-1 callees, with call outlines |
| `callers1.c`, `callers2.c`, `callers3.c`, `drivers.c` | callers: decision drivers, `FUN_00cb9e40`, offer validity, pools |
| `policy.c`, `rules_q.c`, `attrs.c`, `ea_users.c` | `+0xea`/`+0xeb`/`+0xcc` setters and readers, scoring |
| `slots.c`, `surplus_plan.c`, `pools.c` | slot builders, eligibility, hawking, player pools |
| `stores_ea.txt`, `access_ea.txt`, `access_b8.txt`, `access_e6.txt` | member access scans (`PlanMemberStores.java`) |
| `asm1.txt`–`asm3.txt` | disassembly of hook sites (`PlanDisasm.java`) |
| `sources.txt` | debug-asserting functions per source file (`PlanSourceFiles.java`) |
| `trace_plan.py` / `trace_plan.js` | read-only pipeline tracer (sections 5, 8.5) |
| `probe_shortlist.py` / `.js` | read-only one-shot survey of shortlist flags (section 8.1) |
| `verify.py`, `verify.txt`, `site_refs.txt`, `zero_runs*.txt` | patch verification (section 8.4) |

Ghidra scripts added: `PlanSourceFiles.java`, `PlanDecompileTree.java`, `PlanMemberStores.java`, `PlanDisasm.java`, `PlanRangeRefs.java`.

## 8. Implementation (R1 + R3)

### 8.1 What turned out to be native

Survey taken with `probe_shortlist.py` (read-only, main thread), on 2 Mar 2015 in the user's new career, with 760 AI shortlists.

| Item | Finding |
|---|---|
| Does the planner's rule copy (`+0x18`) see the stored 0x04 rules? | **Yes, by construction.** `FUN_00829760` calls `FUN_01062190(team, +0x18, fixture 0, 1, p6 = 1, 0)`. With no fixture and `p6 = 1`, that function keeps every rule except types 0x7e/0xa7 (it erases match-day types only when a fixture is given, or when `p6 = 0`). `FUN_00f8af70(3)` then finds type 0x04, a foreign type (`FUN_00f8a050`) with no age bound (`FUN_00f8a8a0` default branch returns 0), so `+0xea = 1`. |
| `+0xea` in game | **730 of 760** AI shortlists have `+0xea = 1`. The other 30 are competitions without a rule group, or clubs not rebuilt since. R1 forces it for those. |
| Native consequences now active | **`make_transfer_decision` (`005186b3`):** while `+0xb8` (foreign signings since the last rebuild, `target_signs` `00ea2bc2`) is non-zero, every foreign target is dropped; otherwise the first one reserves the slot. Observed `+0xb8` was 4–18 at EPL clubs, so after one foreign signing, those clubs buy no more foreigners until the next rebuild.<br>**Domestic valuation ×1.5** (`FUN_009327d0`) for AI sellers' domestic key, first-team and rotation players: this is the selling-side guard, and it is native.<br>**Stricter foreign candidates** (`FUN_00c109d0`). |
| Minimum-rule slots | **Not triggered.** `FUN_00a636b0` only builds rule-linked slots for rules whose compare byte (`+0xe`) is 1 or 2 (`FUN_00f8a840`, minimums). The 3+2 rules are maxima (`0xff`). Rule-linked slots seen in game: types `0x92`, `0x26`, `0x27`, `0xd4` (data homegrown rules) only. `FUN_00f8be70` only looks for `0x92`/`0x26`. |
| `+0xcc` | Staff attribute #1, from `FUN_00815530` (DoF, else manager). Natively 20 for very few clubs. The exe has only **4** compares of `+0xcc` with 20, all domestic-recruitment logic: `FUN_016e6d20` (nation pool), `FUN_00c109d0`, `FUN_0072e950`, `FUN_00579f40` (refuse foreigners for status > 2). The other shortlist reads copy it into target records (`FUN_016e6110`, `FUN_00934030` → `+0x26`). The remaining 170 `+0xcc` reads in the exe are on other object types. |

**Baseline trace.** `trace_baseline.txt`: 20 minutes of holiday, Mar to Oct 2015, running the old patch set without these changes.
- **Rebuilds:**
  - **2665 of 6017 rebuilds left `+0xea = 0`** (44%), so forcing it matters.
  - `+0xcc = 20` occurred natively 15 times (e.g. Athletic Club's Basque policy).
- **Decisions:** 11885 foreign targets blocked by our target gate.
- **Offer gate:** 214 blocks out of about 7500 checks.
  - Almost all were **pre-agreement loan offers (kind 3)** at state `0x8` (`FUN_00dde2a0`) and `0xb` (`FUN_00855e90`). Those are not "last minute".
  - **State `0x13` confirmed:** 46 checks came from the completion queue `FUN_00daf4f0`, all at state 0x13, and **1 of them was killed (0x29) on completion day**. R3 removes that case.
- **Note on the sale counter:** the tracer's `DOMESTIC SOLD by short club` also fires for natively-20 clubs.

### 8.2 `nostalgia_ai_domestic_planning`

New module `patcher/patches_transfer_ai.py`.

| Part | Site (original bytes) | Cave | What it does |
|---|---|---|---|
| Planning flags | `00829a37` `88 87 eb 00 00 00` (`mov [edi+0xeb],al`, the tail of `FUN_00829760`, which runs on every shortlist rebuild) → `jmp` + nop | `02047a00`–`02047ac2` (195 bytes; club from EBX, see section 9) | Redoes the store. For AI clubs (first team, `FUN_0158a9e0(team, 1) = 0`, club teams only), sets `+0xea = 1` and counts the first team's domestic players. It skips the same players `CHECK` skips (person vfunc `+0x2bc`, player vfunc `+0x16c(0,0)`) and uses the type-0x15 test `FUN_015440e0`. If the count is below `DOMESTIC_MIN` (15), it sets `+0xcc = 20`. |
| Depth chart | `009ed420` `51 55 56 8b 74 24 10` (`FUN_009ed420` entry: own-player eligibility for a slot; args player, slot, ?, **team**, ?; `ret 0x14`) → `jmp` + 2 nops | `02047b00`–`02047b65` (102 bytes) | A player whose contract (person vfunc `+0x1d8`) is transfer-listed (`+0x32` bit 0) **and** "Not Needed" (`+0x30 == 7`) **and** foreign to the team is not eligible (returns 0). This is cheap: one vcall and two byte reads per test, plus `IS_FOREIGN` only for listed status-7 players. |

**Switching back.** On every rebuild, `FUN_00471cf0` runs `FUN_016e3f70` (resets `+0xcc..` to 10) and then `FUN_00815530` (reloads the staff attribute) before `FUN_00829760`. A club that is no longer short gets its own value back at its next rebuild.

**Cave choice.** The foreign-cap cave ranges are full. The new caves sit in a 1074-byte zero run at `02047956`–`02047d87` in `.text`'s raw data, so they are `"offset"` entries whose original bytes are zero. The run is the body of a function moved to `helper.dll`:
- Its stub at `02047950` is `jmp [0x0246b858]`, and `0x0246b858` points into `helper.dll` at runtime. The neighbouring stubs `0x0246b844`, `0x0246b4f4`, `0x0246b63c` and `0x0246b200` all point into `helper.dll` too.
- Ghidra finds no references, instructions or data in the run, and no reference to the stub.
- A byte scan of the exe found no pointer-sized value or rel32 branch that is a real reference into it. The byte-pattern hits are misaligned immediates.
- The run is still all zero in the running game after hours of play.

There are no `0xCC` runs of 16 bytes or more in `.text`. The checksum shield already hashes a pristine `.text`.

**Risk:** if `helper.dll` ever restored a stolen body there, it would overwrite the caves. Nothing suggests it does (the stub isn't referenced).

### 8.3 R3: offer gate fix

In `patches_foreign_cap.py`, `ai_offer_cave`, part of `nostalgia_foreign_cap_ai`. The cave is at `020c1790`–`020c1810` (129 bytes); it now runs into `JOIN_CAVE`, which belongs only to `nostalgia_foreign_cap`, a patch that can't be combined with `_ai`. The assert was adjusted accordingly.
- **Agreed deals are no longer re-checked.** An offer with state `+0x28 == 0x13` passes straight through. 0x13 is the state the completion queue `FUN_00daf4f0` executes, and the state for which `FUN_006f69f0` itself skips its other pre-agreement checks.
  - States seen in game so far: `0x8` (`FUN_00dde2a0`), `0xb` and `0xd` (`FUN_00855e90` / `FUN_00f084a0`).
  - **Confirmed in game:** the completion queue only checks offers in state 0x13 (baseline trace).
- **The checker now gets the buying club's first team.** The cave computes `[[[ctx+0x10]+0x10]]` (team → club → first team) instead of the destination team `ctx`, and only for club teams (`ctx+0x23 == 0`). The human check uses the same first team.

The selling-side guard is native (×1.5, section 8.1). With R1's depth-chart change, domestic players keep their slots, so they are no longer hawked as unslotted. No extra patch was added; the tracer counts `DOMESTIC SOLD by short club`.

### 8.4 Verification

- `verify.py` → `verify.txt`:
  - original bytes of every `NOSTALGIA` patch plus `nostalgia_ai_domestic_planning` match `original/fm.exe`
  - no byte overlaps, using the loader's rule
  - capstone listings of all changed sites and caves, with branch targets
  - **0 problems**
- No branch in the exe lands inside the patched sites (`site_refs.txt`, Ghidra).
- **Names to add to `patch.py` `NOSTALGIA`:** `nostalgia_ai_domestic_planning`. The R3 fix is already part of `nostalgia_foreign_cap_ai`.

### 8.5 Tracer

`trace_plan.py <out> <minutes>`, read-only. New lines:

| Line | Meaning |
|---|---|
| `rebuild: +0xea=… +0xcc=…` | Planning flags after each rebuild. Events `SHORT (domestic planning on): <club>` and `no longer short: <club>`. |
| `cand: candidate added F/D by short club / normal club` | Candidates by nationality. Short clubs should show almost only `D`. |
| `pool: nation-restricted = yes/no (+0xcc 20/other)` | Pool switch. |
| `depth chart: listed Not Needed foreigner left out of a slot` | Exclusions. |
| `valid from <caller> … state 0x.. -> result reason our-gate …` | Offer checks. With R3, there should be no `our-gate BLOCK` at `state 0x13`, and no `OFFER KILLED` events from `FUN_00daf4f0`. |
| `sale by AI SHORT/normal club: player D/F` | Sales, with the event `DOMESTIC SOLD by short club`. |

`probe_shortlist.py <out> "<club>" …` is a one-shot survey: per-club flags, domestic first-teamers, and depth-chart holders by nationality.

### 8.6 Test steps

1. Add `nostalgia_ai_domestic_planning` to `NOSTALGIA`, restart through the launcher, and run `python tools/track_mods.py 5` (or check the loader output: all patched).
2. Run `python reports/transfer_ai/probe_shortlist.py reports/transfer_ai/probe_before.txt "Manchester City" "Chelsea" "Arsenal"`. Holiday a few weeks, then run it again (`probe_after.txt`):
   - Every AI club should have `+0xea 1`.
   - Clubs with domestic below 15 should have `+0xcc 20` after their next rebuild.
   - Their slot holders should turn domestic, or empty.
3. Run `python reports/transfer_ai/trace_plan.py reports/transfer_ai/trace_after.txt 30` while holidaying:
   - `rebuild: … +0xcc=20` and `SHORT` events for short clubs.
   - Short clubs' `cand` lines mostly `D`.
   - `depth chart: … left out` > 0.
   - No `OFFER KILLED … state 0x13`.
   - `DOMESTIC SOLD by short club` rare.
4. Run `python tools/squad_snapshot.py reports/foreign_cap "Manchester City" "Chelsea" "Arsenal"` at the start, after about 4 weeks and at the end of the window:
   - Short clubs' first-team domestic count should rise.
   - `foreigners who joined since` should stay empty for them.
   - Listed surplus foreigners shouldn't hold first-team slots. A smaller first team is fine.
5. Your own club: bids for foreigners are unaffected (human buyers are skipped by every part).

## 9. Crash audit (30 Oct, career creation)

### Crash 2 (17:07, no tracers): the plan cave read the club from a recycled argument slot

- **Faulting instruction:** `02047a1f mov ebx,[ecx]` with `ecx = [club+0x10] = 0`. The "club" came from `[esp+0x58]` after pushad, which is the argument slot `[esp+0x38]` and held `0x3513d800`. At the same moment `EBX = 0x3513d840`.
- **Root cause:** `FUN_00829760` reuses its argument slot as a local. At `008299b1` it runs `mov byte [esp+0x40],cl`, which overwrites the low byte with a flag. By the tail, the slot holds `club & ~0xff`, which points 0x40 bytes before the club object, so its "+0x10/+0x14 vector" is garbage.
  - This is not specific to career creation. It hits any club whose pointer doesn't end in `00`. It showed up then because career creation builds every club's shortlist.
  - My earlier static check was wrong: it only looked at the prologue.
- **Fix:** take the club from **EBX**.
  - EBX is loaded from the argument at `00829774`.
  - It's used as a scratch register only inside the rule loop (`0082995e`–`00829992`) and reloaded from the argument at `00829994`.
  - The paths that skip the loop (`00829949`/`0082995c`) leave EBX unchanged.
  - That reload happens before the slot is overwritten at `008299b1`, and the game itself passes EBX as the club at `008299c4`, `008299fb`, `00829a04` and `00829a13`.
  - The coordinator's sanity check (non-null begin, 1–63 teams) stays as a second line. The cave is now 195 bytes and still ends before `ELIGIBLE_CAVE`.
- **`eligible_cave` checked the same way:** it runs at `FUN_009ed420`'s entry, so the arguments are intact.
  - Both callers (`0085a45a`, `01e4cc1b`) pass player, slot, ?, team, ?.
  - The function itself uses argument 4 as a team (`FUN_0158f450` at `009ed468`).
  - The cave tests player and team for null, and the team for `+0x23 == 0`.

### Crash 1 (16:56, `trace_foreign_cap.js` hooked `015c8926`): Frida, not the status cave

- **What the dump shows:**
  - The listener `FUN_008dd520` read its third argument (club) as `0x02751c0f`. The re-rater (`00b599be`) had passed 0 (`[0x1afb24] = 0`).
  - That argument was pushed by the setter's first instruction (`push [esp+8]`, replayed by the status cave), at `0x1afb18`.
  - `0x015c8926` sits stale at `0x1afae8`, which is the Gum invocation frame of the hook at that address.
- **Mechanism:** a Frida `{onEnter/onLeave}` *object* listener treats its address as a function entry. When it traps the return, it writes its leave trampoline over `[esp]`.
  - At `015c8926`, `[esp]` isn't a return address. It's the club argument the setter just pushed.
  - The listener therefore received a trampoline address as the club and crashed in `FUN_0149f3e0`. `0x02751c0f` lies in no module, which fits Frida-allocated code.
- **The status cave itself is clean:**
  - Its hook path is balanced: `push ecx` twice, cdecl call, `add esp,4`, `pop ecx`; `KEPT` is called as cdecl with `add esp,4`.
  - It reads only `[esp+4]`/`[esp+8]` at the entry, and the replay is byte-identical.
  - The game doesn't read EAX/EDX at the entry, since the setter sets EDX itself.
  - Without Frida, the pushed club is the caller's.
- **Confidence: high** that the hook at `015c8926` explains the crash, and that the cave can't produce it.
- **The same hazard was still in tracers:** `trace_foreign_cap.js` hooked `006296b6` (inside `FUN_006296b0`, where `[esp]` is the saved ESI) and `01062196` (inside `FUN_01062190`, with an `onLeave`). My `trace_plan.js` hooked the depth-chart cave exit. **All three now use Frida's probe form** (a plain function, no return trap). The fixture-list `onLeave` moved to a hook at `FUN_01062190`'s entry. The other hooks in `tools/*.js` and here are on function entries.
  - **Rule:** never pass an object listener to `Interceptor.attach` at a mid-function address.

### Other caves reached during career creation

| Cave | Inputs | Verdict |
|---|---|---|
| 3+2 store, `FUN_01062190` entry | ECX = group, arg 1 = team (entry, intact) | The team is tested for null and `+0x23`. The group list is read the way the game's own copy reads it (a vector `{begin, end}`; an empty list has begin = end). It builds a fresh vector rather than editing in place. OK. |
| 3+2 counter, `01606539` (mid-function) | `[ebp+4]` return, `[ebp+8]` type, `[ebp+0x28]` rule ref | `FUN_01605ae0` never writes `[ebp+4]`, `[ebp+8]`, `[ebp+0xc]` or `[ebp+0x28]` (full scan of the function). OK. |
| Status hook / `IS_SURPLUS` | ECX = contract; contract `+0x32`, `+0x8` team, `+0x4` person | Runs only for status 1–6 and listed contracts. It tests the team for null, `+0x23` and `+0x10`, and the person and player for null. OK. |
| Surplus cave, `FUN_006296b0` entry | `[ecx]` = club (as the game reads it), arguments intact | OK. |
| AI target cave, `005181c7` (mid-function) | registers EBX = club, EDI = player, EBP = shortlist, the same ones the game uses there (`00518692`–`005186a4`) | No stack-argument reads. OK. |
| Offer cave, `006f6a3d` (mid-function) | EBX = offer (`006f6a0a`), ESI = person (`006f6a17`), EDI = reason; `[esp+0x2c]` replays the game's own read | The arguments haven't been rewritten before `006f6a3d`. The new code tests `ctx+0x23` and every pointer it follows. OK. |
| `CHECK` | ctx = a club's team (`+0x23`, `+0x10` tested), player | Its callers now always pass a first team. OK. |

`verify.py` after the fix reports **0 problems**: original bytes, overlaps across NOSTALGIA plus `nostalgia_ai_domestic_planning`, and capstone listings.

## 10. Stripped-back set (current)

This follows [native_mode.md](native_mode.md). The current NOSTALGIA list:

```
always_open_windows, nostalgia_compensation_any_age, nostalgia_retain_on_expiry,
nostalgia_3_foreigners, nostalgia_3_foreigners_ui, nostalgia_foreign_cap_ai,
nostalgia_ai_plan_without_surplus
```

| Piece | Site → cave | Notes |
|---|---|---|
| Stored rule `{0x04 ≤ 3}` | `01062190` → `020c18d0` (207 bytes) + `020c1f80` (ADDRULE) | Any existing type-0x04 maximum ≤ 3 counts as done. Otherwise the first larger maximum is tightened to 3, or the rule is added. |
| Rules screen | `010642b2` → `020c1840` (93 bytes) | One display line. |
| Surplus test `CHECK` | `020c1e00` (355 bytes) | Senior (21+) foreigner outside the club's best 3 by current ability. |
| Surplus ladder | `006296b0` → `020c1c00` (499 bytes) | As before. On the "not surplus" path it calls `UNLIST_JUNIOR`. |
| `UNLIST_JUNIOR` | `020c16c8` (98 bytes) | An under-21 foreigner who is transfer- and loan-listed and "Not Needed" gets unlisted. Its tracer hook point follows the `UNLS` marker. |
| Status hook / `IS_SURPLUS` | `015c8920` → `020c1600` | Unchanged code; it calls the new test. |
| Anti-churn gate | `005181c7` → `02047960` (522 bytes, zero-run cave, `"offset"` entries with zero originals) | Registers at the site: EBX = club, EDI = target player, EBP = shortlist. Type checks: the club's first team must be a club team whose `+0x10` is EBX. Its tracer hook point follows the `CHRN` marker. |
| Depth-chart exclusion | `009ed420` → `02047b80` (61 bytes) | Listed "Not Needed" players are not eligible for slots. This is the coordinator's safe form, with no team argument. |

**Removed:** the offer gate (`006f6a3d`), the value-ranked target gate, `DOMESTIC_MIN`, `+0xcc = 20`, the forced `+0xea` (`00829a37`), and the 3+2 counter (`01606539`).

**Safety:**
- every cave reads registers or freshly pushed arguments only
- every vector is null-checked, and every team is type-checked (`+0x23 == 0`, `+0x10` non-null or equal to the club)
- tracers use object listeners only on function entries and `call` targets (the `CHRN`/`UNLS` sinks), and probe form inside the depth-chart cave

**CPU:** one squad walk per surplus test (per squad review and status write of a listed player, as before), and one per **foreign** target decision (anti-churn). Domestic targets cost nothing extra.

**Verification:** `verify.py` reports 0 problems: original bytes, overlaps across the list above, capstone listings, and every branch target internal or a known game function.

**Tracers:**
- `trace_plan.py`:
  - `anti-churn: foreign target DROPPED/allowed (reason)`
  - `surplus: listed for sale+loan, age …`
  - `unlisted an under-21 foreigner` (with events)
  - `NATIVE +0xea = 0: <club> | competition …` events (clubs with no rule set)
  - `rebuild: +0xea=…`
- `trace_foreign_cap.py`: surplus tests, by caller.
- `tools/squad_snapshot.py`:
  - CA per player
  - senior foreign rank by CA (`#n keep` / `SURPLUS` / `junior`)
  - the best 3
  - the last senior foreign arrival, and whether anti-churn would drop foreign targets

## 11. Dec 2014 follow-up (implemented)

Background: [investigation_dec2014.md](investigation_dec2014.md). All of these are in `nostalgia_foreign_cap_ai`; there are no new patch names.

| Change | Sites → caves | What |
|---|---|---|
| Shared anti-churn evaluation | `CHURN_EVAL` `02047960` (433 bytes, zero run) | cdecl `(club)` returns 0 (n/a: human club, bad object), 1 (drop), 2 (allow: fewer than 3 senior foreigners), 3 (allow: none joined within 365 days). It type-checks the club: first team is a club team whose `+0x10` is the club. |
| Decision gate | `005181c7` → `020c1740` (147 bytes) | As before, now calling `CHURN_EVAL`. `SINK(result)` follows the `CHRN` marker. |
| **Route gate** (issue 3, option A) | the two `call add_transfer_offer` sites of `FUN_0094b700` (`0094bf45`, `0094b78f`) → `02047c60` (203 bytes) | The "offer a listed or unslotted player to interested clubs" route (`FUN_01f33610`). For an AI buyer (offer `+8`, a club team; type-checked) and a player foreign to it, no offer is created (returns −1; both callers free the offer and go on) when the buyer's shortlist has the native brake on (`+0xea` and `+0xb8 > 0`) or `CHURN_EVAL == 1`. Human buyers and domestic players are untouched. `SINK(reason)` follows `ROUT`. |
| **Candidate filter** (issue 1, option B) | `006f4706` (`FUN_006f4290` adds a purchase candidate through `FUN_016e6110`) → `02047bc0` (147 bytes) | A candidate foreign to the club (the game's type-0x15 test, so Welsh, Scots and long-servers count as domestic in England) is not added when the native brake is on or `CHURN_EVAL == 1`. Such a target would be dropped at the decision anyway, and not adding him also avoids registering interest, which feeds the route above. `SINK(reason)` follows `CAND`. |
| **Domestic price factor** (issue 1, option A) | `FUN_009327d0`'s `mulsd xmm0,[0x022d2348]` operand at `009328c4` → `02047d78` (a double) | Native foreign-limited mode prices AI sellers' domestic key, first-team and rotation players at **`DOMESTIC_PRICE_FACTOR` = 1.2** (vanilla 1.5). The shared 1.5 constant elsewhere is untouched. |

**On option B's "nation-only pool":**
- Not used. The game's per-nation pools (`FUN_00c0ebc0`, built in `FUN_00de3d60`) are keyed by the player's own nationalities. An English club's pool therefore holds English nationals only: no Welsh, Scots, Irish or long-serving players.
- The global pool already contains every English player in the same rating window, so the nation pool adds no supply. It only removes foreigners.
- The candidate filter above does that with the game's own definition of domestic, on the global pool. So "domestic" means the game's test.

**CPU:** one `CHURN_EVAL` squad walk per *foreign* candidate that survives every other check (a few hundred per game week worldwide), per routed foreign offer, and per foreign target decision. Domestic candidates cost one `IS_FOREIGN`. No per-club state, so no loader feature is needed.

**Verification:** `verify.py` reports 0 problems (bytes, overlaps across the NOSTALGIA list, capstone, all branch targets internal or known). `site_refs2.txt` shows no branch into the patched call sites.

**Tracer** (`trace_plan.py`):
- `route gate: … NOT created (reason)`
- `candidate filter: … NOT added (reason)`
- `cand: EPL/other candidate added D/F`
- `anti-churn: …`
- decisions by nationality
- `RELEASE (contract ended, paid) by <caller>` against `release cost worked out by <caller>`

### Early terminations (item 4, read-only)

- **What the counter measures:** the "release payout (club ends a contract early)" line of `observe_nostalgia`/`sample_monthly` counts calls to `FUN_0047ca40`, the *cost calculator*, not payments.
- **Its callers:**
  - the AI's weak-player release batch evaluating each candidate (`FUN_00f32700`, from `FUN_01f08430`; the candidates it keeps are then released with `FUN_00ebf920(…, −1)`, which works the cost out again)
  - news and UI packets (`FUN_0043fc20`, `FUN_01e2b5d0`, `FUN_00adf2e0`, `FUN_008bb290`)
  - real releases without an agreed amount (`FUN_00ebf920`)
  - our surplus cave (one per settlement)
- **The December window was 1–3 Dec:** our Jun/Dec settlement checkpoint. 54 surplus settlements were actually paid: £71.1m in total against £156.8m full value; the largest settlement was £9.1m and the largest full value £21.5m.
- **Most of the other ~340 computations** are very likely the news and UI work around those releases plus the AI batch's evaluations. The maximum of £46.5m matches none of our 54 full values, so it is some other contract's cost, and most likely only computed.
- **What our patches add:** our patches add only the settlements; vanilla does all the other computations. `nostalgia_retain_on_expiry` doesn't release anyone.
- **Next step:** the new tracer lines separate real releases from computations by caller, which settles the attribution.
- **Options, if real full-cost releases turn out large:**
  1. a 14-day-style cap on AI releases (as in labour-rights `notice_club_side`)
  2. lower `SETTLE_MAX`
  3. spread the checkpoint over the month (it already depends on review dates)


## 12. Upgrade condition and transition period (implemented)

Everything is still in `nostalgia_foreign_cap_ai`, so the NOSTALGIA list is unchanged.

### Upgrade condition

| Change | Where | What |
|---|---|---|
| `CHURN_EVAL(club, target)` | `02047960` (503 of 544 bytes) | The same squad walk now also counts the senior foreigners whose CA (player vfunc `+0`) is **≥ the target's CA**. The set is `CHECK`'s: every team of the club, foreign to the first team, 21+, not retired-like or away, listed and loaned-in players included, the target himself excluded. If 3 or more are at or above him, he is no upgrade on the 3rd-best senior foreigner. That is the same as "his CA > the 3rd-best CA", and fewer than 3 senior foreigners means any foreigner qualifies. A null target skips the test. Returns: 0 n/a, **1** drop (anti-churn, which takes precedence), 2/3 allow, **4** drop (anti-churn allows, not an upgrade). |
| Decision gate | `005181c7` → `020c1740` (153 bytes) | Passes the target player (EDI). Drops on 1 or 4 (`remove_target`). `SINK(result)` after `CHRN`. |
| Route gate | `0094bf45` / `0094b78f` → `02047c60` (232 bytes) | Passes the offered player (person vfunc `+0x378` of `OFFER_PERSON`). Skips on 1 or 4. `SINK(reason)` after `ROUT`; the reason is 1, 2 (brake) or 4. |
| Candidate filter | `006f4706` → `02047bc0` (152 bytes) | Passes the candidate player (argument 1). Skips on 1 or 4. `SINK(reason)` after `CAND`. |

**CPU:** compared with before, one CA getter per senior foreigner in the walk that already ran, plus one for the target. No extra walks.

**Juniors:** the condition applies to any foreign target, under-21s included, as specified. A low-CA foreign prospect is therefore not bought by a club whose 3 best senior foreigners are better. If that turns out too strict, the cheap fix is an age test on the target in `CHURN_EVAL` (about 20 bytes; 41 bytes are free).

### Transition until 1 September 2014

| Change | Where | What |
|---|---|---|
| Free release of foreigners | `FUN_0047ca40` entry (`83 ec 08 56 8b 74 24 10`) → `PAYOUT_CAVE` `020c1aaa` (141 bytes) | Before `TRANSITION_END` (date key `year << 9 \| day` < `2014 << 9 \| 244`), returns 0 for a player whose contract team (contract `+8`, a club team: `+0x23 == 0`, `+0x10` set) he is foreign to (`FUN_015440e0(team, 1, 1)`). The player test is person vfunc `+0x378` ≠ 0, so staff are untouched. `SINK(person)` after `PAYZ`. From 1 Sep the cost of the hook is the 6-instruction date test. |
| August surplus release | surplus ladder's day-of-year read → `TRANSITION_DOY` `020c1fb8` (67 bytes) | On 15–31 Aug 2014 (0-based days 226–242, year word 2014), for a listed surplus senior foreigner of an AI club (EDI = contract), it sets the Jan/Jul mark and returns a June day. The ladder then takes its release branch at once: unmark, payout (0 by the hook above), settlement 0, `FUN_00ebf920(…, 4, 0, 0, 0, 0)`. Otherwise it returns the plain day of year. `SINK(contract)` after `TRAN`. Human clubs never reach it, because the ladder exits for them first. |

**Callers of `FUN_0047ca40`, and whether 0 is safe:** the vanilla function already returns 0 (no contract, or contract flags `& 0xc`), so 0 is a value every caller handles. No absolute pointers to the function exist, only 7 direct calls, and nothing branches into the replaced bytes.

| Caller | What it does with the value | Effect of 0 |
|---|---|---|
| `0043fc20` (`0044026e`) and `01e2b5d0` (`01e2b89e`) | release dialog / news structure, capped at 7.5M for display | shows 0 |
| `00adf2e0` | news | 0 |
| `008bb290` | UI packet total | adds 0 |
| `00677090` area | "payout > club balance → error 0x1f" | passes |
| `00f32700` (AI weak-player release evaluation) | cost into `FUN_011bcde0` / `FUN_004a7790` | cheaper, so the AI releases foreigners more readily in July and August (intended: free) |
| `00ebf920` at `00ebfbeb` (actual release with amount −1) | the amount booked by `FUN_004a7790` | 0 is booked or skipped (as for any free release) |

**Verification:**
- `verify.py`: 0 problems (original bytes, overlaps across the NOSTALGIA set, capstone end-to-end).
- External branch targets, all known: `0047ca48`, `005181d2`/`0051820d`/`0051821e`, `006296b6`, `008f8840`, `00e5f250`, `00e65550`, `00ebf920`, `0149f260`, `0149f3c0`, `014a6d60`, `015440e0`, `0158a9e0`, `015c8926`, `016e6110`, `0047ca40`, and our own caves.
- `020c1aaa–020c1c00` is free across all `PATCHES`.

**Tracer** (`trace_plan.py`):
- `anti-churn: foreign target DROPPED by the upgrade condition …` (decision gate, reason 4)
- `route gate / candidate filter: … (upgrade condition …)`
- `TRANSITION payout zeroed (foreign player) for <caller>`
- `TRANSITION August surplus release triggered`
- `TRANSITION free release of a foreigner: AI surplus (ladder) | other (<caller>)`, with events naming the player and club
- `release cost worked out by … (0)`

`squad_snapshot` prints the club's upgrade bar. `trace_foreign_cap` counts surplus releases with a 0 payout.

## 13. Daily all-team sweep (implemented; replaces the first version)

### What went wrong, and the evidence

**First version.** The first version swept only the teams the AI squad review leaves out, assuming the Under 21s were among them. In the live run (Jul–27 Sep 2014) it swept 365 times at 219 clubs but processed no players. City still had 16 senior surplus foreigners in "Manchester City Under 21s", and Chelsea 19. They are listed, Not Needed and mostly marked, but the loan-listed bit is clear (flags `0x85`).

**The team exclusion was misread.**
- `FUN_01589610`'s jump table returns 1 for types 4–7 and 23–26, not 8–22.
- So the review driver excludes only types `0x16`, 4–7 and 23–26.
- A read-only read of 16 swept clubs found the team types 0, 1, 10, 11, 12, 15 and 30, all of which the review includes. Team type wasn't the cause.
- The walk's own test had called the game function, so it matched the review exactly. It found nothing to sweep.

**The real cause: the review is rare.**
- The ladder runs only inside the AI squad review (`FUN_006296b0` ← `FUN_00e723b0` ← `FUN_007c7bf0` ← `FUN_00dc4650` ← `FUN_00f5a1d0` modes 1/2 with no team argument).
- It ran about 365 times for 219 clubs over 88 days (one review per club triggered one sweep), so a club can go weeks without one.
- City's ladder last ran before the window. The loan bit, which the ladder's listed branch sets on every pass, was cleared afterwards. So no review fell inside 15–31 Aug, and none would be guaranteed in December either.

**The new trigger.**
- `FUN_00e175f0` is the AI's daily per-club routine. The scheduler `FUN_00ad5da0` calls it for every AI club that has a planning object `[[club+0x50]+0x24]`.
- It runs the decision passes (`FUN_00a71080`, about 680 a day in the trace) and planning mode 3.
- It runs at the top level of the club loop, not inside a squad iteration.

**The crashed probe (`probe_review.js`, 21:12).**
- In the 13 s before FM15 exited, it had sent one 5-second report with every counter at 0, so none of its hooks had fired. The game was paused, and the hooks only fire when a day is processed.
- Its callbacks (getters, `CHECK`, text formatting) never ran.
- Its only effect was installing three inline hooks in probe form at `00e723b0` (function entry), `020c19a0` (our stub, entered by `jmp` from a function entry) and the SWEPT sink. The same kind of attach at the same sink ran for 4 minutes earlier without trouble.
- I can't rule out the hook installation itself, but nothing in the script plausibly killed the process.

### Change

| Part | Where | What |
|---|---|---|
| Daily stub | `FUN_00e175f0` entry (`51 55 56 8b 74 24 10`) → `020c18a0` (46 bytes) | `pushad`; the club argument, null-checked; the planning object `[[club+0x50]+0x24]`, null-checked (AI clubs only). It calls `SWEEP(planning object)` with `ECX` → the club argument, then `popad`, the replaced code and a return to `00e175f7`. No branches into the replaced bytes; the only callers are `00ad5eda` and `00ad60f7`. |
| `SWEEP` head | `020c17dc` (99 bytes) | Checks plus the once-per-day guard (16 × {club, date key}) in the loader-allocated table at `[020c19dc]`. The guard is set only after the checks pass. The walk aborts afterwards only for human clubs or a club with no valid first team, which are never swept anyway. |
| `SWEEP` walk | `020c1b38` (158 bytes) | Every team of the club whose `+0x10` is the club, every member, `SURPLUS_ONE(member, planning object)`. Indexed, re-reading each vector. |
| Review stub | `006296b0` → `020c19a0` (24 bytes) | Only `SURPLUS_ONE` for the reviewed player. No sweep from inside the review, so players aren't released from teams the driver is still walking. |

A second pass on the same day (review plus sweep) is idempotent: listing, keep-7 and the mark are re-applied, and the release unmarks first.

**CPU:** one ladder pass per AI club player per day. Domestic and junior players exit after a few getters plus `IS_FOREIGN` / age.

**Loader feature (`WRITABLE`):** unchanged from the first version.
- `fm15_loader.py` and `fm15_loader.js` allocate a zeroed read-write block and write its address into the patch's 4-byte zero-cave pointer slot.
- Code pages keep their protection.
- `track_mods.py` ignores the slot.

**Verification:**
- `verify.py`: 0 problems (bytes, overlaps across NOSTALGIA, capstone, WRITABLE slot).
- All external branch targets are known. New ones: `00e175f7`. `01589610` is no longer called.

**Tracer** (`trace_plan.py`):
- `SWEEP: per-club all-team sweep` / `distinct clubs swept`
- `player checked in a swept team (type N)`, where 0 is the first team
- listings and releases from a `reviewed team` or a `swept team type N`
- `SWEEP listed/released` events

## 14. Performance: rank once, sweep weekly (implemented)

**Problem.** The holidays were slow. `CHECK` walked every team of the club for each player it judged, so a daily sweep cost O(senior foreigners × members) per club. On top of that, `trace_plan` hooked the per-player paths.

### Changes (all in `nostalgia_foreign_cap_ai`; NOSTALGIA unchanged)

**Cached `CHECK`** (`02047e20`, 582 bytes):
- **Where it lives.** It sits in a second zero run in `.text`, at `02047e16`–`02048247`. Like the first, this is a function body moved to `helper.dll`: its stub at `02047e10` is `jmp [0246b848]`, and neither the stub nor the run is referenced. `020c1e00` is now `jmp 02047e20`, so every caller and tracer keeps the old address.
- **One walk ranks the club.** It keeps the 3 best senior foreigners by (CA descending, address ascending), over the same set as before: every team, foreign to `ctx`, 21+, not retired-like or away.
- **What is cached.** It stores the 3rd one's {CA, address} in the rank cache: 64 direct-mapped slots × {ctx, key, CA3, address3}, in the loader's writable block after the sweep guard.
- **The cache key.** It is day number | first-team size << 20. A new day, or a first-team arrival or departure, re-ranks.
- **The test.** A player is surplus when 3 are ranked and he ranks below the 3rd. That is exactly "3 or more others ahead of him", ties included: he is either in the ranked set or compared against it like any other member.
- **Who benefits.** Every caller: the sweep, the review stub, `IS_SURPLUS` (status hook, bosman retain).
- **Without the block** (pointer 0), it ranks on every call: one walk, as before.

**Weekly sweep** (head `02048070`, 163 bytes; the daily head at `020c17dc` is gone):
- Each club is swept once per `SWEEP_DAYS` = 7 days, using day number = year × 365 + day.
- During 15–31 Aug 2014 it sweeps daily, so that window gets up to 17 sweeps per club.
- An earlier day (another save loaded) always sweeps.

**Writable block:** 1152 bytes (`0x80` sweep guard + 64 × 16 rank cache).

### Cost estimate

About 700 AI clubs, about 60 players each (3 teams), 15–25 senior foreigners at big clubs.

| | Before (daily, uncached) | After (weekly, cached) |
|---|---|---|
| Ladder passes | 42,000 per day | ~6,000 per day |
| Domestic and junior players | cheap: a few getters plus `IS_FOREIGN` / age | unchanged per pass |
| `CHECK` walk of ~60 members, each with 4–5 virtual calls plus `IS_FOREIGN` | once per foreign senior (~10 per club): ~420,000 member evaluations per day for the sweep alone | at most one rank per club per day (on the first `CHECK`): ~6,000 per day weekly, up to ~42,000 per day in the August window |
| Status hook and review | also walk per call | cache hits |

- **Sweep `CHECK` work:** roughly **70× less** outside the August window and about 10× less inside it.
- **Overall daily cost of the mod:** dominated by the gates (`CHURN_EVAL`, unchanged) and the remaining getters.
- **Tracer:** a much larger share of the slowdown came from `trace_plan` with every hook on.

### Tracer

`trace_plan.js` has `const HOT = false`, and `trace_plan.py … --hot` turns it on.

**Off by default (per player or per candidate):**
- candidates and pool (`016e6110`, `016e6d20`)
- shortlist rebuilds
- payout computations (`0047ca40`)
- the depth-chart exit
- decisions (`00517b20`)
- `CHECK`
- offer validity
- the per-player `SURPLUS_ONE` hook

**Always on:**
- gate sinks (CHRN, ROUT, CAND)
- transition sinks (PAYZ, TRAN)
- UNLS
- sweeps (SWEP), with `FUN_00e175f0` entry and exit marking "inside the daily routine"
- listings and releases from the surplus ladder, by path and team type. The team is found by scanning the club's teams only when a listing or release happens.
- releases by caller
- offers, accepts, planning runs, decision passes

### Verification

- `verify.py`: 0 problems (bytes, overlaps across NOSTALGIA, capstone, WRITABLE slot).
- The second zero run is used by no other patch.
- New external branch targets: `02047e20` (from `020c1e00`), `02048070` (from the daily stub), and the walk's `020c1b38` / `020c1bc3`.
