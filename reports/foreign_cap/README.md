# Nostalgia mode: pre-Bosman foreign-player limits

> **Current design (stripped back, see [../transfer_ai/native_mode.md](../transfer_ai/native_mode.md)).** Below this box is the history of the earlier designs (3+2, top-5 by value, the "short of domestic players" switch, the offer gate). They no longer apply.
>
> **Patches in the current set:**
>
> | Patch | What it does |
> |---|---|
> | `nostalgia_3_foreigners` | One stored rule per club competition, `{0x04 ≤ 3}` (all foreigners in a match squad).<br>• Hook: `FUN_01062190` entry → `STORE3_CAVE` `020c18d0`; it uses `P32_ADDRULE`.<br>• An existing type-0x04 maximum ≤ 3 counts as done, whether it's data or the old 3+2 build's marked rule. Saves from the 3+2 build keep a harmless ≤ 5.<br>• A larger maximum is tightened to 3.<br>• The assimilated counting hook (`01606539`) is gone.<br>• The rule switches on the game's own foreign-limited AI mode (shortlist `+0xea`). |
> | `nostalgia_3_foreigners_ui` | The rules screen shows one line, "Maximum of 3 foreign players" (`010642b2` → `020c1840`). |
> | `nostalgia_foreign_cap_ai` | See the rows below. |
>
> **`nostalgia_foreign_cap_ai`, part by part:**
>
> | Part | Where | What it does |
> |---|---|---|
> | `CHECK` | `020c1e00` | **Surplus test:** foreign (type-0x15 test), **aged 21+** (person vfunc `+0xd0`), and at least 3 other senior foreigners at the club have a higher **current ability** (player vfunc `+0`; ties broken by address). Walks every team of the club. |
> | Surplus ladder | `FUN_006296b0` → `020c1c00` | Unchanged: list for sale and loan, Jan/Jul mark, Jun/Dec release with a 20–75% settlement (mixed `rdtsc`, unmark before release). It now uses this test. |
> | Status hook / `IS_SURPLUS` | `020c1600` | Same test. |
> | `UNLIST_JUNIOR` | `020c16c8` | Unlists foreigners under 21 that the old rule listed (transfer- and loan-listed, "Not Needed"; bits 0, 3 and 7 cleared). |
> | Anti-churn gate | `005181c7` → `020c1740`, which calls the shared `CHURN_EVAL` at `02047960` (a zero-run cave in `.text`) | For a **foreign** target of an **AI** club, walks the club's teams and counts senior foreigners. It counts only those with their own contract at the club (no loans in) who aren't listed "Not Needed". It drops the target (no bid) when there are **3 or more** of them and **one joined within 365 days** (contract `+0x28`). Domestic targets and human clubs are unaffected. |
>
> **Dec 2014 additions to `nostalgia_foreign_cap_ai`** (see [../transfer_ai/README.md](../transfer_ai/README.md) section 11):
> - the anti-churn test is a shared routine (`02047960`)
> - a route gate stops the "offer to interested clubs" route (`0094bf45` / `0094b78f`) for foreign players the AI buyer couldn't pursue (anti-churn or native `+0xb8` brake)
> - a candidate filter (`006f4706`) skips such foreign candidates
> - native domestic pricing is ×1.2 instead of ×1.5 (`DOMESTIC_PRICE_FACTOR`)
>
> **Upgrade condition and transition period** (see [../transfer_ai/README.md](../transfer_ai/README.md) section 12):
> - **Upgrade condition:** an AI club only pursues, shortlists or is offered a foreign target whose CA is above its 3rd-best senior (21+) foreigner's CA. A club with fewer than 3 senior foreigners takes any foreigner. This is the same set and measure as `CHECK`. `CHURN_EVAL(club, target)` works it out in the same squad walk as anti-churn. Both must allow, at all three points (decision gate, route gate, candidate filter). Reason code 4.
> - **Transition until 1 Sep 2014:**
>   - The release payout `FUN_0047ca40` returns 0 for a player foreign to his club (entry hook → `020c1aaa`), so AI, surplus-ladder and human releases of foreigners are free.
>   - On 15–31 Aug 2014 the surplus ladder releases listed senior surplus foreigners without the Jan/Jul mark (day-of-year helper `020c1fb8`).
>   - From 1 Sep 2014 the normal mark/settlement ladder and payouts apply.
>
> **Daily all-team sweep** (see [../transfer_ai/README.md](../transfer_ai/README.md) section 13):
> - The AI squad review that ran the ladder is rare: about 365 reviews for 219 clubs over Jul–Sep 2014. City's and Chelsea's surplus in their Under 21s missed the August window.
> - The ladder is now `SURPLUS_ONE` (`020c1c00`, a function). The review stub (`006296b0` → `020c19a0`) calls it for each reviewed player.
> - The AI's daily per-club routine `FUN_00e175f0` (→ stub `020c18a0`) calls `SWEEP` (head `020c17dc`, walk `020c1b38`). At most once per club per game day, it runs the ladder for every member of every team of the club.
> - The guard is a 16-slot table in a block the loader allocates (`WRITABLE`, pointer slot `020c19dc`).
> - **Performance:**
>   - `CHECK` (`020c1e00` → `jmp 02047e20`, a second unreferenced zero run) ranks a club once a day (and again on a first-team arrival or departure). It caches the 3rd-best senior foreigner's {CA, address} in the writable block, with the same verdicts as before.
>   - Sweeps are weekly per club, and daily during 15–31 Aug 2014.
>   - See [../transfer_ai/README.md](../transfer_ai/README.md) section 14.
>
> **Removed:** the offer gate (and its agreed-deal fix), the top-5/short target gate, `DOMESTIC_MIN`/`KEEP_SHORT`, `+0xcc = 20` domestic pools, and the forced `+0xea`.
>
> **`nostalgia_ai_plan_without_surplus`** (`patches_transfer_ai.py`, formerly `nostalgia_ai_domestic_planning`): listed "Not Needed" players are left out of the depth chart (`FUN_009ed420` → `02047b80`).


The nostalgia patch is **`nostalgia_3_plus_2`**: UEFA's "3+2" rule (1991-92 to 1995-96), applied in every league. A match squad may include at most 3 foreigners, plus up to 2 "assimilated" foreigners. Clubs can own as many foreigners as they like and rotate them. Signings and registration are untouched.

Three earlier designs stay in the module as optional patches: a signing block, a plain cap, and AI squad planning.

The research uses fm.exe 15.3, and addresses are Ghidra VAs (image base 0x400000). **Nothing here has been tested in the game.** The patches are in [patcher/patches_foreign_cap.py](../../patcher/patches_foreign_cap.py), none of them are in DEFAULT, and the tracer is `tools/trace_foreign_cap.py`.

## How "foreign" is decided

The game's test for rule type `0x15` (`FUN_015440e0` → `FUN_01543dd0`) decides who counts as foreign:
- A player is foreign if he's foreign to the **club's nation**. If the club plays in another nation's league (`FUN_014b92d0`: Welsh clubs in England, Monaco and similar), he must also be foreign to the **league's nation**.
- **Second nationalities count.** If any of his other nationalities matches, he's domestic.
- **EU nationals are foreign.** This path never calls the EU/EEC test.
- **Exception (guess):** a nation's database can mark other nations as "domestic" for a date range (list at nation `+0xb4`, read by `FUN_015e95c0`). I couldn't read the 1530 database to check.

Rule types `2`, `3`, `4`, `0x15` and `0x7e` all use this same test: one case of the per-player counter `FUN_01605ae0`, at `01606539`.

FM Classic's `no_foreign_restrictions` (`FUN_00dbc070`) never uses these types, so it is irrelevant here.

## How the game applies squad rules

**Rule lists are per-call heap copies.**
- A club's effective rules are built by copying a competition rule group's `+0x34` list and passing the copy through `FUN_01063090(ctx, list, p3, fixture)`, which adds and edits rules per club.
- **Match-day lists** come from `FUN_01062190` when called with a fixture. It keeps match-day types (`FUN_00f8a4a0`, which includes `0x04`) and **erases squad types such as `0x15`**.
- **Registered-squad lists** come from `FUN_011a6b90`, which strips match-day types.

**What uses the registered-squad lists:**
- the registration check `FUN_005bc880` (reason `0x16`)
- the AI registration fixer `FUN_00ae58a0` → `FUN_00d2f120`
- the rules-and-counts helper `FUN_00564960`

All of these are gated on the rule group's registration byte (not `-1`), so they only act in leagues with squad registration. **So a type `0x15` "in squad" rule probably does nothing for match selection in most leagues.** That's why the 3+2 patch uses match-day type `0x04`. Confidence: medium.

**How match-day rules are enforced:**
- **AI selector.** `SQUAD_SELECTOR::select_squad_of_players` (`00e43340`) calls `FUN_00852050`. For each rule it works out the remaining allowance from the players already picked (`FUN_00f8c840` → `FUN_00f8c610`), then adds a selection constraint (`FUN_00f8c270(type, remaining, compare)`). Data rules such as "`0x04` ≤ 5" already exist in some leagues (for example stream 42), so the selector handles this type and shouldn't produce illegal squads.
- **Human screens.** The team-selection and squad-warning code (`FUN_00c93440`, `FUN_0097eea0`) checks each match-day rule with `FUN_00f8a750` against the counts and shows warning texts (IDs `0x3b8xx`). Whether a broken rule hard-blocks the match, or only warns or auto-corrects, is **not confirmed**. The game uses the same mechanism for real-world rules like Russia's foreigner limit.

**Transfers.** FM15 normally doesn't check squad rules at signing time. The two existing checks are gated to competition IDs `0x28` and `0x1fbc1`:
- the offer check `FUN_006f69f0` → `FUN_00824560`
- the AI target check `FUN_00f14fc0` → `FUN_005e4050`

**AI "foreign places".** I found nothing in AI transfer planning that considers match-day foreign places. The only rule-aware planning is the EPL-gated registration check above, which is about registered squads, not match squads. The nostalgia set therefore adds its own AI planning, `nostalgia_foreign_cap_ai` (below).

## `nostalgia_3_plus_2`

3+2 is now a **real rule stored in each competition**. It sits in the competition's own squad-selection rule list, so it is saved with the career, exactly like a league's own foreign-player rule.

### Where the rules live

- **The list.** Each competition's rule group (`FUN_010664a0(comp, team, -1)`: through the competition's `+0x68` object, or through its nation's rules) holds its squad-selection rules as a vector pointer at **`[group+0x34]`**. That list is:
  - filled from the database by the rule loader `FUN_011c8170` when a career is created (`FUN_01064c40`)
  - saved with the career
  - copied by every consumer: `FUN_01062190` for club match-day and squad lists, `FUN_011a6b90` for registration, `FUN_00fe9890` for the status flags and the 'Fgn' badge, `FUN_01064160` for the rules screen
- **The rules added:**
  - `{type 0x04 all_foreign_players_in_match_squad, maximum, 5}`
  - the marked `{0x04, maximum, 3, ref MAGIC}`. `MAGIC` is `0x3250334E`, stored in the rule's ref field `+0x4`, with tag `+0x0` = 0.

### How and when they're added

**Hook.** `FUN_01062190` entry (`55 8b ec 83 e4 f8` → `jmp 020c18d0` + NOP). This is the function that builds a club's rule list from a group. It runs whenever a club's squad or match-day rules are needed, so every competition with club matches passes through it on first use: leagues, cups, and continental club competitions. National-team contexts are skipped. The cave scans the group's stored list (at most 15 rules) and acts as follows.

| Stored list | Action |
|---|---|
| Already has our marked rule (a save from this mode, or already done this session) | Nothing |
| Has an unmarked type-`0x04` maximum ≤ 3 *and* a 4–5 maximum | Re-marks the ≤ 3 one (one dword write). This restores the marker after loading a save, in case the save format doesn't keep `+0x4`. |
| Has an unmarked type-`0x04` maximum ≤ 3 only | Nothing: the data's stricter rule is kept |
| Has type-`0x04` maxima above 5 | Tightens them to 5 in place |
| Otherwise | Builds a **new vector**: the old rule pointers, plus `{0x04 ≤ 5}` (unless a 4–5 maximum is already there), plus the marked `{0x04 ≤ 3}`. It then **publishes it with one pointer write** to `[group+0x34]`. |
| No list at all | Creates one the same way |
| 14 or more rules | Left alone, because the counter structures hold 15 |

**Why a new vector.** The old vector is never freed; it's leaked once per group, a few bytes each. So a thread that's copying the old list at that moment is never disturbed. Pushing into the shared vector could reallocate under such a reader.

**Allocation.** Everything comes from the game's own pools: the `SQUAD_SELECTION_RULE` pool (`FUN_00f842a0` + `FUN_00f5e4b0`), the rule-list vector pool and constructor the loader uses (`FUN_00f8e380` / `FUN_00f8e4e0`), and `FUN_00f64ec0` push_back. The game owns, saves and frees the result.

**Cost.** A scan of the stored list on each call, the same order as the per-call injection it replaces. The new vector is built once per group per session, or never, for a save that already has the rules.

**Why not once at load or new game.** I found no single post-load hook, and the database loader `FUN_011c8170` merges lists by type (`FUN_00f8bd00`), which would collapse the two type-`0x04` rules. The lazy, idempotent first-use approach covers new careers, loaded saves and competitions without a stored list alike.

### Counting (unchanged)

`FUN_01605ae0`'s foreign case (`01606539` → `jmp 020c16c8`) skips players homegrown in the nation (`FUN_016033c0`) for the marked rule, when called from the squad counter `FUN_00f8c610`. The ref field reaches that counter: it copies `{tag, ref}` from the rule it counts, and the copied lists keep all 16 bytes.

### What the stored rules change compared with the old per-fixture injection

- **Match legality, the AI selector and match-day lists.** These get their lists from `FUN_01062190`. With a fixture, it keeps match-day types and so keeps the stored `0x04` rules. Squad lists without a fixture erase match-day types, as before. This is exactly how leagues with data `0x04` rules (stream 42, Russia) already work. The AI selector (`FUN_00852050`) builds a constraint per rule. Its constraints carry no marker, so AI teams name at most 3 foreigners in total (legal and conservative), as before.
- **Registration: unaffected.** `FUN_011a6b90` strips match-day types (`FUN_00f8a4a0`, which includes `0x04`), and so does `FUN_01062190` without a fixture.
- **The 'Fgn' badge is now native.** `FUN_00dbc070` reads the stored list, finds foreign type `0x04`, and sets the Fgn bit for every foreigner. The counting hook doesn't apply there, because the caller isn't `FUN_00f8c610`; that matches the ≤ 5 rule. So `nostalgia_3_plus_2_ui` no longer includes the badge cave.
- **The rules screen still needs `nostalgia_3_plus_2_ui`.** `FUN_01064160` drops match-day types, the stored `0x04` rules included, from the list it shows. The UI patch keeps its rules-screen part, which adds the two display lines to the screen's local copy.
- **Data rules other screens may show:** squad-rule text helpers now see real `0x04` rules wherever they read stored lists.

### Saves

- **Saved with the career.** Rule-group lists are part of the saved competition data; the squad README notes that rules are copied into the save at the start of a career. The two rules therefore live in a nostalgia save. **Unconfirmed:** whether `+0x4` is saved. If it isn't, the marker is restored on first use, as described above.
- **A nostalgia save in vanilla or labour mode:**
  - The stored rules stay. Without the counting hook the marked rule counts all foreigners, so the limit becomes a plain "at most 3 foreigners in the match squad", and the ≤ 5 rule is redundant.
  - Labour mode's `squad_rules_core` + `no_nationality_quota` disables type `0x04`, so neither rule applies there.
  - The 'Fgn' badge shows natively in both.
- **A save from another mode in nostalgia mode** gets 3+2 on first use of each competition, and keeps it from then on.

**Confidence:**
- **Medium-high:** the stored rules are picked up by match legality, the AI selector and the badge (the same paths data `0x04` rules use), and registration is unaffected.
- **Medium:** saving (not traced). Also the hook: every club competition must reach `FUN_01062190` before its rules matter (likely, since match squads are built through it).
- **Thread safety:** handled by publishing a new vector instead of pushing into the shared one, but not proven.

## `nostalgia_foreign_cap_ai` (in the nostalgia set, with 3+2)

AI clubs keep their `KEEP` (5) most valuable foreigners, matching 3+2. They transfer-list the rest, and only buy a foreigner who would rank among their 5 best.

| Part | Site | What it does |
|---|---|---|
| Target gate | `005181c7` in `make_transfer_decision_for_player` | Drops a foreign target, using the game's own `remove_target`, if the club already has 5 or more foreigners worth more than him. Value comes from player vfunc `+0x20`, the stored value at `+0xc0`. |
| Surplus ladder | Entry of `FUN_006296b0`, the AI's per-player squad review: `83 ec 10 53 55 56` → `jmp 020c1c00` (second cave range, `020c1c00`–`020c1dc9`) | The surplus ladder below |
| Checker | `020c1e00` (moved from `020c1600`) | Shared by all parts |
| Offer gate (AI buyers) | `006f6a3d` in `FUN_006f69f0` → `jmp 020c1790` | Below |
| Status hook | Entry of the squad-status setter `FUN_015c8920` → `jmp 020c165d` (cave `020c1600`–`020c16c5`) | Keeps listed surplus foreigners at 7 "Not Needed": the AI's daily re-rating ignores listing. See [../squad_status/README.md](../squad_status/README.md) |

### Domestic-aware AI (added after the first season's results)

**What the season showed.** The tool `tools/squad_snapshot.py` reads squads from the running game (see "Squad snapshots" below), and its output is in [squads_manchester_city.txt](squads_manchester_city.txt), [squads_arsenal.txt](squads_arsenal.txt) and [squads_chelsea.txt](squads_chelsea.txt). The snapshots were taken on 4 Aug 2015, with the patch version before the domestic-aware change. Domestic counts include everyone the game's own test treats as domestic.

| Club | Players | Foreign | First team | Domestic in first team | Foreigners signed since 1 June 2015 (date joined, from contract `+0x28`) |
|---|---|---|---|---|---|
| Manchester City | 115 | 40 | 21 | **3** (Yaya Touré, Joe Hart, Scott Sinclair) | Juan Cuadrado, 7 Jul, value £29.8m, **#3** in the club's foreign value ranking |
| Arsenal | 93 | 12 | 22 | 12 | Rubén García, 9 Jul, £15.4m, **#4** |
| Chelsea | 103 | 29 | 24 | 8 | Antonio Candreva, 20 Jul, £22.9m, **#3** |

**Diagnosis.**
- **The gate let them through by design.** Each new foreigner ranks among his club's 5 most valuable foreigners, so the target gate (`KEEP` = 5) allowed him. Nothing came through an uncovered route.
- **The rule itself was wrong.** It didn't look at how many domestic players a club has. City field at most 3 non-assimilated foreigners under 3+2 but have only 3 domestic first-teamers.
- **The surplus ladder is working:** City have 35 foreigners listed, 18 loan-listed and 30 marked.
- **Who counts as domestic.** The game's type-`0x15` test counts Wales, Scotland and Ireland players as domestic in England, and also Yaya Touré (Ivory Coast), John Obi Mikel and Branislav Ivanovic. All three had played in England for over 5 years, but I haven't traced why the test treats them as domestic. Some EU nationals with long English careers, such as Kompany, are still foreign.

**Other AI buying routes.**
- **Covered by the target gate:** `make_transfer_decision_for_player` (`00517b20`) is called from 5 places, including the listing routine's "prompt interested clubs" (`FUN_00db28b0`). It dispatches to `make_transfer_offer`, `make_free_transfer_offer` (free agents and trials) and loans.
- **Not covered by the target gate:** other code creates bids directly (`FUN_00cb9e40`, called from 9 places such as `006ae051`, `007d9844`, `00842a0d` and `01e4c6b3`), and contract offers to free agents (`FUN_00919690`, also called from `00cba06e`…).
- **New backstop:** these are now covered by an offer gate in `FUN_006f69f0`, the validity check every offer goes through when it's processed. It is the same site as the optional signing block, rebuilt for AI buyers only: human buyers are never affected. An AI offer for a foreigner the checker rejects fails with reason `0x29`.
- **Offer gate fix (see [../transfer_ai/README.md](../transfer_ai/README.md)):** the checker now always gets the buying club's **first team** (an offer's ctx can be its destination team, e.g. the U21s, whose small domestic count made every club look short), and deals already agreed (offer state `+0x28 == 0x13`, executed by the completion queue `FUN_00daf4f0`) are no longer re-checked, so they can't collapse on completion day.
- **Possible gap:** free-agent contracts that never become an offer.

**New rule (`DOMESTIC_MIN` = 15, `KEEP_SHORT` = 3).** The checker now also counts the **domestic players in the club's first team** (the team it is given, not reserves or youth), skipping the same retired and away players.

| Domestic in first team | Buying (target gate, offer gate) | Surplus ladder keeps |
|---|---|---|
| Fewer than 15 | **No foreigners at all**, upgrades included | 3 most valuable foreigners |
| 15 or more | A foreigner only if he'd be among the club's 5 most valuable foreigners | 5 |

On the snapshot data, City, Arsenal and Chelsea are all short (3, 12 and 8 domestic first-teamers), so all three stop buying foreigners and list everyone beyond their best 3.

**Will the AI look for English players instead?** Not deliberately. Dropping a foreign target (`remove_target`) frees the shortlist slot, and the shortlist builder (`FUN_00b86c00` / `create_shortlist`) refills it from its scouting knowledge, which for an English club includes plenty of English players. But it doesn't prefer domestic players, so it may keep proposing foreigners that the gates then drop. That wastes AI decisions but buys no foreigners. Nudging the builder toward domestic players would need its target scoring, which I haven't analysed.

### What listing a surplus foreigner does

**`FUN_0089bbf0` (mode 2).** It returns without listing in these cases:
- the player already has offers or pending moves (`FUN_00f9a930` / `FUN_0163e210` queries)
- his contract type is excluded (`FUN_01541640`)
- the club's AI manager doesn't have bit 0 of `+0xc4` set. **Guess**: this keeps human clubs out.

Otherwise it calls `FUN_00e5f250(player, club, reason, -1, 0)`. The reason is normally `0x0f`. It is `0x12` when the player is worth under £500,001 and his ability is above 130 or 400, depending on value.

**`FUN_00e5f250`** does three things:
- **Listed flag.** It sets contract byte `+0x32` bit 0 ("transfer listed", read by contract vfunc `+0x8c`). With reason `0x12` it also sets bit 5.
- **Squad status.** It sets the squad status to **7** through the game's own setter, contract vfunc `+0x84(7, club)` (`FUN_015c8920`, which writes the byte read by vfunc `+0x80`, contract `+0x30`). So no extra code is needed for "Not Needed".
  - Calls to that setter elsewhere pass the constants 1 to 7.
  - The bid evaluation's factor table has a case for every status 1 to 7, with 7 the lowest at 0.1.
  - That fits the parser's numbering: 1 Key, 2 First Team, 3 Rotation, 4 Backup, 5 Hot Prospect, 6 Youngster, 7 Not Needed.
- **Asking price.** Through `FUN_0163e210(4, 0, price, -1, 0/1, 0)`, it stores a type-4 entry, the asking price, equal to the player's **value**, or his release clause if that is lower. For reasons `0x0f`, `0x10` and `0x12` it also stores a second entry (flag 1) of **max(50% of value, price argument)**. **Guess**: a minimum fee.

### The surplus ladder (AI clubs only)

A **surplus foreigner** is one with 5 or more more-valuable foreigners at his club (the checker with `RANK|SKIP_CONTRACT`).

**Who is left alone.** The ladder skips:
- human-managed clubs (`FUN_0158a9e0(team, 1)`)
- players on loan elsewhere (player vfunc `+0x16c(0,0)`, the same filter the game's squad counter uses)
- players with a move already arranged (player vfunc `+0xe8(0,0)`)
- players whose contract type isn't a normal one, the same test `FUN_0089bbf0` makes (`FUN_01541640`)

Each skip calls a no-op `SINK(reason)` at `020c1dc2`, so the tracer can count it.

**The ladder:**

1. **List every surplus foreigner.** The first in-game run showed `FUN_0089bbf0` (mode 2) refusing most players, about 70%. Its refusals:
   - its contract-type test
   - the AI-manager flag `+0xc4` bit 0
   - mainly, it skips listing whenever other clubs already have the player on a shortlist or are interested (`FUN_01558e70` interest lists, masks 4, 8 and 3); it pokes those clubs to decide instead (`FUN_00db28b0`)

   The cave now calls the inner routine `FUN_00e5f250(player, club, 0x0f, -1, 0)` directly, with the AI manager as `this`, for any surplus foreigner who isn't yet transfer-listed. That routine sets the "listed" flag, squad status 7 "Not Needed" and the asking price (his value), and it never releases on reason `0x0f`. It doesn't touch offers, so pending interest and deals carry on; players with an arranged move are skipped anyway.
2. **List for loan as well.** The cave sets contract `+0x32` bit 3, which the game reads as "listed for loan": player vfunc `+0xdc` (`FUN_0162bbb0`), and the `player_is_transfer_listed_for_loan` filter. I found no separate AI "loan list" routine, so this is a direct flag write, done the same way the game sets the transfer-listed bit.
   - **Nudging loans home:** not done. The AI loan market isn't steered toward the player's own nation. Under 3+2, a home club would count him as domestic, so he'd be playable there. Doing that would need changes to AI loan-target selection (`FUN_0059a330`), which I haven't analysed.
3. **Release after roughly six months, with a negotiated settlement.**
   - **No listing date is stored.** The contract keeps only flag bits at `+0x32`; the asking-price records hold no date I could find. So the cave uses checkpoints and one marker bit, contract `+0x32` bit 7. The code reads this byte through vfunc `+0x8c` and tests bits 0 to 6 only; no instruction tests `0x80`.
   - **Marking.** A surplus foreigner still listed when he's reviewed in **January or July** gets marked.
   - **Releasing.** If he is still listed and marked when reviewed in **June or December**, he's released.
   - **Effect:** release comes 5 to 11 months after listing, about 6 on average. A player who stops being surplus loses the mark. The date comes from `[0x0239ebf4] & 0x1ff`, the day of the year.
   - **How he's released:** through the AI's own call, `FUN_00ebf920(person, team, 4, 0, amount, 0, 0)` with `this = 0x241c138`, the same call `FUN_01f08430` uses. That handles the contract, news and finances.
   - **The settlement:** `amount = full × p / 100`. `full` is `FUN_0047ca40(person)`, wages for the rest of the contract (the normal release cost). `p` is **uniform 20–75%**, from `rdtsc` (I didn't trace a game RNG).
   - **Paying the settlement.** `FUN_00ebf920` books its 5th argument instead of the `FUN_0047ca40` payout whenever it isn't -1 (`00ebfbde`–`00ebfbf9`; the same agreed-amount path mutual terminations use). That one variable feeds the finance booking (`FUN_004a7790`) and the later uses I could see, which probably include the news item. The release is booked with payment type 2 (mutual termination) rather than 1.
   - **Scope.** Only these surplus releases pay a settlement. Human releases and the AI's normal releases still pass -1 and pay the full amount.
   - **`SETTLE_MIN` / `SETTLE_MAX`** are in the module.

**Club finances (risk).**
- **Settlements are big.** A surplus foreigner on £50k a week with 2 years left costs about £5.2m in full, and £1–4m as a settlement.
- **Clubs pay many at once.** Clubs with many surplus foreigners (in the in-game test, Arsenal, Chelsea and Man City) will pay several such settlements at the same two checkpoints, especially in the first season.
- **Releases are skipped when:**
  - a player is out on loan, which a successful loan listing achieves
  - a player has a move arranged
- **Expiry window.** Contracts ending on 30 June cost almost nothing to settle in June.
- **Not covered:** the game's own release code may refuse in some cases (`FUN_00ebf920` has its own checks), and the tracer logs every release with both amounts.

### Does his price fall? Yes, to about his value, and the club gets much easier to deal with

1. **The asking value.** The selling club's valuation (player vfunc `+0x28` → game layer `FUN_009efc80`) **returns a stored type-4 entry directly** when one exists. Once listed, the club's valuation is therefore the player's value, or his release clause if lower.
   - **Unlisted:** the value is built from the club's own importance level for the player (`FUN_0045c3f0` / `FUN_0163e2b0`). The level factors are ×1.1, ×1.0, ×0.9, ×0.55, ×2.0 (hot prospect), ×0.7 and ×0.5.
   - **Inflations on top:** for players the club rates highly (level < 4), extra adjustments apply (`FUN_00f3a3b0` / `FUN_00ac59a0`). These are **skipped when the player is transfer-listed**. Other adjustments include ×3 in some cases, and a `200000000` "not for sale" sentinel.
   - Also, being listed raises the importance step by 1, or by 2 at age 30 or older, and any step above 4 becomes 7 (×0.5) at age 22 or older.
   - The final ×0.1 for listed players at the end of `FUN_009efc80` only applies in the EPL-gated case (`FUN_014a6d60`).
   - **Result:** a listed surplus foreigner is priced at about 1.0× his value, where an unlisted first-teamer is typically well above it.
2. **Bid evaluation (`FUN_01f325f0`).**
   - **Accept:** if the bid is at least **98%** of the valuation, or within £1,000 of it.
   - **Negotiate or reject:** otherwise it compares the bid with **valuation × factor**. A bid at or above that line gets a counter-offer and negotiation; below it, the bid is rejected outright.
   - **Factors by contract squad status, when the club isn't listing the player:** Key 0.6, First Team/Rotation 0.5, Backup/Youngster 0.4, Hot Prospect 0.5.
   - **When the player is listed** (player vfunc `+0xdc`: transfer- or loan-listed): Key 0.4, First Team/Rotation 0.4, Backup/Youngster 0.2, Hot Prospect 0.3, **Not Needed 0.1**.
   - A separate offer flag (`+0x3c` bit 10) uses 0.25.
   - **Example:** a surplus foreigner worth £1m has a valuation of about £1m once listed. A £980k bid is accepted. A £100k bid or more gets a counter-offer, where a First Team player not listed would need £500k just to start talks (at that player's own, usually higher, valuation).
3. **Squad status 7 and free agency.** `nostalgia_retain_on_expiry` lets status-7 players go when their contracts end, so unsold surplus foreigners leave on free transfers, with compensation if `nostalgia_compensation_any_age` applies.

### Risks

- **Marker bit.** Contract `+0x32` bit 7 appears unused (survey of every `+0x32` test, and of every test on the vfunc `+0x8c` result). Some code tests the whole byte for non-zero, but a marked player is always listed too, so that byte is non-zero anyway. The mark is cleared when he stops being surplus.
- **Review frequency.** Marking and releasing need a squad review (`FUN_006296b0`) of the player in the right months. If the game reviews a player less than monthly, release can come later. The tracer counts reviews.
- **Status resets (fixed).** The first in-game season showed the AI's daily re-rating (`FUN_00b59850`, `00b599c4`) overwriting status 7 for most listed surplus foreigners. The status hook now keeps them at 7; see [../squad_status/README.md](../squad_status/README.md). Earlier notes: other code also writes squad status: setter callers at `0x636fce` (5), `0x636fe8` (4), `0x743290` (2), `0xd63bfe` (3), `0x8e7829` (1) and others with variable values. I couldn't rule out the AI re-rating a listed player away from 7. The surplus hook doesn't relist a player who is still listed. The tracer counts status writes by caller.
- **Releases.**
  - The AI's routine release of weak players (`FUN_00f32700`) ignores squad status, so "Not Needed" doesn't trigger a release by itself.
  - The reason-`0x12` path of `FUN_00e5f250` can release the player at once (`FUN_00ebf920`), but only if his contract is type 3 (**guess**: non-contract, so negligible pay-off), or in the EPL-gated registration case.
  - Where a release does happen, the pay-off is the game's normal one (`FUN_0047ca40`): wages for the rest of the contract, because the labour-rights notice cap isn't in the nostalgia set. Expect this to be rare.

## Optional patches (earlier designs)

| Patch | What it does | Combines with 3+2 |
|---|---|---|
| `nostalgia_foreign_cap_rules` | Plain cap: `0x04` ≤ 3 in fixture lists, plus `0x15` ≤ 3 in registered-squad lists (a registration cap where registration exists). Cave `020c18d0`. | No (same site) |
| `nostalgia_foreign_cap` | Hard signing block:<br>• offer gate at `006f6a3d` (`FUN_006f69f0` fails with reason `0x29`)<br>• join gate at `FUN_00b9c670` (returns `0xff`)<br>• AI gate at `005181c7`<br>Uses the same checker without ranking. | Yes. Not with `_ai` (same AI site). |

**How the checker counts.** `CHECK(ctx, player, flags)` walks every team of the club (`FUN_0149f3c0` / `FUN_0149f260`, team `+0x24` list). It skips the players the game's own counter skips (vfuncs `+0x2bc` and `+0x16c`) and counts the others with `FUN_015440e0`. Players already under contract with the club (`FUN_01545810`) are exempt unless flag 2 is set.

**Confidence of the optional patches:** medium. Specifically:
- The offer gate's reason text is unconfirmed.
- `FUN_0089bbf0` has its own gates (AI-manager flag `+0xc4` bit 0, contract type), so human clubs shouldn't be affected. **Guess**: not confirmed.
- I don't know how often `FUN_006296b0` runs; the trace counts it.

## Verification

- **Original bytes** at every site are checked against `original/fm.exe`.
- **Overlaps.** No byte overlaps with any other `patches_*.py`, bosman and clauses included. Inside this module the only shared bytes are between deliberately exclusive pairs: `_rules`/`3_plus_2` share the `FUN_01063090` hook site, and `nostalgia_foreign_cap`/`_ai` share the checker and the AI site. patch.py refuses to combine either pair.
- **No game branch targets the middle of a patched range.** For the counter case at `01606539` I also checked the switch table.
- **Disassembly** was checked with capstone ([verify_capstone.txt](verify_capstone.txt)) and in Ghidra ([verify_3p2.txt](verify_3p2.txt), [verify.txt](verify.txt)).

## Squad snapshots (`tools/squad_snapshot.py`)

Run `python tools/squad_snapshot.py reports/foreign_cap "Manchester City" "Arsenal" "Chelsea"` against the running game. It is read-only.
- **When it runs:** on the game's main thread, inside a one-shot hook on user32 `PeekMessageW`/`GetMessageW` (the message loop), so no game code is mid-way. Then it detaches. NativeFunction calls use Frida's exception catching.
- **Finding clubs:** it enumerates the database's club table (`[[0x02428ee0]+0x14]+0x40`, the in-game list; `+0x34` in the editor) and names each club's first team.
- **Names:** formatted with the game's own text formatter: `FUN_0188f4b0` constructor, `FUN_0188fd00` set format, `FUN_01493e80` add an argument, `FUN_01890790` render, `FUN_0188fc80` destructor. The formats are `<%team#1>`, `<%person#1>` and `<%nation#1>`; the rendered string is UTF-16 at buffer `+4`.
- **Per player:**
  - team; name and age
  - nationality, and other nationalities of the types the foreign test uses (7, 8, 9, `0x65`)
  - foreign, by the game's test relative to the club (`FUN_015440e0`)
  - homegrown-in-nation status (`FUN_016033c0`)
  - value (`+0xc0`)
  - squad status (contract `+0x30`) and transfer-status flags (contract `+0x32`: bit 0 listed, bit 3 loan-listed, bit 7 marked)
  - contract type
  - wages for the rest of the contract (`FUN_0047ca40`, used as the wage figure)
  - contract dates: `+0x20` start, `+0x24` end, `+0x28` joined the club
  - foreign value rank, and skip flags (retired-like, away or on loan, move arranged)
- **Not decoded:** the weekly wage itself, appearances, previous club and fee.
- **Summary:** domestic and foreign counts, first-team domestic players, surplus beyond 5, listing counts, and foreigners who joined since the start of the season.
- **Placeholder players:** reserve and youth teams contain about 30 placeholder players per club (generated names, no contract, flagged "retired?"). The game's own squad counter skips them too.

## Runtime check

Run `python tools/trace_foreign_cap.py reports/foreign_cap/trace.txt 15` after the loader has applied the patches.

| Line | Meaning |
|---|---|
| `surplus: listed for sale`, `surplus: listed for loan`, `surplus: not listed (reason)` | The surplus ladder's listings and skips |
| `check ai target / offer / surplus -> over cap` | The checker's decisions, by caller (offer = the AI offer gate) |
| `surplus release: full F, settled S (P%)`, `surplus releases (count)` | Releases of unsold surplus foreigners, with both amounts |
| `offer accepted for a loan-listed player: offer type T` | Offers accepted for players listed for loan, by offer type (loans show their own type) |
| `transfer listing reason 0xf from 0x89be80`, `squad status set to 7 by transfer listing` | Surplus listings and their status change. A later `squad status set to N by <caller>` for the same players would indicate a reset. |
| `bid valuation / value = 1.00 (listed)` against `(not listed)` | How the selling club prices listed and unlisted players in AI bid evaluations |
| `mode: 3+2 ON ...` | Which patches are present |
| `fixture list from FUN_01062190: size n 0x4<=5(cmp -1) 0x4[non-assimilated]<=3(cmp -1)` | The rules are injected |
| `AI selector rules: ...` | Whether the AI selector's lists contain them. If they don't, the AI ignores 3+2. |
| `rule 0x4[non-assimilated] value 3 count C from <caller> -> ok/broken` | Which code evaluates the rule, including human selection checks |
| `check ...`, `surplus: AI transfer-listed a foreigner`, `AI squad review ran` | Activity of the optional patches |

## In-game test steps (3+2)

1. **Start a new nostalgia career** and run the tracer. `stored rules (club use): size n ... 0x4<=5(cmp -1) 0x4[non-assimilated]<=3(cmp -1)` should appear for each league or cup group, and `fixture list from FUN_01062190` lines should carry the same rules.
2. **Check the badge.** Open your squad: foreigners show 'Fgn' natively, while English, Welsh, Scottish, Northern Irish and game-domestic players don't.
3. **Check the rules screen.** The Premier League's Rules screen shows "Maximum of 5 foreign players" and "Maximum of 3 foreign players" (from `nostalgia_3_plus_2_ui`).
4. **Check match selection.**
   - Name 4 non-assimilated foreigners: the squad should be flagged or refused (`rule 0x4[non-assimilated] value 3 ... -> broken`).
   - 3 non-assimilated plus 2 homegrown-in-nation foreigners should be accepted.
   - A 6th foreigner should be refused.
5. **Holiday a few weeks.** AI teams should name at most 3 foreigners, with no forfeits or illegal squads.
6. **Save, quit and reload in nostalgia mode.** The tracer's `stored rules` lines should show the two rules already there. No duplicates should appear, and the `[non-assimilated]` marker should be present, restored on first use if the save dropped it.
7. **Registration** (the EPL 25-man and homegrown rules) behaves as before.
8. **Optional: load the same save in vanilla mode.** Foreigners still show 'Fgn'. Match squads are limited to 3 foreigners in total, because the assimilated exemption needs the counting hook.

## In-game test steps (AI surplus)

1. Holiday a few weeks with the nostalgia set. Every surplus foreigner at an AI club should be transfer-listed and loan-listed. `surplus: listed for sale` should roughly match the `check surplus -> over cap` count, apart from the `not listed (...)` reasons.
2. Those players should show squad status "Not Needed", with asking prices close to their listed value. Check the trace's `bid valuation / value` ratios for listed players.
3. Bid about 50% of a surplus foreigner's value. Expect a counter-offer rather than a flat rejection; 98% should be accepted.
4. Let an unsold surplus foreigner's contract run out. He should leave on a free (`nostalgia_retain_on_expiry`), not roll over.
5. Watch for `squad status set to` lines from callers other than the transfer listing, for players listed earlier.
6. Loans: some surplus foreigners should go out on loan (`offer accepted for a loan-listed player`). They then drop out of the ladder while away.
7. Holiday past 30 June or 31 December. Surplus foreigners listed since January or July and still unsold should be released. Check the news, the club's finance screen, and the `surplus release: full ..., settled ...` lines: the paid amount should be the settled one, 20–75% of the full one. Keep an eye on big clubs' balances.

## In-game test steps (domestic-aware AI)

1. Apply the updated `nostalgia_foreign_cap_ai`, then run the snapshot for City, Arsenal and Chelsea. Repeat after a few weeks and at the end of the window.
2. AI clubs with fewer than 15 domestic first-teamers should sign no new foreigners. The `foreigners who joined since` line should stay empty for them. The tracer should show `check ai target -> over cap` and `check offer -> over cap`, with `offer validity -> result 2 reason 0x29` for AI offers.
3. Foreigners beyond each short club's 3 most valuable should be listed and loan-listed, and released at the June or December checkpoint.
4. See whether short clubs sign English players instead, and whether their first-team domestic count rises.
5. Your own club must be unaffected: bids for foreigners still go through.

## Files

These are raw dumps and are gitignored.

| File | Contents |
|---|---|
| `core.c`, `count.c` | Legality and counting code; `FUN_01605ae0` |
| `getter.c`, `copy.c`, `misc.c` | Rule-list builders and per-club adjustment |
| `select.c` | Squad selector, match legality and the AI registration fixer |
| `users.c`, `gates*.c`, `offer_users.c` | Transfer-time checks |
| `surplus.c`, `setlist.c`, `squadreview.c`, `listing*.c`, `price*.c`, `valuation*.c` | AI transfer listing (`FUN_00e5f250`, `FUN_0089bbf0`, `FUN_006296b0`) |
| `squads_*.txt` | Squad snapshots (`tools/squad_snapshot.py`) |
| `verify*.txt` | Patch verification |
