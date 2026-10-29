# FM15 squad-registration rules

Research for removing football-only registration rules (homegrown quotas, foreigner limits, squad caps, age rules) while leaving work permits alone. fm.exe 15.3; addresses are Ghidra VAs (image base 0x400000). Nothing here has been tested in game.

## How the rules work

**Rule objects.** A competition or rule group has a list of pointers (at `+0x34` of the rule-group object, plus nested lists such as `fixture_rules`) to 16-byte rule objects, created by the loader `FUN_011c8170`:

| Offset | Field |
|---|---|
| `+0x8` | value (int, default 1000; can come from a `cash` tag for wage caps) |
| `+0xc` | type (u16, enum below) |
| `+0xe` | compare (byte): `0xff` = less_than (a maximum), `0` = equals, `1` = more_than (a minimum). Values 2 to 5 and `0xfe` exist internally and always count as satisfied. |

**Type names.** These come from the game's own enum table at `0x02193018` (`{name, value}` pairs). All 168 are in [rule_types.txt](rule_types.txt). The compare-type table sits just before it.

**Evaluation.** Everything goes through one module at `0x00f89xxx`–`0x00f8exxx`:

| Function | Role |
|---|---|
| `FUN_00f8a750` (thiscall, ECX = rule, `ret 8`) | **"Is this rule satisfied for count N?"** Maximum: N ≤ value. Minimum: N + slack ≥ value. It has 15 callers, including the squad and registration legality check `FUN_007f85f0`, which loops over every rule and is called from 9 places, among them `FUN_00b9c670`, used by the offer-acceptance code. |
| `FUN_00f89f40` | Types that apply to the starting XI |
| `FUN_00f8a050` | Foreign-player types |
| `FUN_00f8a150` | Loan types |
| `FUN_00f8a240` | Non-EEC types |
| `FUN_00f8a320`, `FUN_00f8a3b0` | Bench types |
| `FUN_00f8a4a0` | Matchday types |
| `FUN_00f8a670` | Goalkeeper types |
| `FUN_00f8a8a0` | Age bound for a type (min and/or max age) |
| `FUN_00f8aa80` | Maps a bench type to its matchday-squad type |
| `FUN_00f8b370` | Load-time cleanup that merges or removes redundant rules. Only called from database loaders (`010xxxxx`–`011xxxxx`, `01064c40`). |
| `FUN_00852050` | Called by `SQUAD_SELECTOR::select_squad_of_players`. Turns each rule into a constraint for the AI's matchday selection (`FUN_00f8c270`). It skips starting-XI types. |
| `FUN_00f8ba60` (16 callers) | Reads a rule's value directly to work out "places left". It does **not** go through `FUN_00f8a750`. |

**Not the evaluator:** `FUN_00e84cc0` builds the text for a news item (work-permit or appeal style), and `FUN_008210f0` is UI navigation. `FUN_0054d150` uses a different enum.

## Rule types by group

There are 168 types in total; see `rule_types.txt`. The groups below are what the patches use.

| Group | Types | Football-only? |
|---|---|---|
| **Homegrown / club-trained** | `0x26`/`0x27` homegrown 15–21 from club/nation; `0x58`/`0x59` from club/nation in match squad; `0x67` non_homegrown_players_in_squad; `0x80`/`0x81` in XI; `0x91`/`0x92` from club/nation (registered squad) | **Yes.** These are UEFA and league rules (the EPL's 8-of-25, UEFA's club- and association-trained). |
| **Nationality quotas** | Game's foreign set `0x02 0x03 0x04 0x15 0x34 0x35 0x3c 0x41 0x72 0x7d 0x7e 0x8a 0xb4 0xb6 0xc1 0xc6`; foreign GKs `0x28`; Chinese `0x2e 0x33`; Hong Kong `0x3d 0x47`; non-Canadian `0xae`; same nation `0xd4`; minimums of national players `0x13 0x14 0x69 0x71 0xbe 0xd1` | **Yes.** These are league quotas based on nationality, not state law. Note that this group is about nationality: removing it means clubs can field any number of foreigners. |
| **Non-EU / non-EEC limits** | Game's non-EEC set `0x05 0x06 0x07 0x12 0x53 0xa7 0xb5 0xb7`; `0x1e` non-EU players signed from abroad per season; `0x21` italy_non_eu_players_allowed_for_club | **Ambiguous.** They're league rules, but they follow EU free-movement law, and Italy's non-EU signing quota mirrors a government quota on non-EU sports visas. That's why they're a separate group. |
| **Squad size cap** | `0x09` max_squad_size, `0xa9` outfield_players_in_squad | **Yes.** `0xa5` min_squad_size and the goalkeeper minimums (`0x57`, `0x5a`, `0x40`) are left alone on purpose. |
| **Age quotas** | Every type with an age bound (`FUN_00f8a8a0`), *minus* those that are also nationality, non-EU or loan types. Full list in `patches_squad.py`. | **Yes**, but they also *define* youth competitions (U21 and U23 leagues, over-age limits). Turning them off lets senior players into youth leagues. |
| **Salary cap** | `0x00`, `0x46`, `0x6e` yearly wage caps; `0x5d` foreign wage cap; MLS `0x37 0x6d 0xc5`; A-League marquee `0x6f 0xb2 0xb3` | **Yes** (MLS and A-League). Whether wage caps are enforced through `FUN_00f8a750` is a **guess**. |
| Loans | `FUN_00f8a150` set | No patch, since loans are already abolished. |
| Not grouped | Cup-tied or registered-elsewhere (`0x2f 0x4a 0xaf`), trialists (`0x4b 0x68`), discovery players (`0x0a 0x0b`), `0x01`/`0x25`/`0x32` senior/transitional internationals, goalkeeper and minimum-size rules, MLS roster slots (`0xac 0xb1`), and unnamed `0x7d`/`0x7e`/`0xa7`/`0xd8` (grouped only where the game's own type sets put them) | Left as they are. |

**Example from the data.** Parsed with [tools/cbd.py](../../tools/cbd.py); the dump is in [comps_rules_dump.txt](comps_rules_dump.txt). Stream 42 has `goalkeepers_in_squad` ≥ 3, `min_squad_size` ≥ 23, `max_squad_size` ≤ 28, and per-fixture `all_foreign_players_in_match_squad` ≤ 5 and `over_23_players_in_match_squad` ≤ 3.

**Caveat about the data:** `comps.dbc` only holds rules for 10 nation and competition records. The big leagues' rules, such as the EPL's 25-man and homegrown rules, must be in the main database (`data/db/1530/`), which isn't parsed yet. The code patches don't depend on any of that.

## Patches (`patcher/patches_squad.py`, not in DEFAULT)

**`squad_rules_core`** (required for any group to have an effect):

| Part | Address | What it does |
|---|---|---|
| Checker | `020c1570` | `test eax,0xffffff00; jnz done; bt [bitmap_i],eax; jc done` for each of the six bitmaps, then `ret`. Sets CF if the rule type is disabled. |
| Hook A | `00f8a750` → `020c15b0` | Disabled types return 1 ("satisfied"). Otherwise it re-runs the three replaced instructions and jumps back to `00f8a757`. EAX is saved and restored, and the stack is unchanged. |
| Hook B | call at `0085216f` → `020c15d4` | Disabled types return "starting-XI type", so the AI selector skips them. Otherwise it tail-calls `FUN_00f89f40` with the same argument. |

**Group patches:** each one writes a 32-byte bitmap and nothing else.

| Patch | Bitmap address |
|---|---|
| `no_homegrown_quota` | `020c1420` |
| `no_nationality_quota` | `020c1440` |
| `no_non_eu_limit` | `020c1460` |
| `no_squad_size_cap` | `020c1480` |
| `no_age_quota` | `020c14a0` |
| `no_salary_cap` | `020c14c0` |

A group without the core does nothing, and the core without any group changes nothing.

**Checks done:**
- All the patch code lives in the zero padding at the end of `.text` (`020c1414`–`020c1600`), clear of the notice cave at `020c1500`–`020c1569`.
- Original bytes are checked against `original/fm.exe`.
- A combined build of DEFAULT plus every squad group applies with no overlaps (`patched/squad_test.exe`), and the DEFAULT build is byte-identical to before.
- The core patches disassemble correctly in Ghidra ([verify.txt](verify.txt)).

**Effect on existing saves:** these are code patches that test each rule when it's evaluated, so they apply to existing saves. The rules stay in the save, so removing the patch brings them back.

**Confidence:**

| Group | Confidence |
|---|---|
| Homegrown, nationality, non-EU, squad size | Medium-high that registration and selection legality stops enforcing them, since `FUN_007f85f0` and the transfer check go through `FUN_00f8a750` |
| Age | Medium |
| Salary cap | Low-medium |

## Risks and open points

- **"Places left" helper `FUN_00f8ba60`** reads rule values directly (16 callers). UI counters or AI planning that use it may still say "no foreign slots left", even though selection and registration now allow it. The trace below shows whether it matters.
- **AI behaviour:**
  - Hook B frees the AI's *matchday selection*.
  - Hook A frees legality checks, including transfers through `FUN_00b9c670`.
  - The AI's *transfer and squad planning* may still avoid players "for quota reasons" through other code that hasn't been traced, so the AI might keep following quotas voluntarily.
- **UI:** the squad registration screen will probably stop flagging broken rules where it uses `FUN_007f85f0` / `FUN_00f8a750`. Rule descriptions such as "max 5 foreigners" will still show.
- **Youth competitions:** `no_age_quota` lets senior players into U21 and U23 leagues and lifts limits like "N under-21s on the bench". It's a design choice.
- **Two-stage rules:** `FUN_00f8b370` merges bench rules into match-squad rules at load time. Disabling a type at evaluation doesn't undo that merge, but merged rules use types from the same group (for example foreign-on-bench becomes foreign-in-match-squad), so they're disabled together.

## Runtime check (Frida, for the parent to run)

`python tools/trace_squad_rules.py reports/squad/trace.txt 10` while the game is running. It logs every `FUN_00f8a750` call as `type / compare / value / count / caller → result`, plus calls to the "places left" helper `FUN_00f8ba60`.

What to look for:
- **Without the patches:** which types get checked and from where, ideally with the squad registration screen and team selection open.
- **With the core plus groups:** disabled types should always show `-> 1`.

## What to test in game (after installing the core plus chosen groups)

1. **EPL squad registration:** register more than 17 non-homegrown players. There should be no error and the squad should still be accepted at the deadline.
2. **League with a foreigner limit** (stream 42 above, or Russia/Turkey): pick more foreigners in the matchday squad than allowed, and check the match plays without an "ineligible squad" block.
3. **Max squad size:** register more than 25 players, or 28 in the stream 42 league.
4. **Work permits:** check they still apply. A non-EU signing to England should still need one.
5. **AI:** over a season, check whether AI clubs field more foreigners or non-homegrown players than the old limits allowed.
6. **Places-left UI:** whether "places remaining" counters still show the old limits.

## Files

- [rule_types.txt](rule_types.txt): the enum
- [comps_rules_dump.txt](comps_rules_dump.txt): rules in `comps.dbc` by stream
- [module.c](module.c), [readers.c](readers.c), [cleanup.c](cleanup.c) and [f8a750_callers.c](f8a750_callers.c): decompiled code
- [sites_asm.txt](sites_asm.txt), [sites_asm2.txt](sites_asm2.txt), [verify.txt](verify.txt): assembly and patch verification
- [tools/cbd.py](../../tools/cbd.py): `.dbc` parser, which now handles every stream (adds types `0x04` and `0x0f`, the null-terminated UTF-16 strings, the 12-byte stream header and the `fmf.` sub-header before the last stream)
- [tools/trace_squad_rules.py](../../tools/trace_squad_rules.py) and its `.js` agent
- Ghidra scripts `SquadFindEvaluator`, `SquadImmediates`, `SquadRuleReaders`, `SquadListRange`
