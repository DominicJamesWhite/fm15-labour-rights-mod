# FM15 league and registration rules: reference map

Research notes for future mods (fm.exe 15.3, built Apr 2 2015). Addresses are Ghidra VAs (image base 0x400000).
Nothing here has been tested in the game. **Guess** marks inferences that aren't confirmed.

## Summary

| Area | Where it lives | Easiest lever | Difficulty |
|---|---|---|---|
| Work permits | Data (per-nation `work_permit_rules` in `data/comps.dbc`) plus one code check | Patch `FUN_00eb28f0` to return "no permit needed" (`patches_rules.py: no_work_permits`) | Easy (patch written) |
| Foreigner / non-EU restrictions | Code (player-status function `FUN_00dbc070`) | Force FM Classic's "no foreign restrictions" branch (`no_foreign_restrictions`) | Easy (patch written), effect needs checking in game |
| Squad registration (size caps, homegrown, age rules) | Data (`squad_selection_rules`, `max_squad_size`, `min_squad_size` per competition in `comps.dbc`) | Edit `comps.dbc` (format below) or find the rule-type evaluator | Medium |
| Transfer and contract rules per nation | Data (nation rule records in `comps.dbc`) plus 55 per-nation `*_TRANSFER_RULES` C++ classes | Edit `comps.dbc` | Medium |
| FM Classic "game changers" | Code flags | Reuse as on/off switches (table below) | Easy to read; per-human flags need care |

## 1. Work permits

**Decision function.** `FUN_00eb28f0(rules, person, club)`, cdecl with a plain `ret`, returns true when a move needs a work permit:
- `rules` comes from `FUN_00fd83b0(club)`, which looks up the `TRANSFER_RULES` object for the club's nation (via `+0x4c`). That function has more than 100 callers.
- It returns false if `DAT_0239244d` is non-zero. That's a widely read game-state flag, **guess**: "no active game / database loading". It is not a permit switch.
- It returns false if the nation's permit list at `rules+0x7c..+0x80` is empty, meaning that nation has no permit rules.
- Otherwise the result depends on `FUN_01545010` and `FUN_01543dd0`, the nationality and exemption checks (**guess**: EU membership, caps and so on).

**Callers fall into two families:**
- **Ungated:** `00a11570`, `00b04e20` and `00f27c10`. These are probably the full-FM paths.
- **Gated by `DAT_02392458`:** `009502f0` (applies for a permit and creates `WORK_PERMIT_DECISION_NEWS` via `FUN_01eeb7d0`), `00b11510`, `00a29140` (creates the "awaiting work permit" record), `00af8c90`, `00cc9540`, `00e7f3e0` and `01f35c50`.

**`DAT_02392458` is FM Classic store item 6, "no work permits":**
- It's 0 in the exe's `.data` section, and the only writer is the store handler (`SETNZ` at `01f3b2bf`).
- Its readers treat 0 as "no permit needed", and the store's state query reports the unlock as active when it's 0.
- **Open question:** how full-FM permits are enforced while this flag is 0. Either the ungated callers are the real full-FM path, or the flag gets set at runtime by a route not found statically. A one-byte read of `0x02392458` in a running full-FM game would settle it.

**Patch `no_work_permits`:** in `patcher/patches_rules.py`. It changes file offset `0xAB28F0` from `8b 4c 24` to `32 c0 c3` (`xor al,al; ret`). Every permit path goes through this function, so this should remove permits everywhere, including the "awaiting permit" and decision news. Confidence: medium-high. Untested.

**Data side.** Each nation's rule record in `comps.dbc` has a `work_permit_rules` struct, with:
- `initial_with_permit`, `initial_without_permit` and `contract_renewal` sub-records, each holding `decision_date` and `type`
- `work_permit_days_to_wait`

Editing this data (removing the rules or emptying the list) would be the clean "data only" alternative, but it only takes effect in new games.

**UI and news classes:** `APPLY_FOR_WORK_PERMIT_ACTION` (vftable `020cb038`, built in `01de1650`), `WORK_PERMIT_DECISION_NEWS` (`0210943c`), `WORK_PERMIT_DECISION_RESPONSE` (`02121294`), `AWAITING_WORK_PERMIT_NEWS` (`02120784`, constructor `00b009f0`), and the `ask_for_work_permit_dialog` string (referenced at `00a3dede`).

## 2. Foreigner and non-EU restrictions, homegrown status

- FM Classic store item 9, "no foreign restrictions", sets the byte at `+0x34` of the object returned by `FUN_011a5a50()`, which is `*(*(DAT_024257fc+4)+0x34)`. Store state query: `FUN_0096d1d0`.
- Of the 12 callers of `FUN_011a5a50`, only **`FUN_00dbc070`** reads that byte. That function builds a player's per-competition status/eligibility bitfield (`param_7`):
  - bits `+8 & 0x400` and `+8 & 0x800` are set from `FUN_01604af0` and `FUN_01604b20`
  - bit `+8 & 0x4000` is set near the end
  - bits `+4 & 0x8000000` and `+4 & 0x40000000` are also used
  - **guess:** these are club-trained, nation-trained and foreign / non-EU flags
- At `00dbc5e4` it does `cmp byte [eax+0x34],0` then `jnz 00dbd2be`, the function's shared exit. When the unlock is on, everything after `00dbc5ee` is skipped.
- **Patch `no_foreign_restrictions`:** file offset `0x9BC5E8`, `0f 85 d0 0c 00 00` → `e9 d1 0c 00 00 90`, making that branch unconditional. Confidence: medium. It reproduces FMC's own unlock exactly, but which status bits stop being set needs checking in the game. Homegrown bits `0x400` and `0x800` are set *before* the branch, so homegrown status probably still works.
- Rule classes that take part: `PERSON_VALID_FOR_NATION_RULE`, `ELIGIBILITY_EXTRA_SQUAD_SELECTION_RULE@SICOMPS`, `AGE_EXTRA_SQUAD_SELECTION_RULE@SICOMPS`, `UNDER_AGE_PLAYERS_ELIGIBLE_EXTRA_SQUAD_SELECTION_RULE@SICOMPS` and `NUMBER_OF_PLAYERS_RULE_BASE`.
- Another reader of rule flags: `FUN_01e09680` checks a rule object at `param_1+0x34` with flags at `+0xc`, testing bits `0x2`, `0x80`, `0x400`, `0x800` and `0x40000`. **Guess:** the per-competition squad selection rule flags.

## 3. Where rules live: `data/comps.dbc`

**Container:**
- A 27-byte header: `02 01 'cbd.' 02 00 00 02 01 'fmf.' 04 00 00`, then the dword `0x0007532c` (unknown), then `09 00 00 00 01`.
- After the header come **481 back-to-back zlib streams** with no length prefixes. Read them with `zlib.decompressobj()` and its `unused_data`.
- Each decompressed stream is a `.cbd` record: `02 01 'cbd.' 02 00 00 01 00 00`, then a typed field list.
- **Open question:** the header dword. If it's a checksum or total size, it needs updating when writing the file back.

**Field encoding:**
- Each field is a four-character tag stored as a little-endian dword, so `vers` appears in the file as `srev`, followed by a type byte and then the value.
- Type bytes seen:

| Type byte | Meaning |
|---|---|
| `0x11` | u8 |
| `0x12` | u16 |
| `0x03` | bool |
| `0x01` | u32 or tag reference |
| `0x02` | u32 |
| `0x0a` | struct (u32 field count, then fields, starting with an `id` reference to the struct's own tag) |
| `0x0b` | list (u32 count, then items) |
| `0x00` | empty string |
| `0x06` | UTF-16 string, with a length prefix |

**Tag names.** `reports/rules/tags.txt` lists all 1,326 tags, extracted from the registration function `FUN_01522480`, which calls `FUN_00f5a8d0(tag, name)`. The columns are code order, in-file order and name. Rule-related tags include:

| Group | Tags |
|---|---|
| Nation rules | `work_permit_rules`, `initial_with_permit`, `initial_without_permit`, `contract_renewal`, `work_permit_days_to_wait`, `loan_rules`, `uses_bosman_rules`, `free_transfers_can_join_outside_window`, `loan_players_can_join_outside_window`, `main_contract_end_month`, `alternative_contract_end_months`, `full_contract_min_age`, `youth_contract_max_age`, `developmental_contract_max_age`, `min_age_for_senior_matches`, `release_fee_rules`, `max_player_rules`, `season_windows`, `pre_season_windows`, `mid_season_windows`, `transfer_windows` |
| B-club moves | `cannot_move_registered_over_23_player_to_main_club` and three related `cannot_move_*` rules |
| Competition and squad | `squad_selection_rules` (a list of `{type, value, compare_type}`), `max_squad_size`, `min_squad_size`, `recommended_squad_size`, `squad_selection_value`, `squad_selection_deadline_date`, `squad_number_registration_periods`, `youth_contract_players_can_play_in_competitive_fixtures`, `trialists_can_play_in_competitive_fixtures`, `max_players_to_exchange` |
| Money and discipline | `salary_cap_for_division`, `fine_percentage_overspend`, `discipline_rules`, `yellow_cards_threshold_for_match_fine`, `yellow_cards_match_fine_multiplier`, `red_cards_threshold_for_match_fine`, `red_cards_match_fine_multiplier`, and the corresponding `fine_for_*_limit_in_match` |

**How often they appear in `comps.dbc`:**

| Tag | Count |
|---|---|
| `work_permit_rules` | 20 (in streams 42, 91, 123, 134, 160, 183, 188, 380, 396 and 410) |
| `initial_with_permit` | 8 |
| `initial_without_permit` | 8 |
| `squad_selection_rules` | 57 |
| `max_squad_size` | 33 |
| `loan_rules` | 18 |
| `league_rules` | 157 |
| `rule_group` | 30 |
| `uses_bosman_rules` | 1 |
| `release_fee_rules` | 1 |

**Example** (stream 42): `max_squad_size = 28` with rules `{type 0x57, value 3, compare 1}`, `{type 0xa5, value 23, compare 1}` and `{type 9, value 28, compare 0xff}`.
- **Guess:** these are an age or "over N" limit and a registered-squad cap.
- The meaning of each rule type code needs the evaluator: find what reads `SQUAD_SELECTION_RULE@SICOMPS` type values (look for a switch on the rule type in the `RULE_GROUP_MANAGER@SICOMPS` / `GAME_RULE_GROUP_MANAGER` code).

**The nation `.dbc` files** in `data/db/1500/dbc` (such as English and Italian DBC) are database-change files with the same `.cbd` container but no rule tags. They hold people, clubs and fixes.

**Editing workflow** (not built yet):
1. Decompress every stream.
2. Patch values in place. Same-size edits are easiest, for example a u8 `max_squad_size`, a bool, or changing the count of a `squad_selection_rules` list.
3. Recompress with zlib.
4. Concatenate the streams after the header and resolve the header dword.

Rules are copied into the save when a new game starts, so data edits need a new game. Code patches also affect existing saves.

**Per-nation code:** 55 `XXX_TRANSFER_RULES` classes (`ENG_`, `ITA_`, `ESP_`, `USA_` and so on, plus `EUR_` and `NETWORK_`) derive from `TRANSFER_RULES@SICOMPS`. They mostly override vtable slot `+0x4`, which probably sets up per-nation windows and timings, and occasionally slots `+0x8`, `+0x24`, `+0x28`, `+0x3c` and `+0x58`. The base methods cover transfer-window date ranges (`+0x34` list) and small flags at `+0x94` and `+0x9a`–`+0xae`. See `reports/windows/tr_methods.c`.

## 4. FM Classic "game changers"

The store handler `FUN_01f3b130` uses item numbers that match the achievement IDs (`FUN_005276f0`):

| Item | Effect | Storage |
|---|---|---|
| 1 | No loan restrictions | global `DAT_0239245b` |
| 2 | No transfer windows | global `DAT_02392459` (already patched by `always_open_windows`) |
| 3 | No sacking | bit `0x2` at `+0x36c` of the human manager's object (via vfunc `+0x380`); readers include `00500b90` and `009a6630` |
| 4 | Not mapped | global `DAT_0239245a` |
| 5 | Not mapped | bit `0x8` at `+0x36c` |
| 6 | No work permits | global `DAT_02392458` (see section 1) |
| 7 | Son generated | `FUN_0188ee10` |
| 8 | All players interested | bit `0x1` at `+0x36c` |
| 9 | No foreign restrictions | byte `+0x34` of `FUN_011a5a50()` (see section 2) |
| 10 | Unlimited scouting | bit `0x4` at `+0x36c` |
| 12 | Attribute masking | bit `0x10` at `+0x36c` (inverted) |

The bits at `+0x36c` are per human manager or club, not global.

## 5. Other leads that fit the "football work vs normal work" theme

- **Salary cap:** the `salary_cap_for_division` tag, in data. MLS-specific code is likely too (`PERSON_MLS_CLUB_RIGHTS_RULE`).
- **MLS draft:** `DRAFT_OFFER` (offer type 8), `person_mls_declared_for_next_superdraft`, and `PLAYER_DRAFTED_FILTER_RULE`. Draft offers are accepted in `add_transfer_offer`'s type-8 branch (see the notice cave).
- **Italian co-ownership:** `COOWN_OFFER` (type 6) is evaluated by `FUN_00b05750`, which is reached from the AI dispatcher `FUN_01f331c0`.
- **Fines:** card-based match fines and the overspend fine are data (`discipline_rules`, `*_match_fine_*`, `fine_percentage_overspend`). Manager-imposed player fines weren't traced.
- **Staff and manager compensation:** not traced.
- **Nationality eligibility:** `PERSON_VALID_FOR_NATION_RULE`, `PERSON_IN_NATIONAL_POOL_RULE` and `valid_for_international_teams`.
- **Release fee rules:** a `release_fee_rules` tag in nation rules (one occurrence). This is relevant to the notice-period work.

## Files

- `README.md`: this file
- `tags.txt`: all database tags
- `strings.txt`: rule-related strings in fm.exe
- `rule_classes.txt`: RTTI rule classes
- `store_items.c`, `wp_flag.c`, `wp_core.c`, `wp_callers.c`, `foreign*.c`, `bit2_readers.c`, `achv*.{c,txt}`, `field_table.txt`, `dbc070_*.txt`, `member_36c.txt`, `game_30_writes.txt`, `flag_4d.c`: decompiled code and assembly dumps
- `data/`: copies of `comps.dbc` and two nation `.dbc` files, plus `*.raw` decompressed output
- `ghidra_scripts/RulesMemberAccess.java`: lists every instruction that touches `[reg+offset]`
- `patcher/patches_rules.py`: the `no_work_permits` and `no_foreign_restrictions` patches (not in DEFAULT)
