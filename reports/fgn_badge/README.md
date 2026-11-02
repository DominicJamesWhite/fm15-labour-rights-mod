# Nostalgia mode: showing 3+2 in the UI ('Fgn' badge and rules screen)

**Update:** `nostalgia_3_plus_2` now stores its rules in the competitions' stored lists (see [../foreign_cap/README.md](../foreign_cap/README.md)). The 'Fgn' badge is therefore set natively by `FUN_00dbc070`, and the badge cave has been dropped from `nostalgia_3_plus_2_ui` (its code is kept in the module). The rules-screen part is still needed, because `FUN_01064160` hides match-day types.

`nostalgia_3_plus_2` puts its two rules (`0x04` ≤ 5 foreigners, and a marked `0x04` ≤ 3 that skips players homegrown in the nation) only into the per-call copies of each club's match-day rule lists. Match selection and the AI therefore follow 3+2, but the UI reads the competition's **stored** rules, which are unchanged. So in England and similar leagues no player gets the 'Fgn' badge, and the rules screen doesn't mention the limit.

`nostalgia_3_plus_2_ui` (in [patcher/patches_foreign_cap.py](../../patcher/patches_foreign_cap.py)) fixes both, for display only. fm.exe 15.3, Ghidra VAs. **Untested in game.**

## How the 'Fgn' badge is decided

- **The text.** 'Fgn' is translation id `0x37ac6` (228038), with tooltip `0x37ac7` "Foreign", in `data/languages/english.ltc`. The `.ltc` file has an index at the end: `{u32 id, u32 offset, u8}` entries starting at file offset `0xde4579`, and string data at offset + `0xe`. Next to it are 'HG' `0x37acc` (home-grown at club) and `0x37ace` (home-grown from same nation as club).
- **The icon code** (`01e47ef7`, a per-flag icon/tooltip switch) shows 'Fgn' when the player's status flag word `+4` has bit `0x1000000` (tooltip "Foreign") or `0x2000000` (tooltip `0x5d68a`, the non-EU variant). 'HG' is `+4` bit `2` or `4`.
- **The flags** come from `GAME_PLAYER_STATUS_FLAGS` (vftable `020f7b3c`), slot `+0x1c` = `FUN_006ff040`. That also sets the other icons (Inj, Lst, Loa, Cup, Wp, and so on). Its rule part is `FUN_00dbc070` (called at `006ffb38`; Ghidra lists no caller):
  - **The rule list** is the competition's *stored* list, `[rule_group+0x34]`, through `FUN_0050d910` → `FUN_00fe9890(comp, team)`. It is not a per-club copy.
  - **Early exits** (`00dbc5c5`–`00dbc5e8`): no list, no team, a national team (`team+0x23 == 1`), or FM Classic's "no foreign restrictions" unlock.
  - **The loop** visits each rule that `FUN_00f8aba0(mode)` accepts: match-day types in mode 1 (the normal case), other types in mode 2.
    - For a foreign type (`FUN_00f8a050`; `0x04` is one), it calls `FUN_01605ae0(type, team, …)`. If that's non-zero, it sets `+4 |= 0x1000000` (Fgn).
    - For a non-EEC type, it sets `0x2000000`. Homegrown rule types (`0x26`, `0x27`, `0x91`, `0x92`, `0x59`, …) set the HG bits.
- **So:** Fgn appears only in competitions whose stored data has a foreign rule (Russia and others), and only for players the rule would count.
- **The foreign test.** For type `0x04` (also `2`, `3`, `0x15`, `0x7e`), `FUN_01605ae0` reduces to `FUN_015440e0(person; team, 1, 1)`, at `01606539`. That's the same test the 3+2 rule counts with: Welsh, Scottish and Irish players are domestic in England, as are long-serving players such as Yaya Touré, and EU nationals are foreign.

## How the competition rules screen is built

- **The panel** (`FUN_0048bdf0` → `FUN_00692cf0` → `FUN_009bd990`) deserializes a list of rule records and formats each one with `FUN_011b71a0`. Record type `0x28` holds a list of squad-selection rules, each described by `FUN_00f844e0`. For a type-`0x04` maximum the description is `0x3eae4` "Maximum of [N] foreign players" (`0x49741` when N = 1).
- **The records are written** by `FUN_01064160` (thiscall on a rule group, called from `FUN_010142e0` and `FUN_0103f4c0`):
  - It deep-copies the rule group's `+0x34` list into a local vector.
  - It **erases the match-day types** (`FUN_00f8a4a0`), plus `0x7e` and `0xa7`.
  - It writes the rest as record `0x28` (`FUN_011b3910` at `010642cc`).
  - On exit it frees the copy's rules through the `SQUAD_SELECTION_RULE` pool.
- **Registration screens** use the registered-squad lists (`FUN_011a6b90`). 3+2 is a match-day rule and is deliberately not added there, so registration is unaffected.

## The patch: `nostalgia_3_plus_2_ui`

| Part | Site (original bytes) | Cave | What it does |
|---|---|---|---|
| Badge | `00dbc7ac` `8b 44 24 10 3c 02` (`mov eax,[esp+0x10] ; cmp al,2`, right after the rule loop) → `jmp` + `nop` | `020c1fc8`–`020c1ffd` (54 bytes) | If neither Fgn bit is set yet and `FUN_015440e0(person; team, 1, 1)` says the player is foreign, sets `+4 |= 0x1000000`. ECX (the list, used next) and EDX are preserved, and the replaced code is replayed before jumping to `00dbc7b2`. Applies only where the original code reached the loop (clubs, competitions with a stored rule list, no FMC unlock). |
| Rules screen | `010642b2` `8b 5c 24 60 8b c6` (`mov ebx,[esp+0x60] ; mov eax,esi`, just before the `0x28` record is written) → `jmp` + `nop` | `020c1840`–`020c18ad` (110 bytes) | If the stage's competition (`[[esp+0x60]+0x3c]`) has a nation (`+0x44`, i.e. a domestic league or cup, not an international one), appends `{0x04, ≤5}` and `{0x04, ≤3}` to the *local copy*. The rules are allocated from the game's rule pool, as `nostalgia_3_plus_2` does, and freed by the function's own cleanup. The cached begin/end (EDI/ESI, `[esp+0x10]`) are reloaded. The screen shows "Maximum of 5 foreign players" and "Maximum of 3 foreign players" under the squad rules. |

**Cave placement.** The badge cave leaves `020c1f5b`–`020c1fc7` free so that `CHECK` (which ends at `020c1f5b`) can grow. The rules cave sits in the unused gap between `JOIN_CAVE` (asserted to end ≤ `020c1840`) and `INJECT_CAVE`/`P32_INJECT_CAVE` (`020c18d0`). Module asserts guard both.

**Verification** ([verify_capstone.txt](verify_capstone.txt)):
- **Original bytes** match `original/fm.exe`.
- **Disassembly:** both caves disassemble completely with capstone.
- **Overlaps:** none with `NOSTALGIA` (checked the way `tools/fm15_loader.py` does), nor with any other patch in any module.
- **Branch targets:** no branch in `FUN_00dbc070` or `FUN_01064160` targets the middle of a patched range.

## Does it change enforcement?

No, as far as the code shows:
- The status flags are the icon and status cache: the same object holds Inj, Lst, Cup and Ine. Selection legality, the AI selector and registration use the rule evaluators (`FUN_00f8a750`, `FUN_00f8c610`, `FUN_00852050`, `FUN_007f85f0`), not these bits.
- The rules-screen rules exist only in a local copy that is serialized for the panel and then freed.
- Saved data (stored rule groups) is never written, so saves stay clean, and removing the patch removes the display.

**Residual risk:** `0x1000000` is a common mask. A static search can't rule out a squad-view filter or column reading the same bit, but that would only be UI, such as a "foreign players" filter now matching.

## Limitations

- **The badge shows every foreigner**, i.e. the ≤ 5 rule. It doesn't show who is "assimilated" (homegrown in the nation, exempt from the ≤ 3). A follow-up could set the HG-nation bit (`+4 & 4`) for those players using `FUN_016033c0`.
- **The rules screen** shows two plain "Maximum of N foreign players" lines. There is no string for "not counting assimilated players".
  - International competitions (no nation, e.g. the Champions League) don't get the lines, though 3+2 does apply in their matches.
  - A competition whose squad-rule section was empty now shows one with these two lines.
- **The flags may be cached.** The badge may only appear once the game recomputes a player's status, after continuing a day or reopening the screen.
- **The Frida probe** (`fgn_probe.py`/`.js` here, read-only; it hooks `00dbc7ac` and logs list types, the Fgn bits and the foreign test) saw no calls in 150 s while the game was idle, so runtime behaviour is unconfirmed.

## In-game test steps

1. Load with `NOSTALGIA` + `nostalgia_3_plus_2_ui`, open your club's squad screen and continue one day.
   - Foreign players should show 'Fgn' (tooltip "Foreign").
   - English, Welsh, Scottish and Northern Irish players should not, nor should players the game treats as domestic (compare `tools/squad_snapshot.py`'s "foreign" column).
2. Open a Russian club's squad. The badges should look as before (data rule; no duplicate icons).
3. Open the Premier League's Rules screen, under squad rules. Expect "Maximum of 5 foreign players" and "Maximum of 3 foreign players".
4. Check registration (EPL 25-man and homegrown) still behaves as before: no new foreign limit at registration.
5. Pick 4 non-assimilated foreigners for a match. The game should still warn or refuse as before; this patch doesn't change that.
6. Optional: `python reports/fgn_badge/fgn_probe.py out.txt` while browsing squads. It shows `fgnbits` and `isForeign` per player.
