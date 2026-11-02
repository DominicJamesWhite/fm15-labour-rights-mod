# FM15 labour rights mod

A mod for Football Manager 2015 (Steam, version 15.3) that gives footballers roughly the same working rights as everyone else.

| Football rule | In this mod |
|---|---|
| Transfer windows | None: players can move at any time of year |
| Transfer fees | None: no fee, instalments, add-ons, sell-on clauses or friendly-match clauses |
| A club can refuse to sell | It can't. Every offer is accepted by the selling club, and the player decides in contract talks |
| Loans | Abolished |
| Paying out the rest of a contract | A club can release a player for at most two weeks' wages, mutual terminations included |
| Notice period | A move completes 14 days after it's agreed |
| Homegrown, nationality and non-EU squad quotas, and the squad size cap | Switched off |

National law still applies: work permits, and Italy's non-EU signings-per-season quota, which mirrors a government visa quota, are unchanged.

The AI is adjusted to match. It treats players as free to sign (but still budgets for signing-on and agent fees), it can approach any player, and it no longer plans around the old squad caps.

The switched-off squad rules are also removed from each competition's stored rules (`tools/squad_strip.js`, run by the loader), so they no longer appear on the rules screen, and the AI doesn't plan around them either. The only rule kept is Italy's limit on non-EU players signed from abroad per season (`0x1E`). Players no longer show the "Fgn" and homegrown badges.

## Rule sets

The launcher (`Launch FM15 (modded).bat`, or `tools/launcher.pyw`) asks which rules to start FM15 with:

| Mode | Patches |
|---|---|
| Vanilla | None |
| Labour rights | `patch.py` `DEFAULT`, described above |
| Nostalgia | `patch.py` `NOSTALGIA`: football before the 1995 Bosman ruling, below |
| Parity | `patch.py` `PARITY` plus the agents in `MODE_AGENTS["parity"]`: labour rights with money redistributed between clubs and knockout continental cups, below |
| Custom | Any combination of the rule groups in `patch.py` `CUSTOM`, ticked in the launcher or passed as `--custom fees,foreign3` |

Patches stay in memory until FM15 quits, so to switch rules, quit and start it from the launcher again.

The custom groups are: no transfer windows, no transfer fees, no loans, two weeks' notice, no football-only squad quotas, pre-Bosman contracts, 3 foreign players, redistribution, and knockout continental cups. Ticking the first five gives Labour rights; adding the last two gives Parity. Some groups depend on or clash with others, and the launcher keeps the ticks consistent:
- Two weeks' notice needs no transfer fees. A club that must accept every offer could otherwise be bought for a token fee.
- Pre-Bosman contracts can't be combined with no transfer fees or two weeks' notice, because both zero the compensation those contracts rely on.
- With both 3 foreign players and no squad quotas, the nationality quotas stay on, because the 3-foreigner rule is one of them.

### Nostalgia mode

Football before the 1995 Bosman ruling, following the historical rules where FM15 allows it.

| Rule | In this mode | Patch |
|---|---|---|
| End of contract | A contract the club doesn't release rolls over a year on the same terms (Belgium's pre-Bosman rule), so a wanted player can only leave for a fee. The human releases players from the contracts-expiring news; AI clubs let "Not Needed" players go | `nostalgia_retain_on_expiry` |
| Out-of-contract and pre-contract moves | Compensation is due at any age and to any country (vanilla: only young players, some countries). Pre-contracts stay allowed, but cost that fee | `nostalgia_compensation_any_age` |
| Foreign players | At most 3 foreigners in a match squad, in every league. The rule is stored in each club competition's own rules and saved with the career. "Foreign" is the game's own test: home nations and long-serving players count as domestic, EU players count as foreign. Clubs may own any number. The competition rules screen lists it | `nostalgia_3_foreigners`, `nostalgia_3_foreigners_ui` |
| AI squad building | The rule switches on the game's own "foreign-limited league" AI: one foreign target at a time, stricter foreign candidates, home first-teamers priced at 1.5x. On top of that: AI clubs keep their 3 best foreigners aged 21+ (by current ability) and list the rest for sale and loan as "Not Needed"; unsold ones are released twice a year with a 20–75% settlement. Under-21s are left to the game. Listed players drop out of the AI's squad plan, so the club looks for replacements. Anti-churn: a club with 3+ senior foreigners, one of whom joined within the last year, doesn't pursue or shortlist foreign targets, and isn't offered listed foreigners either. Upgrades only: a foreign target must have a higher current ability than the club's 3rd-best senior foreigner (any foreigner if it has fewer than 3); both conditions must allow. Transition until 1 September 2014: releasing a foreign player costs nothing (AI and human), and from 15 to 31 August 2014 AI clubs release their unsold listed surplus foreigners straight away. The ladder runs weekly (daily from 15 to 31 August 2014) for every team of every AI club, Under 21s included, so surplus parked in a youth side is listed and released like the rest. Home first-teamers at foreign-limited AI clubs are priced at 1.2x instead of the game's 1.5x | `nostalgia_foreign_cap_ai`, `nostalgia_ai_plan_without_surplus` |
| Transfer windows | None, as before 2002 | `always_open_windows` |
| Release clauses | Unchanged: they existed pre-Bosman (mandatory in Spain since 1985) | |

Optional extras, by name: `nostalgia_no_pre_contracts`, `nostalgia_no_release_clauses`, and the earlier foreign-cap designs `nostalgia_foreign_cap` (signing block) and `nostalgia_foreign_cap_rules` (plain 3 in match and registered squads). Neither combines with `nostalgia_foreign_cap_ai`.

Nostalgia mode hasn't been tested in game yet. While playing, `python tools/observe_nostalgia.py 240` reports whether windows, compensation, contract rollovers and foreign-player limits behave as intended, and `python tools/trace_foreign_cap.py reports/foreign_cap/trace.txt 15` traces the foreign rules in detail. Write-ups with test steps: `reports/bosman`, `reports/foreign_cap`, `reports/clauses`. Don't combine nostalgia patches with the labour-rights fee and notice patches, which zero the compensation.

### Parity mode

The labour-rights rules plus redistribution, aimed at competitive balance. Design and research are in `reports/parity` (start with `PLAN.md`).

| Rule | In this mode |
|---|---|
| League TV | Pooled. Each month, half of every club's league TV is shared equally by every club in that nation's pyramid, and a quarter equally within its league. The last quarter is shared by final position when the league ends (linear: the champion gets n shares, last place 1) |
| Gates and season tickets | 50% of league gates and season-ticket income is shared equally within the league |
| Commercial income | Above the league median, 75% of the excess is levied at each club's season rollover, half of it to the pyramid and half to the league. Commercial means sponsorship, merchandising and FM's "other income" deals. Owner money paid as sponsorship counts as owner money instead |
| Owner money | A luxury tax: owners may put in any amount, in any form (sugar-daddy payments, loss cover, bailouts, takeover money, overdraft clearance). The club keeps all of it as cash, and the owner pays 100% of it on top, shared equally by the nation's pyramid. Nothing is taken from the club's accounts, so FM's owners don't top up again to cover the tax. Bank loans, a parent club's subsidy to its B team and owner contributions to stadium builds are exempt. Owner money FM books as other income or sponsorship counts as owner money |
| Wage budgets | FM sets them from each club's existing wage bill and cash, not its revenue. At each club's season rollover and every month, the budget is set to 80% of the revenue the club kept last season (after its pool payments and the commercial levy due on that season), plus 20% a year of its cash in the bank. Owner money and loans are capital: they count only through the cash they leave, so an injection is written off over about five years as it's spent, and money that only covered losses adds nothing. The budget is lowered to that figure, but never below 0.8× the current wage bill or the league's median budget, and raised to it only while the club's balance isn't negative |
| Dividends, parachute payments | None |
| Virtual players | FM fills the squads of clubs it doesn't simulate in detail with generated "virtual" players. They're now rated as FM rates those of clubs in loaded leagues (half the reputation-based level, at most 90 before a +/-20 spread), so a club from an unloaded league is no stronger than an equal club from a loaded one (`parity_virtual_players_loaded_strength`) |
| National cups | Every senior cup, league cups included: single matches, extra time and penalties, no replays, the lower-division club at home. Gates are split 50/50, and each round's TV money is shared equally by every club in the round |

Only clubs in loaded leagues take part, because FM gives other clubs no real finances. Pool money goes out as Grants income, and payments in are booked as Other expenses. Nothing is held in memory, so quitting at any point loses nothing. While playing, the agent logs every settlement to `reports/parity_agent.log`.

Cup entry is left as FM has it. Restructuring cups so the top two divisions all enter in the same round was built, but it's switched off: it's the least important rule, and a crash followed the first restructured draws.

Continental cups (`tools/parity_continental.js`):

| Rule | In this mode |
|---|---|
| Format | One knockout stage: two legs per round where FM's own data plays two legs, a one-match final (extra time and penalties), random draws with country protection in each club's first round |
| Primary cups (Champions League, Libertadores, AFC Champions League and the other confederations' champions' cups) | Each member nation's league champion and domestic cup winner (the losing finalist if the champion won both; the league runner-up where there's no cup), plus the title holder. Nations not loaded send a reputation-weighted pick from their top division. When the field isn't a power of two, the byes go to the league champions |
| Secondary cups (Europa League and the equivalents) | Two clubs per nation: the two best-placed top-division clubs not already in the primary cup. Nations not loaded send a reputation-weighted pick. (A 2nd–7th play-off, `tools/parity_playoff.js`, used to decide one place; it no longer builds new play-offs, because FM couldn't fit its finals in before the June entry, but stays loaded so saves holding a play-off still load) |
| Squad registration | Champions League and Europa League clubs are marked as first-qualifying-round entrants, so FM's own UEFA squad registration registers them at every deadline (before this fix it skipped them, and their unregistered players were replaced by virtual players) |
| Money | Every continental competition, super cups and the Club World Cup included, is settled once when it finishes: 40% equally to the clubs taking part, 40% to solidarity (an equal share per member nation, passed down its pyramid) and 20% by how far each club got. The total stays what FM would have paid, with the Champions League and Europa League TV pools worked out for the actual field |
| Nation strength | Once a year, when FM updates each confederation's nation strengths (the value its leagues' reputations are set from), every nation moves 5% of the way toward the confederation's median strength (at least 1 point, nothing within 2 points of the median, limits 5–190). No nation overtakes or ties another, and FM's own yearly ranking step still applies first. This slowly narrows the reputation gap between leagues. It runs whatever the format switches say |

Each competition has its own switch in the `FORMATS` table; a competition whose conversion fails keeps FM's format for that season, with the reason in `reports/parity_continental.log`.

## How it works

FM15 contains a tamper check. It hashes its own code (`.crsig`, signed with RSA), both at start-up and periodically while you play. Any modification, even one unused byte, silently gives every player and manager a fake name. So the mod never changes `fm.exe` on disk:

1. `tools/fm15_loader.py` starts FM15 through Steam and attaches with [Frida](https://frida.re).
2. It installs a **checksum shield**. The game's SHA-1 update function is redirected to an untouched copy of the code whenever it hashes the code section, so the check always passes.
3. About 30 seconds after start-up, once the start-up check has passed, it writes the patches into memory. Each one is first checked against the original bytes.
4. A patch module may declare `WRITABLE` blocks (patch name → pointer slot and size). The loader allocates zeroed read-write memory for each and writes its address into the slot, which is a 4-byte zero cave of that patch. Code pages keep their protection. `nostalgia_foreign_cap_ai` uses one such block for its sweep guard and its per-club ranking cache.

## Requirements

- FM15 on Steam, version 15.3 (the `fm.exe` built on 2 Apr 2015)
- Windows, with Python 3 and Frida (`pip install frida`)
- Your own copy of `fm.exe` in `original/fm.exe`. It isn't included here.

## Usage

```
python tools/fm15_loader.py              # start FM15 with every patch in patch.py's DEFAULT
python tools/fm15_loader.py --delay 60   # for slower start-ups
python tools/fm15_loader.py --mode nostalgia   # the pre-Bosman rule set
python tools/track_mods.py 20            # while playing: check every patch is present and working
```

`Launch FM15 (modded).bat` opens the launcher, so it can sit behind a desktop shortcut; given arguments, it passes them to the loader. Launching FM15 from Steam directly starts the unmodified game.

## Layout

| Path | Contents |
|---|---|
| `patcher/patches*.py` | Every patch: file offset, original bytes, replacement bytes and an explanation. `patch.py` lists the default set and can also build a patched exe, though that triggers the fake-names check |
| `tools/` | Loader, tracker, Frida tracing scripts, and the RTTI and `.cbd` parsing helpers |
| `ghidra_scripts/` | Headless Ghidra scripts used for the analysis |
| `reports/*/README.md` | Write-ups on league rules, squad rules and AI behaviour |

## Optional patches

Not in the default set, but available by name:
- `no_age_quota`
- `no_salary_cap`
- `ai_ignores_valuations`
- `ai_accepts_all_offers`
- `no_compensation`
- `no_work_permits`
- `no_foreign_restrictions`

For example: `python tools/fm15_loader.py no_loans always_open_windows`.
