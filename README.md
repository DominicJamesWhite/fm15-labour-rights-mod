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

## How it works

FM15 contains a tamper check. It hashes its own code (`.crsig`, signed with RSA), both at start-up and periodically while you play. Any modification, even one unused byte, silently gives every player and manager a fake name. So the mod never changes `fm.exe` on disk:

1. `tools/fm15_loader.py` starts FM15 through Steam and attaches with [Frida](https://frida.re).
2. It installs a **checksum shield**. The game's SHA-1 update function is redirected to an untouched copy of the code whenever it hashes the code section, so the check always passes.
3. About 30 seconds after start-up, once the start-up check has passed, it writes the patches into memory. Each one is first checked against the original bytes.

## Requirements

- FM15 on Steam, version 15.3 (the `fm.exe` built on 2 Apr 2015)
- Windows, with Python 3 and Frida (`pip install frida`)
- Your own copy of `fm.exe` in `original/fm.exe`. It isn't included here.

## Usage

```
python tools/fm15_loader.py              # start FM15 with every patch in patch.py's DEFAULT
python tools/fm15_loader.py --delay 60   # for slower start-ups
python tools/track_mods.py 20            # while playing: check every patch is present and working
```

`Launch FM15 (modded).bat` wraps the loader, so it can sit behind a desktop shortcut. Launching FM15 from Steam directly starts the unmodified game.

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
