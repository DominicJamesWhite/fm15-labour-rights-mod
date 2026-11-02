"""Command line for unattended FM15 test careers.

Usage:
    python fm15_cli.py new-career --setup NAME [--until YYYY-MM-DD] [--mode MODE | --custom GROUPS]
                                  [--keep-running] [--timeout SECONDS]
    python fm15_cli.py harness --setup NAME [--until YYYY-MM-DD] [--out FILE] [--prefs-out DIR]
    python fm15_cli.py prefs backup
    python fm15_cli.py prefs restore [BACKUP] [--apply]
    python fm15_cli.py status

new-career    builds a new career with no clicks through FM's auto-setup harness: backs up the
              preferences, puts the harness file in FM's install folder (FM opens <name>.cfg there),
              switches the harness on, launches FM through fm15_loader.py (with --gate, so the career is
              built under the mode's rules), waits for FM to quit, restores the preferences and lists the
              new saves. --keep-running returns once the career is built (holidaying careers), and the
              harness is switched off straight away; run `prefs restore --apply` after FM quits.
harness       writes FM's auto-setup ("quick start") text file for a setup in fm15_setups.json and prints the
              preference files that would switch it on. Dry run: the live Preferences folder is never
              written; --prefs-out writes the preference files to a staging folder instead.
prefs backup  copies the whole Preferences\\version 3 folder to reports/automation/prefs_backups/<time>.
prefs restore shows what restoring a backup (default: the newest) would change; --apply copies it back,
              and refuses while fm.exe is running.
status        read-only: is fm.exe running (pid, start time), the latest game date in
              reports/parity_agent.log, and the last screen title in FM's navigation.txt.

Format and addresses: reports/automation/new_career.md.
"""

import argparse
import csv
import datetime
import filecmp
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SETUPS = pathlib.Path(__file__).resolve().parent / "fm15_setups.json"
LOCAL = pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "Sports Interactive" / "Football Manager 2015"
PREFS = LOCAL / "Preferences" / "version 3"
NAVIGATION = LOCAL / "Logs" / "navigation.txt"
BACKUPS = ROOT / "reports" / "automation" / "prefs_backups"
HARNESS_DIR = ROOT / "reports" / "automation" / "harness"
AGENT_LOG = ROOT / "reports" / "parity_agent.log"

SIZES = {"MINIMUM": 0, "MEDIUM": 1, "MAXIMUM": 2, "HUGE": 3}       # 0x00d31510 -> WORLD+0x227
AUTO_SAVES = ["OFF", "DAY", "WEEK", "FORTNIGHT", "MONTH", "3_MONTHS", "YEAR", "FIVE_YEARS"]
# date_format.xml value -> field order used by FM's date parser 0x018bec20 (tables at 0x02277b60)
DATE_ORDERS = {0: "%d/%m/%Y", 1: "%m/%d/%Y", 2: "%Y/%m/%d"}


# ---------------------------------------------------------------- preference files

def pref_xml(kind, value):
    """One preference file in FM's own shape (UTF-16 with BOM, CRLF), e.g. last_saved_game.xml."""
    if kind == "folder":
        body = f'\t<folder id="value" path="{value}"/>'
    else:
        body = f'\t<{kind} id="value" value="{value}"/>'
    return f'<?xml version="1.0" encoding="UTF-16" ?>\r\n<record>\r\n{body}\r\n</record>\r\n'


def read_pref(name):
    """Value attribute of a preference file in the live folder (read only), or None."""
    path = PREFS / f"{name}.xml"
    if not path.exists():
        return None
    text = path.read_bytes().decode("utf-16")
    m = re.search(r'id="value" (?:value|path)="([^"]*)"', text)
    return m.group(1) if m else None


# ---------------------------------------------------------------- harness file

INSTALL_DEFAULT = pathlib.Path(r"C:\Program Files (x86)\Steam\steamapps\common\Football Manager 2015")
HARNESS_NAME = "fm15cli"           # FM opens <application_root>\<value>.cfg (0x00483860; smoke test 2)
LOADER = ROOT / "tools" / "fm15_loader.py"
STOP_AGENT = ROOT / "tools" / "holiday_stop.js"
PENDING_RESTORE = ROOT / "reports" / "automation" / "pending_restore.txt"   # backup to restore once FM quits
DOCS = pathlib.Path(os.environ.get("USERPROFILE", "")) / "Documents" / "Sports Interactive" / "Football Manager 2015"


def install_folder():
    """FM's install folder: the default Steam path, else derived from database_location.xml."""
    if (INSTALL_DEFAULT / "fm.exe").exists():
        return INSTALL_DEFAULT
    current = read_pref("database_location") or ""      # ...\Football Manager 2015\data\db\1500\1500_fm\
    p = pathlib.Path(current.rstrip("\\"))
    for parent in p.parents:
        if (parent / "fm.exe").exists():
            return parent
    return None

def fm_date(iso):
    order = DATE_ORDERS.get(int(read_pref("date_format") or 0), DATE_ORDERS[0])
    return datetime.date.fromisoformat(iso).strftime(order)


def nation_list(codes):
    for code in codes:
        if not re.fullmatch(r"[A-Z]{3}(-\d+)?", code):
            raise ValueError(f"bad nation entry {code!r}: use a 3-letter code, optionally -n")
    return ", ".join(codes)


def harness_text(setup, until=None):
    """Key line, value line pairs (reader 0x018bb900); '//' lines are comments."""
    if not setup.get("playable"):
        raise ValueError("a setup needs at least one playable nation (PLAYABLE is required)")
    lines = ["// written by fm15_cli.py; one KEY line, then its VALUE line"]

    def put(key, value):
        lines.extend([key, str(value)])

    put("PLAYABLE", nation_list(setup["playable"]))
    if setup.get("view_only"):
        put("VIEW_ONLY", nation_list(setup["view_only"]))
    if setup.get("size"):
        if setup["size"] not in SIZES:
            raise ValueError(f"size must be one of {', '.join(SIZES)}")
        put("DATABASE", setup["size"])
    for i, m in enumerate(setup.get("managers", [])[:20]):
        for field in ("first", "last"):
            if '"' in m[field] or not m[field].strip():
                raise ValueError(f"manager {i}: {field} name must be non-empty and contain no double quote")
        put(f"ADD_MANAGER_{i}", f'"{m["first"]}" "{m["last"]}" "{int(m.get("team", -1))}"')
    if setup.get("holiday"):
        put("HOLIDAY", "YES")
    if setup.get("auto_save"):
        if setup["auto_save"] not in AUTO_SAVES:
            raise ValueError(f"auto_save must be one of {', '.join(AUTO_SAVES)}")
        put("AUTO_SAVE", setup["auto_save"])
    dates = list(setup.get("save_dates", []))
    if until:
        dates = [until]
    if len(dates) > 1:
        # 0x00d31510 seems to empty the date list for every SAVE_GAME_DATE_n it finds, so only one survives.
        raise ValueError("only one save date is supported (see new_career.md, stage 1)")
    if dates:
        put("SAVE_GAME_DATE_0", fm_date(dates[0]))
    if setup.get("quit_when_done"):
        put("QUICK_START_EXIT", "YES")
    return "\r\n".join(lines) + "\r\n"


def cmd_harness(opts):
    setups = json.loads(SETUPS.read_text("utf-8"))
    if opts.setup not in setups:
        print(f"unknown setup {opts.setup!r}; known: {', '.join(k for k in setups if not k.startswith('_'))}")
        return 1
    setup = setups[opts.setup]
    try:
        text = harness_text(setup, opts.until)
    except ValueError as e:
        print(e)
        return 1
    out = pathlib.Path(opts.out) if opts.out else HARNESS_DIR / f"{opts.setup}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(text.encode("ascii"))
    print(f"harness file: {out}\n")
    print(text.replace("\r\n", "\n"))

    # 0x00483860 opens the file through the "application_root" folder object (0x02426e44), so an absolute
    # path is not found (smoke test 1). The file must sit in that folder and the setting is its relative name.
    current = read_pref("database_location") or ""
    install = pathlib.PureWindowsPath(current).parents[3] if current.count("\\") > 4 else None
    print(f"copy the harness file to: {install / out.name if install else '<FM install folder>'}  (not done)")
    prefs = {"auto_play_game_file": pref_xml("string", out.name)}
    if setup.get("database"):
        current = read_pref("database_location")      # ...\data\db\1500\1500_fm\
        if not current:
            print("database_location.xml not found; cannot place the database folder")
            return 1
        db_root = pathlib.PureWindowsPath(current).parent.parent
        prefs["database_location"] = pref_xml("folder", f"{db_root / setup['database'] / (setup['database'] + '_fm')}\\")
    print(f"preference files to write in {PREFS} (dry run, not written):")
    for name, xml in prefs.items():
        print(f"--- {name}.xml\n{xml.replace(chr(13), '')}")
    print("--- afterwards: delete auto_play_game_file.xml, or every launch re-runs the harness")
    if opts.prefs_out:
        stage = pathlib.Path(opts.prefs_out)
        if stage.resolve() == PREFS.resolve():
            print("--prefs-out must not be the live Preferences folder in this stage")
            return 1
        stage.mkdir(parents=True, exist_ok=True)
        for name, xml in prefs.items():
            (stage / f"{name}.xml").write_bytes(b"\xff\xfe" + xml.encode("utf-16-le"))
        print(f"staged copies written to {stage}")
    return 0


# ---------------------------------------------------------------- prefs backup / restore

def cmd_new_career(opts):
    import time
    setups = json.loads(SETUPS.read_text("utf-8"))
    if opts.setup not in setups:
        print(f"unknown setup {opts.setup!r}; known: {', '.join(k for k in setups if not k.startswith('_'))}")
        return 1
    setup = setups[opts.setup]
    running = fm_processes()
    if running is None or running:
        print("fm.exe is running (or could not be checked); quit it first")
        return 1
    install = install_folder()
    if install is None:
        print("FM install folder not found")
        return 1
    try:
        text = harness_text(setup, opts.until)
    except ValueError as e:
        print(e)
        return 1
    if "QUICK_START_EXIT" not in text and not opts.keep_running:
        print("note: the setup does not quit when done; waiting until FM is closed or the timeout")
    cmd_backup(opts)
    backup = sorted(p for p in BACKUPS.iterdir() if p.is_dir())[-1]
    cfg = install / f"{HARNESS_NAME}.cfg"
    cfg.write_bytes(text.encode("ascii"))
    prefs = {"auto_play_game_file": pref_xml("string", HARNESS_NAME)}
    if setup.get("database"):
        current = read_pref("database_location")
        db_root = pathlib.PureWindowsPath(current).parent.parent
        prefs["database_location"] = pref_xml("folder", f"{db_root / setup['database'] / (setup['database'] + '_fm')}\\")
    for name, xml in prefs.items():
        (PREFS / f"{name}.xml").write_bytes(xml.encode("utf-16"))
    print(f"harness {cfg} switched on ({opts.setup})")

    def switch_off():
        for f in (cfg, PREFS / "auto_play_game_file.xml"):
            try:
                f.unlink()
            except FileNotFoundError:
                pass

    mark = time.time()
    nav_start = NAVIGATION.stat().st_size if NAVIGATION.exists() else 0
    mode = opts.custom and ["--custom", opts.custom] or ["--mode", opts.mode or setup.get("mode") or "vanilla"]
    gate = [] if mode == ["--mode", "vanilla"] else ["--gate"]
    print("launching:", " ".join(mode + gate), flush=True)
    r = subprocess.run([sys.executable, str(LOADER)] + mode + gate, cwd=ROOT)
    if r.returncode:
        print("the loader failed; switching the harness off (quit FM, then `prefs restore --apply`)")
        switch_off()
        return 1
    built = False
    screen = None
    deadline = time.time() + opts.timeout
    while time.time() < deadline:
        time.sleep(5)
        now = last_screen(nav_start)
        if now != screen:
            screen = now
            print(f"  screen: {screen}", flush=True)
        if screen and screen.startswith("Game:"):
            if not built:
                built = True
                switch_off()                 # read once at start-up; off for the next launch
                print("career built", flush=True)
            if opts.keep_running:
                PENDING_RESTORE.write_text(backup.name, "utf-8")
                print(f"FM left running; `holiday --until DATE --quit` restores the preferences after it quits")
                return 0
        running = fm_processes()
        if running is not None and not running:
            break
    else:
        print(f"timeout after {opts.timeout}s; FM left running. After it quits: fm15_cli.py prefs restore {backup.name} --apply")
        switch_off()
        return 1
    switch_off()
    cmd_restore(argparse.Namespace(backup=backup.name, apply=True))
    new = [p for d in (DOCS / "games", install / "data" / "quick starts") if d.is_dir()
           for p in d.iterdir() if p.is_file() and p.stat().st_mtime > mark]
    print("career built" if built else "FM quit without building a career (setup failed?)")
    for p in new:
        print(f"  saved: {p}")
    return 0 if built else 1


def cmd_holiday(opts):
    """Wait until the game date reaches --until and FM's next autosave after it, copy that autosave to a named
    save, and optionally quit (FM's own autosave: a forced save of a never-named career fails, new_career.md)."""
    import time
    import frida
    target = datetime.date.fromisoformat(opts.until)
    goal = (target.year, target.timetuple().tm_yday)
    session = frida.attach("fm.exe")
    script = session.create_script(STOP_AGENT.read_text("utf-8"))
    script.load()
    api = script.exports_sync
    games = DOCS / "games"
    deadline = time.time() + opts.timeout
    print(f"waiting for {target}; game date {api.date()}", flush=True)
    last_print = reached = 0
    while time.time() < deadline:
        time.sleep(1)
        y, d = api.date()
        if not reached and (y, d) >= goal:
            reached = time.time()
            print(f"reached {y}/{d}; waiting for the next autosave", flush=True)
        if reached:
            files = [f for f in games.glob("*.fm") if f.stat().st_mtime > reached]
            if files:
                f = max(files, key=lambda f: f.stat().st_mtime)
                size = f.stat().st_size
                time.sleep(5)
                if f.stat().st_size == size:
                    break
        elif time.time() - last_print > 60:
            last_print = time.time()
            print(f"  game date {y}/{d}", flush=True)
    else:
        print("timeout; FM left running")
        return 1
    name = games / f"{opts.name or 'cli'} {target}.fm"
    shutil.copy2(f, name)
    print(f"autosave {f.name} at game date {api.date()} copied to {name}", flush=True)
    if not opts.quit:
        session.detach()
        return 0
    api.quit()
    session.detach()
    while time.time() < deadline:
        time.sleep(2)
        running = fm_processes()
        if running is not None and not running:
            break
    else:
        print("FM did not quit")
        return 1
    print("FM quit")
    if PENDING_RESTORE.exists():
        backup = PENDING_RESTORE.read_text("utf-8").strip()
        if cmd_restore(argparse.Namespace(backup=backup, apply=True)) == 0:
            PENDING_RESTORE.unlink()
    return 0


def fm_processes():
    """[(pid, start time)] for fm.exe via WMI; does not open the process."""
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='fm.exe'\" | "
          "ForEach-Object { \"$($_.ProcessId),$($_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss'))\" }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                             timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return [tuple(row) for row in csv.reader(out.splitlines()) if len(row) == 2]


def cmd_backup(opts):
    if not PREFS.is_dir():
        print(f"no preferences folder at {PREFS}")
        return 1
    dest = BACKUPS / datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copytree(PREFS, dest)          # reads only; the live folder is not changed
    print(f"copied {sum(1 for _ in dest.rglob('*') if _.is_file())} files to {dest}")
    return 0


def cmd_restore(opts):
    backups = sorted(p for p in BACKUPS.iterdir() if p.is_dir()) if BACKUPS.is_dir() else []
    src = BACKUPS / opts.backup if opts.backup else (backups[-1] if backups else None)
    if src is None or not src.is_dir():
        print("no backup found" if src is None else f"no backup {src}")
        return 1
    changed, added, extra = [], [], []
    for f in src.rglob("*"):
        if f.is_file():
            live = PREFS / f.relative_to(src)
            if not live.exists():
                added.append(live)
            elif not filecmp.cmp(f, live, shallow=False):
                changed.append(live)
    if PREFS.is_dir():
        extra = [f for f in PREFS.rglob("*") if f.is_file() and not (src / f.relative_to(PREFS)).exists()]
    print(f"restore from {src}: {len(changed)} changed, {len(added)} missing, {len(extra)} extra in live")
    for label, files in (("changed", changed), ("missing", added), ("extra (would be deleted)", extra)):
        for f in files:
            print(f"  {label}: {f.name}")
    if not opts.apply:
        print("dry run; pass --apply to restore (FM must not be running)")
        return 0
    running = fm_processes()
    if running is None or running:
        print("fm.exe is running (or could not be checked); not restoring")
        return 1
    for f in extra:
        f.unlink()
    shutil.copytree(src, PREFS, dirs_exist_ok=True)
    print("restored")
    return 0


# ---------------------------------------------------------------- status

def last_game_date():
    if not AGENT_LOG.exists():
        return None
    with AGENT_LOG.open("rb") as f:
        f.seek(max(0, AGENT_LOG.stat().st_size - 65536))
        tail = f.read().decode("utf-8", "replace")
    dates = re.findall(r"^(\d{4}-\d{2}-\d{2}) ", tail, re.M)
    return dates[-1] if dates else None


def last_screen(since=None):
    """Last ' - Section: Screen' line in navigation.txt (UTF-16; read only, tail only), or only among the
    lines written after byte offset `since` (a session's own screens, not the last session's)."""
    if not NAVIGATION.exists():
        return None
    size = NAVIGATION.stat().st_size
    with NAVIGATION.open("rb") as f:
        f.seek((since if since is not None and since <= size else max(0, size - 262144)) & ~1)
        tail = f.read().decode("utf-16-le", "replace")
    titles = [line.strip() for line in tail.splitlines() if line.startswith(" - ")]
    return titles[-1][2:] if titles else None


def cmd_status(opts):
    procs = fm_processes()
    if procs is None:
        print("fm.exe: could not query processes")
    elif not procs:
        print("fm.exe: not running")
    for pid, started in procs or []:
        print(f"fm.exe: running, pid {pid}, started {started}")
    print(f"latest game date in {AGENT_LOG.name}: {last_game_date() or 'none'}")
    print(f"last screen in navigation.txt: {last_screen() or 'none'}")
    harness = read_pref("auto_play_game_file")
    print(f"auto_play_game_file preference: {harness or 'not set'}")
    return 0


def main(argv):
    args = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = args.add_subparsers(dest="command", required=True)
    n = sub.add_parser("new-career", help="build a new career with no clicks (FM's auto-setup harness)")
    n.add_argument("--setup", required=True)
    n.add_argument("--until", help="YYYY-MM-DD: save on this date (replaces the setup's save_dates)")
    n.add_argument("--mode", help="rule set (default: the setup's mode, else vanilla)")
    n.add_argument("--custom", help="custom rule groups instead of --mode (fm15_loader.py --custom)")
    n.add_argument("--keep-running", action="store_true", help="return once the career is built")
    n.add_argument("--timeout", type=int, default=1800)
    n.set_defaults(func=cmd_new_career)
    o = sub.add_parser("holiday", help="wait for a game date, then save (and optionally quit)")
    o.add_argument("--until", required=True, help="YYYY-MM-DD game date")
    o.add_argument("--quit", action="store_true", help="quit FM after the save (and restore preferences)")
    o.add_argument("--name", help="saved as games/<name> <date>.fm (default: cli)")
    o.add_argument("--timeout", type=int, default=7200)
    o.set_defaults(func=cmd_holiday)
    h = sub.add_parser("harness", help="write the auto-setup file for a setup (dry run for preferences)")
    h.add_argument("--setup", required=True)
    h.add_argument("--until", help="YYYY-MM-DD: save on this date (replaces the setup's save_dates)")
    h.add_argument("--out", help="harness file path (default reports/automation/harness/<setup>.txt)")
    h.add_argument("--prefs-out", help="also write the preference files to this staging folder")
    h.set_defaults(func=cmd_harness)
    p = sub.add_parser("prefs", help="back up or restore FM's Preferences\\version 3 folder")
    psub = p.add_subparsers(dest="action", required=True)
    b = psub.add_parser("backup")
    b.set_defaults(func=cmd_backup)
    r = psub.add_parser("restore")
    r.add_argument("backup", nargs="?", help="backup folder name (default: newest)")
    r.add_argument("--apply", action="store_true")
    r.set_defaults(func=cmd_restore)
    s = sub.add_parser("status", help="read-only state of FM and the logs")
    s.set_defaults(func=cmd_status)
    opts = args.parse_args(argv[1:])
    return opts.func(opts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
