"""Monthly snapshots of nostalgia mode, cheap enough to leave running through long holidays.

Usage: python sample_monthly.py [days per sample, default 3] [hours to run, default 12]

Between samples only rare events are hooked (contract rollovers, contract ends and releases, accepted
transfers), counted per game month in reports/monthly/totals.txt; a small script also reads the game
date and the transfer-windows flag every two seconds. On the first game day of each month it attaches
observe_nostalgia.js and trace_foreign_cap.js for a few game days, then detaches them and writes
reports/monthly/<year>-<month>.txt with both reports for that window.
"""

import importlib.util
import pathlib
import sys
import time

import frida

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "monthly"
# Game date: u16 at 0x0239ebf4 (day of year in the low 9 bits, as in contract end dates), u16 year after it.
CLOCK = """
const b = Process.getModuleByName("fm.exe").base;
const va = (a) => b.add(a - 0x400000);
const date = va(0x0239ebf4);
const windows = va(0x02392459);
// Cheap always-on counters for rare events, per game month: contract rollovers, contract expiries,
// release costs (FUN_0047ca40, > 0 only), accepted transfers.
const totals = {};
let month = "";
function bump(name, value) {
  const t = totals[month] || (totals[month] = {});
  const c = t[name] || (t[name] = {n: 0, sum: 0});
  c.n++;
  c.sum += value || 0;
}
recv("start", (msg) => {
  // Mid-function address: use the probe form (no return trap; an object listener there can
  // overwrite [esp], see reports/transfer_ai section 9).
  if (msg.retain) Interceptor.attach(ptr(msg.retain).add(b).sub(0x400000), function () { bump("contracts rolled over"); });
  // FUN_00478070: a contract running out (the path nostalgia_retain_on_expiry skips for wanted players)
  Interceptor.attach(va(0x00478070), {onEnter() { bump("contracts expired (player let go or agreed move)"); }});
  Interceptor.attach(va(0x0047ca40), {onLeave(r) {
    const v = r.toInt32();
    if (v > 0) bump("release cost worked out (paid if the club goes ahead)", v);
  }});
  Interceptor.attach(va(0x00ca6360), {onEnter(args) {
    try {
      const vft = args[0].readPointer().sub(b).add(0x400000).toInt32() >>> 0;
      if (vft === 0x0216bcec || vft === 0x020e2fdc) {
        const fee = args[0].add(0x18).readS32();
        bump(fee > 0 ? "transfers accepted with a fee" : "transfers accepted for free", fee);
      }
    } catch (e) {}
  }});
});
setInterval(() => {
  const d = date.readU16() & 0x1ff, y = date.add(2).readU16();
  const len = [31, y % 4 ? 28 : 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  let m = 0, left = d;
  while (m < 11 && left > len[m]) left -= len[m++];
  month = y + "-" + String(m + 1).padStart(2, "0");
  send({day: date.readU16() & 0x1ff, year: date.add(2).readU16(), windows: windows.readU8(), totals});
}, 2000);
"""
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def month_of(day, year):
    lengths = [31, 29 if year % 4 == 0 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    for m, n in enumerate(lengths):
        if day <= n:
            return m
        day -= n
    return 11


def main(argv):
    days = int(argv[1]) if len(argv) > 1 else 3
    hours = float(argv[2]) if len(argv) > 2 else 12
    OUT.mkdir(parents=True, exist_ok=True)
    observer = load_module(ROOT / "tools" / "observe_nostalgia.py")
    patcher = load_module(ROOT / "patcher" / "patch.py")
    loader = load_module(ROOT / "tools" / "fm15_loader.py")
    to_va = loader.section_map(loader.ORIGINAL.read_bytes())
    patches, retain = [], None
    for name in patcher.NOSTALGIA:
        for p in patcher.PATCHES[name]:
            data = bytes.fromhex(p["patched"].replace(" ", ""))
            at = p["va"] if "va" in p else to_va(p["offset"])
            patches.append({"name": name, "va": at, "len": len(data), "patched": data.hex(" ")})
            if name == "nostalgia_retain_on_expiry" and observer.ROLLOVER in data:
                retain = at + data.index(observer.ROLLOVER)

    session = frida.attach("fm.exe")
    state = {"clock": None, "obs": None, "trace": {}, "windows_on": 0}

    def on_clock(message, data):
        if message["type"] == "send":
            state["clock"] = message["payload"]
            if message["payload"]["windows"]:
                state["windows_on"] += 1

    def on_obs(message, data):
        if message["type"] == "send" and "stats" in message["payload"]:
            state["obs"] = message["payload"]["stats"]

    def on_trace(message, data):
        if message["type"] == "send" and "ready" not in message["payload"]:
            state["trace"] = message["payload"]

    clock = session.create_script(CLOCK)
    clock.on("message", on_clock)
    clock.load()
    clock.post({"type": "start", "retain": retain})
    print(f"watching the game date; {days}-day sample each month, snapshots in {OUT}", flush=True)

    sampled, active, started = None, None, time.time()
    while time.time() - started < hours * 3600:
        time.sleep(2)
        c = state["clock"]
        if not c or c["year"] < 2000:  # 1900: no game loaded yet
            continue
        # While a career is being created or loaded the date jumps about (1900, 2013...): only
        # sample once it has moved forward by at most a week per check for a minute, so heavy hooks are
        # never attached mid-load.
        stamp = c["year"] * 400 + c["day"]
        if state.get("stamp") is None or not 0 <= stamp - state["stamp"] <= 7:
            state["stable_since"] = time.time()
        state["stamp"] = stamp
        if time.time() - state.get("stable_since", time.time()) < 60 and active is None:
            continue
        if c.get("totals"):
            rows = ["Whole-month counts (always on). Contracts end on 30 June in most leagues, so June",
                    "is the month to compare: rollovers vs players let go.", ""]
            for mon in sorted(c["totals"]):
                rows.append(mon)
                for name, v in sorted(c["totals"][mon].items()):
                    avg = f"  (avg {v['sum'] // v['n']:,})" if v["sum"] else ""
                    rows.append(f"    {v['n']:7,}  {name}{avg}")
            (OUT / "totals.txt").write_text("\n".join(rows), "utf-8")
        month = (c["year"], month_of(c["day"], c["year"]))
        if active is None and month != sampled:
            # start a sample: attach the hooks
            state["obs"], state["trace"] = None, {}
            obs = session.create_script((ROOT / "tools" / "observe_nostalgia.js").read_text("utf-8"))
            obs.on("message", on_obs)
            obs.load()
            obs.post({"type": "start", "patches": patches, "retainCave": retain})
            trace = session.create_script((ROOT / "tools" / "trace_foreign_cap.js").read_text("utf-8"))
            trace.on("message", on_trace)
            trace.load()
            active = {"month": month, "start": c["day"], "scripts": (obs, trace)}
            sampled = month
            print(f"{MONTHS[month[1]]} {month[0]}: sampling", flush=True)
        elif active is not None and (c["day"] - active["start"]) % 366 >= days:
            time.sleep(16)  # let both scripts send their last counts
            for s in active["scripts"]:
                s.unload()
            year, m = active["month"]
            text = [f"FM15 nostalgia, {MONTHS[m]} {year}: {days} game days from day {active['start']}",
                    f"windows flag seen on (should be 0 or a brief blip at career start): {state['windows_on']}", ""]
            if state["obs"]:
                text.append(observer.render(state["obs"], time.time()))
            text += ["", "Foreign-player trace:"]
            text += [f"{n:9,}  {k}" for k, n in sorted(state["trace"].items(), key=lambda kv: -kv[1])]
            (OUT / f"{year}-{m + 1:02d}.txt").write_text("\n".join(text), "utf-8")
            print(f"{MONTHS[m]} {year}: snapshot written", flush=True)
            active = None
    session.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
