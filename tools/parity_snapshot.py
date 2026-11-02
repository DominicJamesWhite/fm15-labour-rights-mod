"""Read-only season snapshot of parity-mode club finances, with a per-league summary.

Usage:
  python tools/parity_snapshot.py            # attach to fm.exe, save reports/parity/snapshots/<game date>.json, summarise
  python tools/parity_snapshot.py --summary  # summarise the saved snapshots only (no attach)

The agent (tools/parity_snapshot.js) only reads memory at script load and is unloaded straight away:
no hooks, no writes. Take it just after the summer rollovers (early July), when "last season" is the
season that has just ended for every club.

Per top division: wage budget gap (top 4 / bottom 4 and highest / lowest), total weekly wage budget
and bill, last season's wages paid as a share of net revenue (revenue minus Other Out, which holds
the pool debits and levies), owner money received, clubs in the red and the median balance, each
with the change from the previous snapshot.
"""

import json
import os
import pathlib
import statistics as st
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "parity" / "snapshots"
REVENUE = [12, 13, 14, 15, 17, 19, 20, 21, 23, 30, 31, 32, 33]   # block dwords, as parity_agent.js REVENUE
OTHER_OUT, INVESTMENT, WAGES = 0, 16, (4, 5)


def take():
    import frida
    s = frida.attach("fm.exe")
    result = {}
    sc = s.create_script((ROOT / "tools" / "parity_snapshot.js").read_text(encoding="utf-8"))
    sc.on("message", lambda m, d: result.setdefault("data", m.get("payload")) if m.get("type") == "send" else print(m))
    sc.load()
    for _ in range(120):
        if "data" in result:
            break
        time.sleep(0.5)
    sc.unload()
    s.detach()
    data = json.loads(result["data"])
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{data['date']}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    print(f"saved {path} ({len(data['clubs'])} clubs)")


def league_stats(snap):
    out = {}
    for lk, lg in snap["leagues"].items():
        if lg["level"] != 0:
            continue
        cs = [c for c in snap["clubs"] if c["league"] == lk]
        if len(cs) < 8:
            continue
        budget = sorted(c["f"][16] + c["f"][7] for c in cs)
        bill = [c["f"][19] or c["f"][18] for c in cs]
        last = [c["l"] for c in cs]
        net = sum(sum(b[i] for i in REVENUE) - b[OTHER_OUT] for b in last)
        paid = sum(b[WAGES[0]] + b[WAGES[1]] for b in last)
        bal = [c["bal"] for c in cs]
        out[lg.get("name", lk)] = {
            "clubs": len(cs),
            "top4/bottom4": sum(budget[-4:]) / max(1, sum(budget[:4])),
            "max/min": budget[-1] / max(1, budget[0]),
            "budget/wk": sum(budget),
            "bill/wk": sum(bill),
            "wages/net revenue": paid / net if net > 0 else None,
            "owner money": sum(b[INVESTMENT] for b in last),
            "in the red": sum(1 for b in bal if b < 0),
            "median balance": st.median(bal),
        }
    return out


def fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float) and abs(v) < 100:
        return f"{v:.2f}"
    return f"{v / 1e6:.1f}m" if abs(v) >= 1e5 else str(int(v))


def summary():
    files = sorted(OUT.glob("*.json"))
    if not files:
        print("no snapshots")
        return
    prev = None
    for f in files:
        snap = json.loads(f.read_text(encoding="utf-8"))
        stats = league_stats(snap)
        print(f"\n== {snap['date']}")
        keys = ["top4/bottom4", "max/min", "budget/wk", "bill/wk", "wages/net revenue", "owner money", "in the red", "median balance"]
        print(f"{'league':28}" + "".join(f"{k:>18}" for k in keys))
        for name, s in sorted(stats.items()):
            row = f"{name[:28]:28}"
            for k in keys:
                cell = fmt(s[k])
                p = prev.get(name, {}).get(k) if prev else None
                if p is not None and s[k] is not None and isinstance(s[k], (int, float)) and p:
                    cell += f" ({(s[k] - p) / abs(p) * 100:+.0f}%)" if k not in ("in the red",) else f" ({s[k] - p:+d})"
                row += f"{cell:>18}"
            print(row)
        prev = stats


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if "--summary" not in sys.argv:
        take()
    summary()
