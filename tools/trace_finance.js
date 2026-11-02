// Frida agent: logs club income in a running fm.exe, aggregated per game day, for the parity-mode money
// research (reports/parity/finances.md). Run with tools/trace_finance.py.
//
// Answers: which payers fire at month start and season end, where parachute money is paid, how owner
// money arrives, and whether the CLUB_FINANCE accumulator arrays (+0xf0.., +0x238..) are monthly or
// seasonal. Read-only: hooks only observe arguments; nothing in game memory is written.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + (p.sub(mod.base).add(0x400000).toUInt32() >>> 0).toString(16);
const TODAY = va(0x0239ebf4);

function today() {
  const doy = TODAY.readU16() & 0x1ff;
  const year = TODAY.add(2).readU16();
  return new Date(Date.UTC(year, 0, doy)).toISOString().slice(0, 10);
}

// Per-day aggregates: key -> {n, sum, min, max}.
let day = null;
let agg = {};
function bump(key, amount) {
  const c = agg[key] || (agg[key] = { n: 0, sum: 0, min: null, max: null });
  c.n++;
  if (amount !== undefined && amount !== null) {
    c.sum += amount;
    if (c.min === null || amount < c.min) c.min = amount;
    if (c.max === null || amount > c.max) c.max = amount;
  }
}

// The first few calls per (hook, caller) also get a fuzzy backtrace, to find who drives them.
const traced = {};
function backtraceOnce(name, ctx, caller) {
  const k = name + caller;
  if ((traced[k] = (traced[k] || 0) + 1) > 2) return;
  const bt = Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 10).map(rva).join(" ");
  send({ event: { date: day, hook: name, caller, backtrace: bt } });
}

// Finance objects seen getting league TV deal money (type-10 deals), sampled daily.
const samples = [];
function sample(fin) {
  if (samples.length >= 8 || samples.some((p) => p.equals(fin))) return;
  samples.push(fin);
}
function readDwords(p, from, to) {
  const out = [];
  for (let o = from; o <= to; o += 4) out.push(p.add(o).readS32());
  return out;
}
function snapshotSamples() {
  return samples.map((fin) => {
    try {
      return { fin: fin.toString(), a1: readDwords(fin, 0xf0, 0x148), a2: readDwords(fin, 0x238, 0x290) };
    } catch (e) {
      return { fin: fin.toString(), error: String(e) };
    }
  });
}

function flushDay() {
  const d = today();
  if (d === day) return;
  if (day !== null) send({ day: { date: day, agg, samples: snapshotSamples() } });
  day = d;
  agg = {};
}

// Leaf credit methods on DB::CLUB_FINANCE (thiscall, amount first stack argument).
const LEAVES = {
  0x01680140: "TransferIn",
  0x016804f0: "GatesIn",
  0x01680540: "OtherIn",
  0x016805d0: "PrizeIn",
  0x01680810: "slot_f4",
  0x01680880: "TVIn",
  0x01680990: "slot_100",
  0x0167fdc0: "SponsorIn",
  0x01680a50: "slot_108",
  0x01680aa0: "slot_110",
  0x0167fe10: "deal7",
  0x0167feb0: "deal2",
  0x0167fe60: "postmatch_fe60",
  0x01681120: "DividendOut",
};
for (const [addr, name] of Object.entries(LEAVES)) {
  Interceptor.attach(va(Number(addr)), {
    onEnter(args) {
      flushDay();
      const caller = rva(this.returnAddress);
      bump(name + " from " + caller, args[0].toInt32());
      backtraceOnce(name, this.context, caller);
    },
  });
}

// Season tickets: credited inline in slot +0x04.
Interceptor.attach(va(0x016673f0), {
  onEnter() {
    flushDay();
    const caller = rva(this.returnAddress);
    bump("SeasonTicketFn from " + caller);
    backtraceOnce("SeasonTicketFn", this.context, caller);
  },
});

// GAME_COMP_MANAGER pay: (club, amount, comp, ?, ?, char type, ...), thiscall.
Interceptor.attach(va(0x0091a160), {
  onEnter(args) {
    flushDay();
    const caller = rva(this.returnAddress);
    const type = args[5].toInt32() & 0xff;
    let level = "?";
    try { level = args[2].isNull() ? "none" : args[2].add(0xdd).readU8(); } catch (e) {}
    bump("CompPay type=" + type + " level=" + level + " from " + caller, args[1].toInt32());
    backtraceOnce("CompPay type=" + type, this.context, caller);
  },
});

// Monthly deal processor (GAME_CLUB_FINANCE +0xa8). Sample league clubs from its type-10 TV credits.
let inDeals = false;
Interceptor.attach(va(0x00b9de70), {
  onEnter() {
    flushDay();
    inDeals = true;
    const caller = rva(this.returnAddress);
    bump("DealProcessor from " + caller);
    backtraceOnce("DealProcessor", this.context, caller);
  },
  onLeave() { inDeals = false; },
});
// League TV instalments arrive from inside CLUB_FINANCE (caller 0x0167faae, seen 13 Jul 2014), not
// via the deal processor, so sample clubs credited from either.
Interceptor.attach(va(0x01680880), {
  onEnter() {
    if (inDeals || this.returnAddress.equals(va(0x0167faae))) sample(this.context.ecx);
  },
});

// Context-only hooks: count, caller, first backtraces.
const CONTEXT = {
  0x00453c50: "PostMatchIncome",
  0x0097b310: "OwnerMonthly",
  0x00d15b60: "Dividends",
  0x00aaa430: "CashInjectionNews",
  0x00c80800: "cand_periodic_110",
};
for (const [addr, name] of Object.entries(CONTEXT)) {
  Interceptor.attach(va(Number(addr)), {
    onEnter() {
      flushDay();
      const caller = rva(this.returnAddress);
      bump(name + " from " + caller);
      backtraceOnce(name, this.context, caller);
    },
  });
}

// Owner investment: stdcall (fin, amount, flag).
Interceptor.attach(va(0x01e36f80), {
  onEnter(args) {
    flushDay();
    const caller = rva(this.returnAddress);
    bump("InvestmentIn flag=" + args[2].toInt32() + " from " + caller, args[1].toInt32());
    backtraceOnce("InvestmentIn", this.context, caller);
  },
});

// Parachute getter (ACTUAL_COMP vt+0x50, thiscall, ret 8): log the amount it returns and who asks.
Interceptor.attach(va(0x00f9f0e0), {
  onEnter() {
    this.caller = rva(this.returnAddress);
    this.ctx = this.context;
    backtraceOnce("ParachuteGetter", this.context, this.caller);
  },
  onLeave(retval) {
    flushDay();
    bump("ParachuteGetter from " + this.caller, retval.toInt32());
  },
});

// Day changes with no hooked activity still get flushed.
setInterval(() => { try { flushDay(); } catch (e) {} }, 500);
send({ ready: mod.base.toString(), date: today() });
