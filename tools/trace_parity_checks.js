// Frida agent: the live checks listed in reports/parity/identity_timing.md (F1-F9) and
// reports/parity/money_flows.md (transfer payment types, owner-money routes). Run with
// tools/trace_parity_checks.py through at least one month start and one season end.
//
// Read-only: hooks read arguments and memory, and call only getters (balance 0x014b1550, the
// <%team#1> name formatter). Nothing in game memory is written.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + (p.sub(mod.base).add(0x400000).toUInt32() >>> 0).toString(16);
const TODAY = va(0x0239ebf4);

const GET_BALANCE = new NativeFunction(va(0x014b1550), "int", ["pointer"], "thiscall");
const TEXT_CTOR = new NativeFunction(va(0x0188f4b0), "pointer", ["pointer"], "thiscall");
const TEXT_SET = new NativeFunction(va(0x0188fd00), "void", ["pointer", "pointer"], "thiscall");
const TEXT_ARG = new NativeFunction(va(0x01493e80), "void", ["pointer", "int", "pointer", "int", "int", "pointer"], "thiscall");
const TEXT_RENDER = new NativeFunction(va(0x01890790), "pointer", ["pointer"], "thiscall");
const TEXT_DTOR = new NativeFunction(va(0x0188fc80), "void", ["pointer"], "thiscall");
const EMPTY = va(0x02426d58);

function today() {
  const doy = TODAY.readU16() & 0x1ff;
  return new Date(Date.UTC(TODAY.add(2).readU16(), 0, doy)).toISOString().slice(0, 10);
}

function decode(p) {
  if (p.isNull()) return "";
  const c = [];
  for (const f of [() => p.readUtf16String(), () => p.add(2).readUtf16String(), () => p.add(4).readUtf16String(),
                   () => p.readUtf8String(), () => p.add(1).readUtf8String()]) {
    try { c.push(f()); } catch (e) {}
  }
  const good = c.filter((s) => s && /^[\p{L}\p{M} .,'\-()&0-9]{2,60}$/u.test(s));
  return good.length ? good.sort((a, b) => b.length - a.length)[0] : "?";
}
function teamName(team) {
  try {
    const text = Memory.alloc(0x100);
    TEXT_CTOR(text);
    TEXT_SET(text, Memory.allocUtf8String("<%team#1>"));
    TEXT_ARG(text, 1, team, 0, 0, EMPTY);
    const r = TEXT_RENDER(text);
    const s = decode((r.isNull() ? text : r).readPointer());
    TEXT_DTOR(text);
    return s;
  } catch (e) {
    return "err";
  }
}

const ror = (x, n) => (n &= 31, ((x >>> n) | (x << (32 - n))) >>> 0);
function handBalance(fin) {
  const p = fin.add(0xc);
  let x = ~ror(p.readU32(), 7) >>> 0;
  x = ~ror(x, p.toUInt32() & 31) >>> 0;
  return ror(x, 5) | 0;
}

// Per-day aggregates, flushed when the date changes; individual records go out as events.
let day = null;
let agg = {};
function bump(key, amount) {
  const c = agg[key] || (agg[key] = { n: 0, sum: 0 });
  c.n++;
  if (amount !== undefined) c.sum += amount;
}
function event(kind, data) { send({ event: Object.assign({ date: day, kind }, data) }); }
function flushDay() {
  const d = today();
  if (d === day) return;
  if (day !== null) send({ day: { date: day, agg } });
  day = d;
  agg = {};
  recheckTeams();
}
const capped = {};
function limit(key, n) { return (capped[key] = (capped[key] || 0) + 1) <= n; }
function bt(ctx) { return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, 6).map(rva).join(" "); }

// F1: balance getter against the hand decode, on the monthly routine (thiscall singleton, arg0 = fin).
Interceptor.attach(va(0x00b8a700), {
  onEnter(args) {
    flushDay();
    const fin = args[0];
    try {
      const g = GET_BALANCE(fin), h = handBalance(fin);
      bump("F1 balance " + (g === h ? "match" : "MISMATCH"));
      if (g !== h || limit("F1", 5)) event("F1", { fin: fin.toString(), getter: g, hand: h });
    } catch (e) { bump("F1 error " + e); }
    bump("F8 monthly routine calls");
  },
});

// F8: month-start loop boundaries.
Interceptor.attach(va(0x0063e9b8), { onEnter() { flushDay(); bump("F8 loop start"); event("F8", { at: "start" }); } });
Interceptor.attach(va(0x0063e9f7), { onEnter() { flushDay(); bump("F8 after loop"); } });

// F2/F3: CompPay comp level, ACT+0x93 copy, international flag, finance reverse link.
Interceptor.attach(va(0x0091a160), {
  onEnter(args) {
    flushDay();
    const club = args[0], act = args[2], type = args[5].toInt32() & 0xff;
    let level = "?", a93 = "?", intl = "?", link = "?";
    try {
      const comp = act.add(0x3c).readPointer();
      level = comp.add(0xdd).readS8();
      a93 = act.add(0x93).readS8();
      intl = comp.add(0x44).readPointer().isNull() ? "intl" : "dom";
    } catch (e) {}
    try { link = club.add(0x9c).readPointer().add(8).readPointer().equals(club) ? "ok" : "BAD"; } catch (e) {}
    bump(`F2 CompPay type=${type} level=${level} act93=${a93} ${intl} link=${link}`, args[1].toInt32());
  },
});

// F5: final tables at the league-stage position prize. Remember teams to re-read +0x67 later (F4).
const watchedTeams = [];
Interceptor.attach(va(0x01018700), {
  onEnter() {
    flushDay();
    const stage = this.context.ecx;
    try {
      const n = stage.add(0x44).readS8();
      const rows = stage.add(0x38).readPointer();
      const act = stage.add(0x28).readPointer();
      let level = "?";
      try { level = act.add(0x3c).readPointer().add(0xdd).readS8(); } catch (e) {}
      const table = [];
      for (let i = 0; i < n && i < 48; i++) {
        const team = rows.add(4 * i).readPointer().add(0x30).readPointer();
        table.push({ pos: i, name: teamName(team), last67: team.add(0x67).readU8() });
        if (watchedTeams.length < 200) watchedTeams.push({ team, name: table[i].name, finalPos: i + 1, seen: team.add(0x67).readU8() });
      }
      event("F5", { stage: stage.toString(), n, level, table });
    } catch (e) { event("F5", { error: String(e) }); }
  },
});
// F4: report when a watched team's +0x67 changes (expect: becomes the 1-based final position).
function recheckTeams() {
  for (const w of watchedTeams) {
    try {
      const v = w.team.add(0x67).readU8();
      if (v !== w.seen) { event("F4", { name: w.name, finalPos: w.finalPos, from: w.seen, to: v }); w.seen = v; }
    } catch (e) {}
  }
}

// F9: competition finished (ecx = ACTUAL_COMP).
Interceptor.attach(va(0x00fad710), {
  onEnter() {
    flushDay();
    const act = this.context.ecx;
    const r = { act: act.toString() };
    try { r.vft = rva(act.readPointer()); } catch (e) {}
    try { r.a85 = act.add(0x85).readU8(); r.afc = act.add(0xfc).readU32(); } catch (e) {}
    try { r.a68_18 = act.add(0x68).readPointer().add(0x18).readU32(); } catch (e) {}
    try { const c = act.add(0x3c).readPointer(); r.level = c.add(0xdd).readS8(); r.intl = c.add(0x44).readPointer().isNull(); } catch (e) {}
    event("F9", r);
  },
});

// F6: season rollover (ecx = fin): season block moves to last season and is zeroed.
const SNAP = [0x254, 0x2f8, 0x288, 0x32c];
Interceptor.attach(va(0x016842b0), {
  onEnter() {
    flushDay();
    this.fin = this.context.ecx;
    try { this.before = SNAP.map((o) => this.fin.add(o).readS32()); } catch (e) {}
    bump("F6 rollover");
  },
  onLeave() {
    if (!this.before || !limit("F6", 6)) return;
    try {
      event("F6", { fin: this.fin.toString(), offsets: SNAP.map((o) => "+0x" + o.toString(16)), before: this.before,
                    after: SNAP.map((o) => this.fin.add(o).readS32()), d45c: this.fin.add(0x45c).readU32() });
    } catch (e) {}
  },
});

// F7: owner monthly logic: who calls it.
Interceptor.attach(va(0x0097b310), {
  onEnter() { flushDay(); bump("F7 owner logic from " + rva(this.returnAddress)); },
});

// Transfer payments (cdecl-ish: amount, payer, payee, ?, type byte, offer).
Interceptor.attach(va(0x0085ba90), {
  onEnter(args) {
    flushDay();
    const amount = args[0].toInt32(), type = args[4].toInt32() & 0xff, offer = args[5];
    const caller = rva(this.returnAddress);
    let ovft = "none", ofee = null;
    if (!offer.isNull()) {
      try { ovft = rva(offer.readPointer()); ofee = offer.add(0x18).readS32(); } catch (e) { ovft = "bad"; }
    }
    bump(`T pay type=${type} offer=${ovft} from ${caller}`, amount);
    if (amount !== 0 && limit("T" + type + caller, 4)) event("T", { amount, type, caller, ovft, ofee, bt: bt(this.context) });
  },
});
Interceptor.attach(va(0x00e7d410), {
  onEnter() {
    flushDay();
    try {
      const m = this.context.ecx;
      bump("T instalment list size=" + ((m.add(0x68).readU32() - m.add(0x64).readU32()) / 4));
    } catch (e) {}
  },
});

// Owner money routes: investment, disguised sponsorship, Other In.
function owner(name, fin, amount, ctx, ret) {
  const r = { name, amount, caller: rva(ret), bt: bt(ctx) };
  try {
    r.balance = GET_BALANCE(fin);
    r.b8 = fin.add(0xb8).readS32();
    r.a0 = fin.add(0xa0).readS32();
    r.clubA9 = fin.add(8).readPointer().add(0xa9).readU8();
  } catch (e) { r.err = String(e); }
  bump(`O ${name} from ${r.caller}`, amount);
  if (limit("O" + name + r.caller, 6)) event("O", r);
}
Interceptor.attach(va(0x01e36f80), {
  onEnter(args) { flushDay(); owner("InvestmentIn flag=" + args[2].toInt32(), args[0], args[1].toInt32(), this.context, this.returnAddress); },
});
Interceptor.attach(va(0x00e0e6d0), {
  onEnter(args) { flushDay(); owner("DisguisedSponsor", args[0], args[1].toInt32(), this.context, this.returnAddress); },
});
Interceptor.attach(va(0x01680540), {
  onEnter(args) { flushDay(); owner("OtherIn", this.context.ecx, args[0].toInt32(), this.context, this.returnAddress); },
});

setInterval(() => { try { flushDay(); } catch (e) {} }, 500);
send({ ready: mod.base.toString(), date: today() });
