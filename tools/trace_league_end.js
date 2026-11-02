// Frida agent: when does FM mark a domestic league finished (ACTUAL_COMP+0x8c == -5) relative to
// its last league stage ending? Check L1 of reports/parity/league_playoff.md, observation only.
// Run with tools/trace_league_end.py. Read-only: hooks read memory and call only the name formatter.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + (p.sub(mod.base).add(0x400000).toUInt32() >>> 0).toString(16);
const TODAY = va(0x0239ebf4);
const tc = (addr, ret, args) => new NativeFunction(va(addr), ret, ["pointer"].concat(args || []), "thiscall");

const TEXT_CTOR = tc(0x0188f4b0, "pointer");
const TEXT_SET = tc(0x0188fd00, "void", ["pointer"]);
const TEXT_ARG = tc(0x01493e80, "void", ["int", "pointer", "int", "int", "pointer"]);
const TEXT_RENDER = tc(0x01890790, "pointer");
const TEXT_DTOR = tc(0x0188fc80, "void");
const EMPTY_TEXT = va(0x02426d58);

function today() {
  return new Date(Date.UTC(TODAY.add(2).readU16(), 0, TODAY.readU16() & 0x1ff)).toISOString().slice(0, 10);
}
function compName(comp) {
  try {
    const text = Memory.alloc(0x100);
    TEXT_CTOR(text);
    TEXT_SET(text, Memory.allocUtf8String("<%comp#1>"));
    TEXT_ARG(text, 1, comp, 0, 0, EMPTY_TEXT);
    const r = TEXT_RENDER(text), p = (r.isNull() ? text : r).readPointer();
    for (const f of [() => p.readUtf16String(), () => p.add(2).readUtf16String(), () => p.add(4).readUtf16String()]) {
      try { const s = f(); if (s && /^[\p{L}\p{M} .,'\-()&0-9]{2,60}$/u.test(s)) { TEXT_DTOR(text); return s; } } catch (e) {}
    }
    TEXT_DTOR(text);
  } catch (e) {}
  return comp.toString();
}

// ACTUAL_COMP <-> COMP@DB (ACT+0x3c, COMP+0x68). Returns {act, comp} or null.
function pair(p) {
  try {
    const comp = p.add(0x3c).readPointer();
    if (comp.add(0x68).readPointer().equals(p)) return { act: p, comp };
  } catch (e) {}
  try {
    const act = p.add(0x68).readPointer();
    if (act.add(0x3c).readPointer().equals(p)) return { act, comp: p };
  } catch (e) {}
  return null;
}
// Domestic league in the top two divisions.
function watched(pr) {
  if (!pr) return false;
  try {
    const type = pr.act.add(0x85).readU8(), level = pr.comp.add(0xdd).readS8();
    return !pr.comp.add(0x44).readPointer().isNull() && [0, 1, 14].includes(type) && level >= 0 && level <= 1;
  } catch (e) { return false; }
}
const status = (pr) => pr.act.add(0x8c).readS16();
function out(kind, pr, extra) {
  send({ event: Object.assign({ date: today(), kind, comp: compName(pr.comp), act: pr.act.toString(),
    level: pr.comp.add(0xdd).readS8(), status: status(pr) }, extra || {}) });
}

// League stage end (LEAGUE_STAGE vt+0x20, ecx = stage; stage+0x28 = its competition).
Interceptor.attach(va(0x01018650), {
  onEnter() {
    this.pr = pair(this.context.ecx.add(0x28).readPointer());
    if (!watched(this.pr)) { this.pr = null; return; }
    out("league stage end: enter", this.pr, { stage: this.context.ecx.toString() });
  },
  onLeave() { if (this.pr) out("league stage end: leave", this.pr); },
});

// Stage finished handler: log its arguments' competition and the status around it.
Interceptor.attach(va(0x00fb5370), {
  onEnter(args) {
    this.pr = pair(this.context.ecx) || pair(args[0]);
    if (!watched(this.pr)) { this.pr = null; return; }
    out("stage finished: enter", this.pr, { caller: rva(this.returnAddress), arg0: args[0].toString(), arg1: args[1].toString() });
  },
  onLeave() { if (this.pr) out("stage finished: leave", this.pr); },
});

// Status setter (thiscall ACT, s16 status).
Interceptor.attach(va(0x00fc04f0), {
  onEnter(args) {
    const pr = pair(this.context.ecx);
    if (!watched(pr)) return;
    out("status set", pr, { to: args[0].toInt32() << 16 >> 16, caller: rva(this.returnAddress) });
  },
});

// Competition finished (ecx = ACT).
Interceptor.attach(va(0x00fad710), {
  onEnter() {
    const pr = pair(this.context.ecx);
    if (watched(pr)) out("competition finished", pr);
  },
});

send({ ready: mod.base.toString(), date: today() });
