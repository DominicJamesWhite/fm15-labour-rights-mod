// Frida agent for labour-rights mode (and parity, which inherits it): removes football-only squad
// rules from each competition's stored rule lists, so the rules screen, the AI (FM's native
// foreign-limited mode, squad planning), registration and the Fgn/homegrown badges all see no rule.
// The enforcement patches in patches_squad.py stay as a backstop for rules FM creates on the fly.
// See reports/squad/strip_rules.md. Logs to reports/squad_strip.log.
//
// FM rebuilds the lists from its database at every new game, save load and season rollover;
// FUN_01060a60 (thiscall: FIXTURE_RULES group, year) is the last writer each time, so the agent
// strips the group's active list (+0x34) and every dated sub-list (vector +0x28, entry +0xc) when
// it returns. Which types go is read from the labour-rights bitmaps (homegrown, nationality,
// non-EU, squad size), so changing patches_squad.py changes what is stripped.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);

const BITMAPS = [0x020c1420, 0x020c1440, 0x020c1460, 0x020c1480].map(va);
const ERASE = new NativeFunction(va(0x00f8dc20), "void", ["pointer", "pointer", "int"], "thiscall");
const TODAY = va(0x0239ebf4);

let logFile = null;
function log(line) {
  if (!logFile) return;
  const date = new Date(Date.UTC(TODAY.add(2).readU16(), 0, TODAY.readU16() & 0x1ff)).toISOString().slice(0, 10);
  try { logFile.write(date + " " + line + "\n"); logFile.flush(); } catch (e) {}
}

function stripped(type) {
  if (type > 0xff) return false;
  return BITMAPS.some((b) => (b.add(type >> 3).readU8() >> (type & 7)) & 1);
}

const out = Memory.alloc(4);
function stripList(list, removed) {
  if (list.isNull()) return;
  const count = list.add(4).readPointer().sub(list.readPointer()).toInt32() / 4;
  for (let i = count - 1; i >= 0; i--) {       // backwards, so indices stay valid after an erase
    const rule = list.readPointer().add(4 * i).readPointer();
    if (rule.isNull()) continue;
    const type = rule.add(0xc).readU16();
    if (!stripped(type)) continue;
    ERASE(list, out, i);
    removed[type] = (removed[type] || 0) + 1;
  }
}

Interceptor.attach(va(0x01060a60), {
  onEnter() { this.group = this.context.ecx; },
  onLeave() {
    try {
      const removed = {};
      stripList(this.group.add(0x34).readPointer(), removed);
      const begin = this.group.add(0x28).readPointer(), end = this.group.add(0x2c).readPointer();
      for (let p = begin; p.compare(end) < 0; p = p.add(4)) {
        const entry = p.readPointer();
        if (!entry.isNull()) stripList(entry.add(0xc).readPointer(), removed);
      }
      const types = Object.keys(removed);
      if (types.length) log(`group ${this.group}: removed ` + types.map((t) => `0x${(+t).toString(16)}x${removed[t]}`).join(" "));
    } catch (e) { log("strip error " + e.stack); }
  },
});

recv("config", (msg) => {
  try { logFile = new File(msg.log, "a"); } catch (e) {}
  log("squad strip agent started");
  send({ started: true });
});
