// Frida agent: logs squad-selection rule checks in a running fm.exe.
// FUN_00f8a750 (thiscall, ECX = rule: value +0x8, type u16 +0xc, compare byte +0xe) answers
// "is this rule satisfied for count N". Run with tools/trace_squad_rules.py.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + p.sub(mod.base).add(0x400000).toString(16);

const counts = {};
function bump(key) {
  counts[key] = (counts[key] || 0) + 1;
}

Interceptor.attach(va(0x00f8a750), {
  onEnter(args) {
    const rule = this.context.ecx;
    this.key = "type=0x" + rule.add(0xc).readU16().toString(16) +
      " cmp=" + rule.add(0xe).readS8() + " value=" + rule.add(0x8).readS32() +
      " count=" + args[0].toInt32() + " from " + rva(this.returnAddress);
  },
  onLeave(retval) {
    bump(this.key + " -> " + (retval.toInt32() & 0xff));
  },
});

// "places left" helper that reads rules without going through FUN_00f8a750
Interceptor.attach(va(0x00f8ba60), {
  onEnter() {
    bump("places_left_helper from " + rva(this.returnAddress));
  },
});

setInterval(() => send(counts), 15000);
send({ ready: mod.base.toString() });
