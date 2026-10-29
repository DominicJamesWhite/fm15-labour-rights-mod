// Frida agent for find_checker.py: finds FM15's in-memory code checker by guarding a sample of
// .text pages and recording any instruction that READS them as data (normal play only executes
// code). A hashing loop shows up as one instruction reading many different pages.

const mod = Process.getModuleByName("fm.exe");
const toVa = (p) => p.sub(mod.base).add(0x400000).toInt32() >>> 0;
const hex = (n) => "0x" + (n >>> 0).toString(16);

const TEXT = mod.base.add(0x1000);
const TEXT_SIZE = 0x1cc0000;
const STRIDE = 0x40000; // one guarded page every 256 KB -> ~115 pages

const ranges = [];
for (let off = 0; off < TEXT_SIZE; off += STRIDE) ranges.push({ base: TEXT.add(off), size: 0x1000 });

const readers = {}; // from VA -> {pages: Set, backtraces: Set}
let executes = 0;

function arm() {
  MemoryAccessMonitor.enable(ranges, {
    onAccess(d) {
      if (d.operation === "execute") {
        executes++;
        return;
      }
      const from = toVa(d.from);
      const r = readers[from] || (readers[from] = { pages: new Set(), backtraces: new Set(), op: d.operation });
      r.pages.add(d.rangeIndex);
      if (r.backtraces.size < 3 && d.context) {
        try {
          r.backtraces.add(Thread.backtrace(d.context, Backtracer.FUZZY).slice(0, 8)
            .map((p) => hex(toVa(p))).join(" <- "));
        } catch (e) {}
      }
    },
  });
}

arm();
// Pages fire once per arming; re-arm so pages consumed by normal execution are watched again.
setInterval(() => {
  MemoryAccessMonitor.disable();
  arm();
}, 20000);

setInterval(() => {
  const out = {};
  for (const [from, r] of Object.entries(readers)) {
    out[hex(Number(from))] = { pages: r.pages.size, op: r.op, backtraces: Array.from(r.backtraces) };
  }
  send({ readers: out, executes, watched: ranges.length });
}, 15000);
send({ ready: ranges.length });
