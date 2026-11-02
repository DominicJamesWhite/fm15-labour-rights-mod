// Frida agent for fm15_loader.py: writes byte patches into the running fm.exe.
// Receives {patches: [{name, va, original, patched}], writes: [{name, va, bytes}],
//           writable: [{name, va, size}]} via recv().
// writable: zeroed read-write blocks for patch code (e.g. the nostalgia sweep's per-club table). Each
// is allocated here and its address written into the patch's 4-byte pointer slot at va (a zero cave).
// Code pages keep their protection; the blocks stay referenced (and the script is eternalized), so
// they live as long as the game. A slot that is already set (loader run again) is kept.
const keepAlive = [];

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const hex = (bytes) => Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, "0")).join(" ");
const parse = (s) => s.split(" ").filter((x) => x).map((x) => parseInt(x, 16));

// Checksum shield: FM15 periodically SHA-1s its own .text in memory (tamper check; a mismatch
// silently switches to fake names). Its SHA-1 update (FUN_02050b60, thiscall: data, len) is
// redirected to an untouched copy of .text from original/fm.exe whenever it is asked to hash .text,
// so the check passes whatever has been patched or hooked in the live code.
const TEXT = va(0x00401000);
let pristine = null;
let shieldHits = 0;

recv("pristine", (msg, data) => {
  pristine = Memory.alloc(data.byteLength);
  pristine.writeByteArray(data);
  const textEnd = TEXT.add(data.byteLength);
  Interceptor.attach(va(0x02050b60), {
    onEnter(args) {
      const p = args[0];
      if (p.compare(TEXT) >= 0 && p.compare(textEnd) < 0) {
        args[0] = pristine.add(p.sub(TEXT));
        shieldHits++;
      }
    },
  });
  send({ shield: data.byteLength });
});

recv("apply", (msg) => {
  const results = [];
  for (const p of msg.patches) {
    const at = va(p.va);
    const orig = parse(p.original);
    const patched = parse(p.patched);
    const found = hex(at.readByteArray(orig.length));
    if (found === hex(new Uint8Array(patched).buffer)) {
      results.push(`${p.name} @ 0x${p.va.toString(16)}: already patched`);
      continue;
    }
    if (found !== hex(new Uint8Array(orig).buffer)) {
      results.push(`${p.name} @ 0x${p.va.toString(16)}: expected ${p.original}, found ${found}; SKIPPED`);
      continue;
    }
    Memory.patchCode(at, patched.length, (code) => code.writeByteArray(patched));
    results.push(`${p.name} @ 0x${p.va.toString(16)}: patched`);
  }
  for (const b of msg.writable || []) {
    const slot = va(b.va);
    const cur = slot.readU32();
    if (cur !== 0) {
      results.push(`${b.name} writable @ 0x${b.va.toString(16)}: already set (0x${cur.toString(16)})`);
      continue;
    }
    const block = Memory.alloc(b.size);
    block.writeByteArray(new Array(b.size).fill(0));
    keepAlive.push(block);
    Memory.patchCode(slot, 4, (code) => code.writeU32(block.toUInt32()));
    results.push(`${b.name} writable @ 0x${b.va.toString(16)}: ${b.size} bytes at ${block}`);
  }
  for (const w of msg.writes) {
    const at = va(w.va);
    const bytes = parse(w.bytes);
    Memory.protect(at, bytes.length, "rw-");
    at.writeByteArray(bytes);
    results.push(`${w.name} write @ 0x${w.va.toString(16)}: ${w.bytes}`);
  }
  // Loading a save restores some of these globals (seen: the transfer-windows flag went back to 1
  // with FM Classic's other switches), so keep re-applying them. The script is eternalized, so
  // this keeps running after the loader exits.
  if (msg.writes.length) {
    setInterval(() => {
      for (const w of msg.writes) va(w.va).writeByteArray(parse(w.bytes));
    }, 2000);
  }
  send({ done: results });
});

send({ ready: mod.base.toString() });
