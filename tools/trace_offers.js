// Frida agent: logs how transfer/loan offers are accepted, rejected and priced in a running fm.exe.
// Addresses are Ghidra VAs (image base 0x400000) and are rebased onto the loaded module.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + p.sub(mod.base).add(0x400000).toString(16);

const OFFER_CLASSES = {
  0x0216bcec: "TRANSFER_OFFER",
  0x020e2fdc: "FULL_TRANSFER_OFFER",
  0x0216bac4: "LOAN_OFFER",
  0x020e31a4: "TRIAL_OFFER",
  0x020e35e0: "COOWN_OFFER",
  0x020e33c8: "ENQUIRY_OFFER",
  0x020e32bc: "DRAFT_OFFER",
  0x0216bbd0: "TRADE_OFFER",
  0x020dab34: "B_CLUB_MOVE_OFFER",
  0x020e34d4: "AGENT_OFFER",
};

function offerInfo(offer) {
  try {
    const vft = offer.readPointer().sub(mod.base).add(0x400000).toInt32() >>> 0;
    return { cls: OFFER_CLASSES[vft] || "vft_0x" + vft.toString(16), fee: offer.add(0x18).readS32() };
  } catch (e) {
    return { cls: "unreadable", fee: null };
  }
}

// Aggregate by key so long holidays don't flood the log; flushed periodically.
const counts = {};
function bump(key, fee) {
  const c = counts[key] || (counts[key] = { n: 0, maxFee: 0 });
  c.n++;
  if (fee !== null && fee > c.maxFee) c.maxFee = fee;
}

function hook(addr, name, describe) {
  Interceptor.attach(va(addr), {
    onEnter(args) {
      bump(name + " " + describe.call(this, args) + " from " + rva(this.returnAddress), this.fee ?? null);
    },
  });
}

hook(0x00ca6360, "ACCEPT", function (args) {
  const o = offerInfo(args[0]);
  this.fee = o.fee;
  return o.cls;
});
hook(0x008fad90, "REJECT", function (args) {
  const o = offerInfo(args[0]);
  this.fee = o.fee;
  return o.cls + " reason=0x" + (args[4].toInt32() >>> 0).toString(16);
});
hook(0x00abeba0, "SET_FEE", function (args) {
  const o = offerInfo(this.context.ecx);
  this.fee = args[0].toInt32();
  return o.cls;
});
hook(0x00b87d00, "should_attempt_loans", () => "");
hook(0x007f0c90, "computer_evaluate_loan_offer", () => "");
hook(0x0047ca40, "release_payout", () => "");
hook(0x00f26870, "create_loan_offer", () => "");

// FULL_TRANSFER_OFFER vfunc +0x24 (fee + installments + add-ons). Log who asks and, for the first
// non-zero totals, dump the offer's non-zero dwords so we can see which fields hold the money.
let samples = 0;
Interceptor.attach(va(0x00e71020), {
  onEnter() {
    this.offer = this.context.ecx;
    this.caller = rva(this.returnAddress);
  },
  onLeave(retval) {
    const total = retval.toInt32();
    bump("TOTAL_VALUE " + (total > 0 ? "nonzero" : "zero") + " from " + this.caller, total);
    // A few small ones for context, then only large totals so big leaks aren't missed.
    if (total > 0 && (samples < 5 || (total > 50000 && samples < 60))) {
      samples++;
      const fields = {};
      for (let off = 0; off < 0xb4; off += 4) {
        const v = this.offer.add(off).readS32();
        if (v !== 0) fields["+0x" + off.toString(16)] = v;
      }
      // Contents of the two lists the total also sums (+0x60: 0x14-byte entries, +0x6c: 0x18-byte).
      for (const [at, size] of [[0x60, 0x14], [0x6c, 0x18]]) {
        try {
          const begin = this.offer.add(at).readPointer();
          const end = this.offer.add(at + 4).readPointer();
          const n = Math.min(end.sub(begin).toInt32() / size, 4);
          for (let i = 0; i < n; i++) {
            const words = [];
            for (let w = 0; w < size; w += 4) words.push(begin.add(i * size + w).readS32());
            fields["list+0x" + at.toString(16) + "[" + i + "]"] = words.join(",");
          }
        } catch (e) {}
      }
      const cls = offerInfo(this.offer).cls;
      send({ sample: { total, cls, caller: this.caller, fields } });
    }
  },
});

setInterval(() => send(counts), 15000);
send({ ready: mod.base.toString() });
