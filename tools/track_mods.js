// Frida agent for track_mods.py: checks in a running fm.exe that every labour-rights patch is in
// memory and doing its job. Addresses are Ghidra VAs (image base 0x400000).

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const hex = (p, n) => Array.from(new Uint8Array(p.readByteArray(n))).map((b) => b.toString(16).padStart(2, "0")).join(" ");

const stats = {};
function stat(key) {
  return stats[key] || (stats[key] = { n: 0, bad: 0, max: 0, sum: 0, examples: [] });
}
function record(key, ok, value, example) {
  const s = stat(key);
  s.n++;
  if (!ok) {
    s.bad++;
    if (example && s.examples.length < 5) s.examples.push(new Date().toTimeString().slice(0, 8) + " " + example);
  }
  if (typeof value === "number") {
    s.sum += value;
    if (value > s.max) s.max = value;
  }
}

const OFFER_CLASSES = {
  0x0216bcec: "TRANSFER_OFFER", 0x020e2fdc: "FULL_TRANSFER_OFFER", 0x0216bac4: "LOAN_OFFER",
  0x020e31a4: "TRIAL_OFFER", 0x020e35e0: "COOWN_OFFER", 0x020e33c8: "ENQUIRY_OFFER",
  0x020e32bc: "DRAFT_OFFER", 0x0216bbd0: "TRADE_OFFER", 0x020dab34: "B_CLUB_MOVE_OFFER",
  0x020e34d4: "AGENT_OFFER",
};
function offerClass(offer) {
  try {
    const vft = offer.readPointer().sub(mod.base).add(0x400000).toInt32() >>> 0;
    return OFFER_CLASSES[vft] || "other";
  } catch (e) {
    return "unreadable";
  }
}

// Sites the hooks below overwrite with Frida trampolines; integrity re-checks skip them. Where a
// patched function starts with our own jmp into a cave, Frida hooks the cave instead, so the cave
// entries are listed too.
const HOOKED = [0x00b87d00, 0x00f8a750, 0x00f8ba60, 0x00f8bab0, 0x020c15b0, 0x020c14e0, 0x020c15e8];
let patchList = [];
let flagWrites = [];

function checkIntegrity(initial) {
  for (const p of patchList) {
    if (!initial && HOOKED.some((h) => p.va <= h && h < p.va + p.len)) continue;
    const found = hex(va(p.va), p.len);
    record("integrity " + p.name, found === p.patched, null, `0x${p.va.toString(16)}: ${found}`);
  }
  for (const w of flagWrites) {
    const found = hex(va(w.va), w.len);
    record("integrity " + w.name + " flag", found === w.bytes, null, `0x${w.va.toString(16)}: ${found}`);
  }
}

function installHooks() {
  // --- no_loans ---
  Interceptor.attach(va(0x00b87d00), {
    onLeave(r) { record("loans: AI asked 'should we look for loans?' (expect always no)", (r.toInt32() & 0xff) === 0); },
  });

  // --- accept / reject: loans never accepted; transfers accepted by the selling club at £0 ---
  const acceptFromCave = va(0x00e6604f).toString();
  Interceptor.attach(va(0x00ca6360), {
    onEnter(args) {
      const cls = offerClass(args[0]);
      if (cls === "LOAN_OFFER") record("loans: loan offers accepted (expect none)", false, null, "accepted a loan");
      if (cls === "FULL_TRANSFER_OFFER" || cls === "TRANSFER_OFFER") {
        const viaCave = this.returnAddress.toString() === acceptFromCave;
        record("notice_player_side: transfer offers accepted by selling club on arrival", viaCave, null,
          "accepted via another path");
      }
    },
  });
  Interceptor.attach(va(0x008fad90), {
    onEnter(args) {
      if (offerClass(args[0]) === "LOAN_OFFER") record("loans: loan offers rejected", true);
    },
  });

  // --- fees: the game's own total value of a transfer offer at acceptance (caller 0xca63b5) ---
  const acceptTotalCaller = va(0x00ca63b5).toString();
  Interceptor.attach(va(0x00e71020), {
    onEnter() { this.atAccept = this.returnAddress.toString() === acceptTotalCaller; },
    onLeave(r) {
      if (!this.atAccept) return;
      const total = r.toInt32();
      record("fees: total value of transfer offers at acceptance (expect £0)", total <= 0, total, `£${total}`);
    },
  });

  // --- notice: release payouts capped at 14 days' wages, including mutual terminations ---
  const capped = new Map(); // person -> capped payout from FUN_0047ca40
  Interceptor.attach(va(0x0047ca40), {
    onEnter(args) { this.person = args[0].toString(); },
    onLeave(r) { capped.set(this.person, r.toInt32()); },
  });
  Interceptor.attach(va(0x004a7790), {
    onEnter(args) {
      const amount = args[2].toInt32();
      const cap = capped.get(args[0].toString());
      const ok = cap === undefined || amount <= cap + 1;
      record("notice: release payments no bigger than 14 days' wages", ok, amount,
        `paid £${amount}, cap £${cap}`);
    },
  });

  // --- squad rules: disabled rule types always count as satisfied ---
  const bitmaps = [0x020c1420, 0x020c1440, 0x020c1460, 0x020c1480, 0x020c14a0, 0x020c14c0]
    .map((a) => new Uint8Array(va(a).readByteArray(32)));
  const disabled = (t) => bitmaps.some((b) => (b[t >> 3] >> (t & 7)) & 1);
  Interceptor.attach(va(0x00f8a750), {
    onEnter() { this.type = this.context.ecx.add(0xc).readU16(); },
    onLeave(r) {
      if (!disabled(this.type)) return;
      record("squad rules: disabled rule checks answered 'satisfied'", (r.toInt32() & 0xff) === 1, null,
        "type 0x" + this.type.toString(16) + " not satisfied");
    },
  });
  Interceptor.attach(va(0x00f8ba60), {
    onLeave(r) { record("squad_rules_counters: squad cap lookups say 'no cap'", r.isNull(), null, "cap rule found"); },
  });
  Interceptor.attach(va(0x00f8bab0), {
    onLeave(r) { record("squad_rules_counters: squad cap value lookups say 'no cap'", r.toInt32() === -1, null, "value " + r.toInt32()); },
  });

  // --- AI: estimated transfer fee for contracted players (types 4/13, fee only) is £0 ---
  Interceptor.attach(va(0x0095cfe0), {
    onEnter(args) {
      this.type = args[0].toInt32() & 0xff;
      this.withContract = args[5].toInt32() & 0xff;
    },
    onLeave(r) {
      if ((this.type === 4 || this.type === 13) && this.withContract === 0) {
        record("ai_fee_free_targets: AI fee estimate for contracted players (expect £0)", r.toInt32() === 0, r.toInt32());
      }
    },
  });

  // --- activity counters (no pass/fail) ---
  Interceptor.attach(va(0x00b7c870), { onEnter() { record("activity: AI transfer offers made", true); } });
  Interceptor.attach(va(0x0057dcc0), { onEnter() { record("activity: AI free-agent offers made", true); } });
}

recv("start", (msg) => {
  patchList = msg.patches;
  flagWrites = msg.writes;
  checkIntegrity(true);
  installHooks();
  setInterval(() => { checkIntegrity(false); send({ stats }); }, 15000);
  send({ stats });
});
send({ ready: true });
