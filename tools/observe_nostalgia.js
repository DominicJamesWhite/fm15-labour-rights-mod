// Frida agent for observe_nostalgia.py: watches a running fm.exe in nostalgia mode and counts what
// the transfer market, contracts and squad rules actually do. Read-only apart from Frida's hooks.
// Addresses are Ghidra VAs (image base 0x400000), rebased onto the loaded module.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + p.sub(mod.base).add(0x400000).toString(16);
const hex = (bytes) => Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, "0")).join(" ");

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

// stats[key] = {n, bad, sum, max, examples}; "bad" marks results that contradict nostalgia rules.
const stats = {};
function record(key, bad, value, example) {
  const s = stats[key] || (stats[key] = { n: 0, bad: 0, sum: 0, max: 0, examples: [] });
  s.n++;
  if (bad) {
    s.bad++;
    if (example && s.examples.length < 3) s.examples.push(example);
  }
  if (value !== null && value !== undefined) {
    s.sum += value;
    if (value > s.max) s.max = value;
  }
}

function offerInfo(offer) {
  try {
    const vft = offer.readPointer().sub(mod.base).add(0x400000).toInt32() >>> 0;
    return {
      cls: OFFER_CLASSES[vft] || "vft_0x" + vft.toString(16),
      fee: offer.add(0x18).readS32(),
      // byte +0x3a = 3: transfer of a player whose contract is running out / has run out
      // (fee = compensation), per reports/bosman
      outOfContract: offer.add(0x3a).readU8() === 3,
    };
  } catch (e) {
    return { cls: "unreadable", fee: 0, outOfContract: false };
  }
}

function safeAttach(addr, callbacks, label) {
  try {
    Interceptor.attach(va(addr), callbacks);
  } catch (e) {
    record("observer could not hook " + label, true, null, String(e));
  }
}

let cfg = null;

recv("start", (msg) => {
  cfg = msg;

  // Transfer windows: the global flag must stay 0, and the window lookup must answer "open".
  setInterval(() => {
    const flag = va(0x02392459).readU8();
    record("transfer windows flag (0 = no windows)", flag !== 0, null, "flag = " + flag);
  }, 15000);

  // Accepted offers: what moved, and for how much.
  safeAttach(0x00ca6360, {
    onEnter(args) {
      const o = offerInfo(args[0]);
      if (o.cls === "TRANSFER_OFFER" || o.cls === "FULL_TRANSFER_OFFER") {
        if (o.outOfContract) {
          record("accepted move of an out-of-contract / expiring player (fee = compensation)", o.fee <= 0,
            o.fee, `fee ${o.fee} (should be > 0: compensation is due at any age)`);
        } else {
          record("accepted transfer of a contracted player", false, o.fee);
        }
      } else {
        record("accepted " + o.cls, false, o.fee);
      }
    },
  }, "accept_offer");

  safeAttach(0x008fad90, {
    onEnter(args) {
      const o = offerInfo(args[0]);
      record("rejected " + o.cls + " (reason 0x" + (args[4].toInt32() >>> 0).toString(16) + ")", false, o.fee);
    },
  }, "reject_offer");

  // Compensation: is it due (FUN_00ea7fc0 -> AL), and how much (FUN_006d4d20 -> EAX).
  safeAttach(0x00ea7fc0, {
    onLeave(retval) {
      record("compensation due? (expect nearly always yes)", (retval.toInt32() & 0xff) === 0, null,
        "no (only real non-club cases should say no)");
    },
  }, "compensation_due");
  safeAttach(0x006d4d20, {
    onLeave(retval) {
      const amount = retval.toInt32();
      // > 0 expected; young high-value players keep vanilla's larger amounts
      record("compensation amount (expect > 0)", amount <= 0, amount, "amount " + amount);
    },
  }, "compensation_amount");

  // Contracts: the daily expiry check, the rollover cave, and release payouts.
  safeAttach(0x007cb2d0, { onEnter() { record("activity: daily contract checks", false, null); } }, "contract_check");
  if (cfg.retainCave) {
    // mid-function address: probe form, no return trap (an object listener there can overwrite [esp])
    safeAttach(cfg.retainCave, function () {
      record("contract rolled over a year on the same terms (instead of expiring)", false, null);
    }, "retain cave");
  }
  safeAttach(0x0047ca40, {
    onLeave(retval) {
      record("release payout (club ends a contract early)", false, retval.toInt32());
    },
  }, "release_payout");

  // Squad rules: every evaluation of a foreign-player rule (FUN_00f8a750, ECX = rule, arg0 = count).
  // Types: 0x02 foreign in XI, 0x04 foreign in match squad, 0x15 foreign in squad.
  safeAttach(0x00f8a750, {
    onEnter(args) {
      const rule = this.context.ecx;
      this.type = rule.add(0xc).readU16();
      if (this.type === 0x02 || this.type === 0x04 || this.type === 0x15) {
        this.value = rule.add(8).readS32();
        this.cmp = rule.add(0xe).readS8();
        this.count = args[0].toInt32();
      } else {
        this.type = -1;
      }
    },
    onLeave(retval) {
      if (this.type < 0) return;
      const ok = retval.toInt32() & 0xff;
      const name = { 2: "foreign in starting XI", 4: "foreign in match squad", 0x15: "foreign in squad" }[this.type];
      // INFO only: the AI selector and UI also evaluate candidate squads, so a "broke" result is
      // not proof that a team fielded too many foreigners.
      record(`activity: rule check ${name} <= ${this.value} (incl. candidate squads)`, !ok, this.count,
        `count ${this.count} over ${this.value}`);
    },
  }, "rule_satisfied");

  // AI transfer-listing (squad building): how often AI clubs put players up for sale. The surplus
  // ladder of nostalgia_foreign_cap_ai (cave 0x020c1c00-0x020c1e00) calls the inner listing routine
  // FUN_00e5f250 directly for senior foreigners outside the club's best 3 by current ability.
  safeAttach(0x00e5f250, {
    onEnter() {
      const r = this.returnAddress;
      if (r.compare(va(0x020c1c00)) >= 0 && r.compare(va(0x020c1e00)) < 0) {
        record("activity: AI transfer-listed a surplus foreigner (senior, outside its best 3 by ability)", false, null);
      } else {
        record("activity: AI transfer-listed a player (other reasons)", false, null);
      }
    },
  }, "transfer_list");

  // Integrity: every nostalgia patch still in memory.
  setInterval(() => {
    for (const p of cfg.patches) {
      // Frida hooks (ours and trace_foreign_cap's) put a 5-byte jmp at hooked instructions inside
      // the caves, so a difference starting with e9 and no longer than 8 bytes is a hook, not a loss.
      const found = new Uint8Array(va(p.va).readByteArray(p.len));
      const want = p.patched.split(" ").map((x) => parseInt(x, 16));
      let lost = false;
      for (let i = 0; i < p.len; i++) {
        if (found[i] === want[i]) continue;
        let j = i;
        while (j < p.len && found[j] !== want[j]) j++;
        if (found[i] !== 0xe9 || j - i > 8) lost = true;
        i = j;
      }
      record("patch present: " + p.name, lost, null, `0x${p.va.toString(16)}: ${hex(found.buffer)}`);
    }
  }, 60000);

  setInterval(() => send({ stats }), 15000);
  send({ ready: mod.base.toString() });
});
