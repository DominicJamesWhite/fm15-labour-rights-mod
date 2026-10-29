// Frida agent: counts what the AI's squad-building code does in a running fm.exe, so a holiday
// shows whether AI clubs still behave as if fees, loans, windows and squad caps exist.
// Addresses are Ghidra VAs (image base 0x400000), rebased onto the loaded module.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + p.sub(mod.base).add(0x400000).toString(16);

const counts = {};
function bump(key, value) {
  const c = counts[key] || (counts[key] = { n: 0, max: 0, sum: 0 });
  c.n++;
  if (value !== undefined && value !== null) {
    c.sum += value;
    if (value > c.max) c.max = value;
  }
}

// TC_SHORTLIST::calculate_cost_of_transfer (cdecl: type, ..., flag): the AI's cost estimate per
// target type. With ai_fee_free_targets, type 4/13 costs should be wages only (or 0).
Interceptor.attach(va(0x0095cfe0), {
  onEnter(args) {
    this.type = args[0].toInt32() & 0xff;
    this.flag = args[5].toInt32() & 0xff;
  },
  onLeave(retval) {
    const cost = retval.toInt32();
    bump("cost type=" + this.type + " withContract=" + this.flag + (cost > 0 ? " >0" : " =0"), cost);
  },
});

// TC_SHORTLIST::make_transfer_decision_for_player (thiscall, 8 stack args; the 8th is a char*
// reason out). Reason 2 is "costs more than the budget", 5 "over budget/wage budget".
Interceptor.attach(va(0x00517b20), {
  onEnter(args) {
    // Read-only: remember the out pointer and its value on entry, report what it holds on exit.
    this.reason = args[7];
    try { this.before = this.reason.readU8(); } catch (e) { this.reason = null; }
  },
  onLeave(retval) {
    let r = -1;
    try { if (this.reason) r = this.reason.readU8(); } catch (e) {}
    bump("decision ret=" + (retval.toInt32() & 0xff) + " reason=" + r + (r === this.before ? " (unchanged)" : ""));
  },
});

const simple = {
  0x00b7c870: "make_transfer_offer",
  0x0057dcc0: "make_free_transfer_offer",
  0x00919690: "free_transfer_contract_offer",
  0x00579410: "trial_offer_instead_of_contract",
  0x00f26870: "create_loan_offer",
  0x00f32700: "ai_release_batch",
  0x00f8ba60: "squad_cap_rule_lookup",
  0x00f8bab0: "squad_cap_value_lookup",
};
for (const [addr, name] of Object.entries(simple)) {
  Interceptor.attach(va(Number(addr)), {
    onEnter() { this.caller = rva(this.returnAddress); },
    onLeave(retval) {
      const v = retval.toInt32();
      const tag = name.startsWith("squad_cap") ? (name.endsWith("value_lookup") ? " value=" + v : (v === 0 ? " none" : " found")) : "";
      bump(name + tag + " from " + this.caller);
    },
  });
}

// FUN_004a7790 (cdecl: person, club, amount, type, out): pays a release; amount = what it cost.
Interceptor.attach(va(0x004a7790), {
  onEnter(args) {
    bump("release_payment from " + rva(this.returnAddress), args[2].toInt32());
  },
});

setInterval(() => send(counts), 15000);
send({ ready: mod.base.toString() });
