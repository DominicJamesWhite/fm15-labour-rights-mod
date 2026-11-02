// Frida agent: traces the nostalgia foreign-player cap (patcher/patches_foreign_cap.py) in a running
// fm.exe. Read-only apart from Frida's own hooks. Run with tools/trace_foreign_cap.py after the loader
// has applied the patches (it detects which are present and hooks accordingly).
//
// Counted lines:
//   mode ...                                    which patches were found in memory
//   check <gate> -> over cap|ok                  the cap checker, by caller (ai / surplus / offer / join)
//   surplus: listed for sale / listed for loan   surplus foreigners listed by the surplus hook
//   surplus: not listed (reason)                 surplus foreigners skipped (on loan, move arranged, contract type)
//   surplus release: full F, settled S (P%)      releases of unsold surplus foreigners (wages for the rest of
//                                                the contract, and the settlement actually paid)
//   offer accepted for a loan-listed player ...  accepted offers (loans: offer type of loans) for loan-listed players
//   AI squad review ran                          FUN_006296b0 calls (how often surplus can trigger)
//   AI selector rules: ...                       FUN_00852050's rule list: are the 3+2 rules in it?
//   stored rules (club use): ...                 each competition rule group's STORED list (3+2 stored there)
//   fixture list from FUN_01062190: ...          match-day lists built from them for club fixtures
//   rules list from <builder>: ...               lists built for clubs: types 0x04 / 0x15 present?
//   rule 0x04|0x15 value V count C -> ok|broken  the game evaluating the cap rules (FUN_00f8a750)
//   offer validity -> result R reason X          FUN_006f69f0 (1/2 = offer fails; 0x29 = squad rules)
//   squad status set to S by ...                 contract squad-status writes (7 = Not Needed), as written
//                                                after the status hook
//   status hook: re-rating to S kept at 7 ...    re-ratings of listed surplus foreigners turned into 7
//   review: listed surplus player at status S... KEEP7 in the surplus review found a status other than 7
//   status S written for a listed SURPLUS ...    must stay 0: a non-7 status reached a surplus player
//   transfer listing reason R from ...           FUN_00e5f250 calls (0x0f list, 0x12 list/release)
//   bid valuation / value = X (listed|not)       selling club's valuation in AI bid evaluation

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const rva = (p) => "0x" + p.sub(mod.base).add(0x400000).toString(16);
const inRange = (p, lo, hi) => p.compare(va(lo)) >= 0 && p.compare(va(hi)) < 0;
const patched = (a) => va(a).readU8() === 0xe9;

const counts = {};
function bump(key) {
  counts[key] = (counts[key] || 0) + 1;
}

const rulesOn = patched(0x01063090);
const aiOn = patched(0x006296b0);
const signingOn = patched(0x00b9c670);
const p32On = patched(0x01062190);  // stored foreign rule (nostalgia_3_foreigners; formerly 3+2)
const statusOn = patched(0x015c8920);  // squad-status hook (nostalgia_foreign_cap_ai, cave 0x020c1600)
const MAGIC = 0x3250334e;  // ref (+0x4) of the 3+2 "non-assimilated" rule
bump("mode: stored foreign rule " + (p32On ? "ON" : "off") + ", rules " + (rulesOn && !p32On ? "ON" : "off") +
  ", ai " + (aiOn ? "ON" : "off") + " (status hook " + (statusOn ? "ON" : "off") + "), signing block " +
  (signingOn ? "ON" : "off"));


// Cave addresses move when patches_foreign_cap.py changes, so find them in memory: the return
// address after a call to `target` inside [lo, hi), or the target of the first call there.
function callSite(lo, hi, target) {
  for (let a = va(lo); a.compare(va(hi)) < 0; a = a.add(1)) {
    if (a.readU8() === 0xe8 && a.add(5).add(a.add(1).readS32()).equals(va(target))) return a.add(5);
  }
  return null;
}
function firstCallTarget(lo, hi, after) {
  for (let a = va(lo); a.compare(va(hi)) < 0; a = a.add(1)) {
    if (a.readU8() === 0xe8 && (!after || a.sub(2).readU8() === 0x6a)) return a.add(5).add(a.add(1).readS32());
  }
  return null;
}
// CHECK (0x020c1e00): with nostalgia_foreign_cap_ai, the surplus test (senior foreigner outside the
// club's best 3 by current ability); with the optional nostalgia_foreign_cap, the old value-ranked cap.
const CHECK_FN = (aiOn || signingOn) ? va(0x020c1e00) : null;
const RET_LIST = callSite(0x020c1c00, 0x020c1e00, 0x00e5f250);
const RET_PAYOUT = callSite(0x020c1c00, 0x020c1e00, 0x0047ca40);
const RET_RELEASE = callSite(0x020c1c00, 0x020c1e00, 0x00ebf920);
let SINK = null;
for (let a = va(0x020c1c00); a.compare(va(0x020c1e00)) < 0; a = a.add(1)) {
  // SINK(reason): "push 1 ; call SINK" in the surplus cave
  if (a.readU8() === 0x6a && a.add(1).readU8() === 0x01 && a.add(2).readU8() === 0xe8) {
    const t = a.add(7).add(a.add(3).readS32());
    if (inRange(t, 0x020c1c00, 0x020c1e00)) { SINK = t; break; }
  }
}

function gateOf(ret) {
  if (signingOn && inRange(ret, 0x020c1740, 0x020c1790)) return "ai target (optional signing block)";
  if (inRange(ret, 0x020c1790, 0x020c17f0)) return "offer";
  if (inRange(ret, 0x020c17f0, 0x020c1840)) return "join";
  if (inRange(ret, 0x020c1c00, 0x020c1e00)) return "surplus";
  if (inRange(ret, 0x020c1e00, 0x020c2000)) return "check";
  if (inRange(ret, 0x020c1600, 0x020c16c8)) return "status hook (IS_SURPLUS)";
  return "other " + rva(ret);
}

// Rule list (vector of rule pointers): size and any type 0x04 / 0x15 rule.
function describeList(list) {
  if (list.isNull()) return "null";
  const begin = list.readPointer();
  const n = list.add(4).readPointer().sub(begin).toInt32() >> 2;
  let found = "";
  for (let i = 0; i < n && i < 32; i++) {
    const rule = begin.add(i * 4).readPointer();
    const type = rule.add(0xc).readU16();
    if (type === 0x04 || type === 0x15) {
      found += " 0x" + type.toString(16) + (rule.add(4).readU32() === MAGIC ? "[non-assimilated]" : "") +
        "<=" + rule.add(8).readS32() + "(cmp " + rule.add(0xe).readS8() + ")";
    }
  }
  return "size " + n + (found || " no foreign rule");
}

if (aiOn || signingOn) {
  if (CHECK_FN) Interceptor.attach(CHECK_FN, {  // CHECK(ctx, player, flags) -> AL
    onEnter() {
      this.gate = gateOf(this.returnAddress);
    },
    onLeave(retval) {
      bump("check " + this.gate + " -> " + ((retval.toInt32() & 0xff) ? "over cap" : "ok"));
    },
  });
}
// --- surplus ladder (nostalgia_foreign_cap_ai, cave 0x020c1c00) ------------------------------------
// listing: FUN_00e5f250 called from the surplus cave = listed for sale + for loan
Interceptor.attach(va(0x00e5f250), {
  onEnter() {
    if (RET_LIST && this.returnAddress.equals(RET_LIST)) {
      bump("surplus: listed for sale");
      bump("surplus: listed for loan");
    }
  },
});
// refusals: SINK(reason) in the surplus cave
const REFUSED = { 1: "on loan elsewhere", 2: "move already arranged", 3: "contract type" };
if (aiOn && SINK) {
  Interceptor.attach(SINK, {
    onEnter(args) {
      bump("surplus: not listed (" + (REFUSED[args[0].toInt32()] || args[0].toInt32()) + ")");
    },
  });
}
// releases: full payout (FUN_0047ca40 called from the surplus cave) and the settlement passed to the release
let lastFull = 0;
Interceptor.attach(va(0x0047ca40), {
  onLeave(retval) {
    if (RET_PAYOUT && this.returnAddress.equals(RET_PAYOUT)) lastFull = retval.toInt32();
  },
});
Interceptor.attach(va(0x00ebf920), {
  onEnter(args) {
    if (!RET_RELEASE || !this.returnAddress.equals(RET_RELEASE)) return;
    const settled = args[4].toInt32();
    const pct = lastFull > 0 ? Math.round((settled * 100) / lastFull) : 0;
    bump("surplus release: full " + lastFull + ", settled " + settled + " (" + pct + "%)");
    bump("surplus releases (count)");
    if (lastFull === 0) bump("surplus releases with a 0 payout (transition before 1 Sep 2014: free)");
  },
});
// loans agreed: accept_offer (FUN_00ca6360, arg 0 = offer) for players listed for loan (+0x32 bit 3)
const offerPerson = new NativeFunction(va(0x008f8840), "pointer", ["pointer"], "thiscall");
Interceptor.attach(va(0x00ca6360), {
  onEnter(args) {
    try {
      const offer = args[0];
      const type = new NativeFunction(offer.readPointer().add(0x48).readPointer(), "uint8", ["pointer"], "thiscall")(offer);
      const person = offerPerson(offer);
      if (person.isNull()) return;
      const contract = new NativeFunction(person.readPointer().add(0x1d8).readPointer(), "pointer", ["pointer"], "thiscall")(person);
      if (contract.isNull()) return;
      const flags = contract.add(0x32).readU8();
      if (flags & 8) bump("offer accepted for a loan-listed player: offer type " + type + ((flags & 1) ? " (also transfer-listed)" : ""));
    } catch (e) {
      bump("accept_offer trace error");
    }
  },
});
// FUN_006296b0 body, after the surplus hook. Mid-function ([esp] = saved ESI, not a return address), so
// Frida's probe form (a plain function): an {onEnter} object listener may replace [esp] with its
// return trap, corrupting the saved register (see reports/transfer_ai/README.md, crash audit).
Interceptor.attach(va(0x006296b6), function () {
  bump("AI squad review ran (FUN_006296b0)");
});
Interceptor.attach(va(0x00852050), {  // AI match-day selector: rules -> constraints
  onEnter(args) {
    bump("AI selector rules: " + describeList(args[0]));
  },
});
// Stored competition rule lists (nostalgia_3_plus_2 stores 3+2 there): hook just after the 3+2 cave
// at the start of FUN_01062190 (ECX = rule group, [ebp+8] = team, [ebp+0x10] = fixture); one line
// per group (first use) and the per-call fixture lists.
const seenGroups = new Set();
// Mid-function probe (after `push ebp; mov ebp,esp; and esp,-8` in the 3+2 cave): plain function only.
Interceptor.attach(va(0x01062196), function () {
  const group = this.context.ecx;
  const fp = this.context.ebp;
  const team = fp.add(8).readPointer();
  const club = !team.isNull() && team.add(0x23).readU8() === 0;
  const key = group.toString();
  if (!seenGroups.has(key)) {
    seenGroups.add(key);
    bump("stored rules (" + (club ? "club" : "non-club") + " use): " + describeList(group.add(0x34).readPointer()));
  }
});
// Fixture lists: at the function's entry ([esp] is the real return address there, so onLeave is safe;
// Frida relocates the 3+2 patch's jmp at the entry into its trampoline).
Interceptor.attach(va(0x01062190), {
  onEnter(args) {
    this.list = args[1];
    this.fixture = !args[2].isNull();
  },
  onLeave() {
    if (this.fixture) bump("fixture list from FUN_01062190: " + describeList(this.list));
  },
});
Interceptor.attach(va(0x011a6b90), {  // registered-squad rules
  onEnter(args) {
    this.list = args[3];
  },
  onLeave(retval) {
    bump("rules list from FUN_011a6b90 (registered): " +
      ((retval.toInt32() & 0xff) && !this.list.isNull() ? describeList(this.list) : "none"));
  },
});
Interceptor.attach(va(0x00f8a750), {  // the game's rule evaluator
  onEnter(args) {
    const rule = this.context.ecx;
    const type = rule.add(0xc).readU16();
    this.hit = type === 0x04 || type === 0x15;
    if (this.hit) {
      this.key = "rule 0x" + type.toString(16) + (rule.add(4).readU32() === MAGIC ? "[non-assimilated]" : "") +
        " value " + rule.add(8).readS32() + " count " +
        args[0].toInt32() + " from " + rva(this.returnAddress);
    }
  },
  onLeave(retval) {
    if (this.hit) bump(this.key + " -> " + ((retval.toInt32() & 0xff) ? "ok" : "broken"));
  },
});
Interceptor.attach(va(0x006f69f0), {  // offer validity
  onEnter(args) {
    this.reason = args[2];
  },
  onLeave(retval) {
    const reason = this.reason.isNull() ? "-" : "0x" + this.reason.readU16().toString(16);
    bump("offer validity -> result " + (retval.toInt32() & 0xff) + " reason " + reason);
  },
});

// --- squad status of surplus players (status hook, cave 0x020c1600) ----------------------------
// KEPT(original status): the hook turned a re-rating of a listed surplus foreigner into 7. At its
// entry: [esp+4] = original status, [esp+8] = the setter's caller.
let KEPT = null, KEEP7 = null, IS_SURPLUS = null;
if (statusOn) {
  for (let a = va(0x020c1600); a.compare(va(0x020c1740)) < 0; a = a.add(1)) {
    // "push dword [esp+4] ; call KEPT"
    if (a.readU32() === 0x042474ff && a.add(4).readU8() === 0xe8) { KEPT = a.add(9).add(a.add(5).readS32()); break; }
  }
  for (let a = va(0x020c1c00); a.compare(va(0x020c1e00)) < 0; a = a.add(1)) {
    // "push ebx ; push edi ; call KEEP7" in the surplus cave
    if (a.readU8() === 0x53 && a.add(1).readU8() === 0x57 && a.add(2).readU8() === 0xe8) { KEEP7 = a.add(7).add(a.add(3).readS32()); break; }
  }
  IS_SURPLUS = new NativeFunction(va(0x020c1600), "uint8", ["pointer"]);
}
const caller = (p) => (p.equals(va(0x00b599c4)) ? "AI re-rating 0xb599c4" : rva(p));
if (KEPT) Interceptor.attach(KEPT, {
  onEnter() {
    const sp = this.context.esp;
    bump("status hook: re-rating to " + (sp.add(4).readU32() & 0xff) + " kept at 7 (listed surplus) from " + caller(sp.add(8).readPointer()));
  },
});
if (KEEP7) Interceptor.attach(KEEP7, {  // stdcall KEEP7(contract, club)
  onEnter(args) {
    const st = args[0].add(0x30).readU8();
    if (st !== 7) bump("review: listed surplus player at status " + st + ", set back to 7");
  },
});
// No hook on the squad-status setter itself (015c8926): FM15 crashed while a sample attached one
// there during career creation, and it ran IS_SURPLUS (a whole-squad walk) inside every status
// write. The status hook's own KEPT point and KEEP7 above count the cases that matter.

// --- prices of listed / surplus players -------------------------------------------------------
// Listing calls: reason 0x0f = list, 0x12 = list + free/release path; args: player, club, reason, price.
Interceptor.attach(va(0x00e5f250), {
  onEnter(args) {
    bump("transfer listing reason 0x" + (args[2].toInt32() & 0xff).toString(16) + " from " + rva(this.returnAddress));
  },
});
// Selling club's valuation in the AI bid evaluation FUN_01f325f0 (player vfunc +0x28 -> 0x0163e4c0),
// as a ratio of the player's stored value (+0xc0), split by "listed" (player vfunc +0xdc).
Interceptor.attach(va(0x0163e4c0), {
  onEnter() {
    this.on = inRange(this.returnAddress, 0x01f325f0, 0x01f33300);
    if (!this.on) return;
    const p = this.context.ecx;
    this.value = p.add(0xb4).readU32() ? p.add(0xc0).readS32() : 0;
    try {
      const fn = new NativeFunction(p.readPointer().add(0xdc).readPointer(), "uint8", ["pointer"], "thiscall");
      this.listed = fn(p) & 1;
    } catch (e) {
      this.listed = "?";
    }
  },
  onLeave(retval) {
    if (!this.on) return;
    const v = retval.toInt32();
    const ratio = this.value > 0 ? (Math.round((v / this.value) * 4) / 4).toFixed(2) : "n/a";
    bump("bid valuation / value = " + ratio + (this.listed === 1 ? " (listed)" : " (not listed)"));
  },
});

setInterval(() => send(counts), 15000);
send({ ready: mod.base.toString() });
