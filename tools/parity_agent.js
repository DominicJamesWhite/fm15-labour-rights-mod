// Frida agent for parity mode: the pools and levies of reports/parity/PLAN.md. Loaded and
// eternalized by fm15_loader.py --mode parity (patch.py MODE_AGENTS); logs to reports/parity_agent.log.
//
// Nothing is held in memory between game days: every rule settles at once from FM's own finance
// blocks in CLUB_FINANCE (saved with the game), as a debit (Other Out) from the paying clubs and
// Grants credits to the receiving ones. Grants are outside the commercial set, so pool money is
// never levied again. Only detailed clubs (full CLUB_FINANCE) take part.
//
// Rules: B1 league broadcast money, i.e. league TV and league prize money (monthly 50% pyramid /
// 25% league; 25% by final position at season end), B2 50% of league gates and season tickets to the league, B3 75% commercial levy above the
// league median at each club's season rollover, B4 owner luxury tax: 50% of all owner money,
// paid on top by the owner and shared by the pyramid, B5 national cup TV split over
// each round, B6 wage budgets set to 80% of net revenue, C national
// cup rules, plus re-routing of non-commercial Other In and owner sponsorship (B3).

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const TODAY = va(0x0239ebf4);
const WORLD = va(0x02428ee0);

const tc = (addr, ret, args) => new NativeFunction(va(addr), ret, ["pointer"].concat(args || []), "thiscall");
const CLUB_COUNT = tc(0x0151db30, "int");
const CLUB_AT = tc(0x0151da10, "pointer", ["int"]);
const FIN_OF = tc(0x014c9670, "pointer");                 // club -> CLUB_FINANCE, or 0 if not detailed
const BALANCE = tc(0x014b1550, "int");
const BLOCK_FOR = tc(0x0168b780, "pointer", ["pointer"]); // (fin, COMP@DB) -> its season block
const OTHER_OUT = tc(0x01680fa0, "void", ["int"]);
const GRANTS_IN = tc(0x0167feb0, "void", ["int"]);
const INVEST = new NativeFunction(va(0x01e36f80), "void", ["pointer", "int", "int"], "stdcall");

// Block-relative offsets (month block fin+0xc0, season +0x208, last season +0x2ac).
const MONTH = 0xc0, SEASON = 0x208, LAST_SEASON = 0x2ac;
const GATES = 0x30, OTHER = 0x34, TICKETS = 0x38, INVESTMENT = 0x40, MERCH = 0x44, SPONSOR = 0x4c, MERCH_DEAL = 0x54;
const TV_LIST = 0x8c, PRIZE_LIST = 0x98;                  // vectors of {COMP@DB*, amount}
const REVENUE = [0x30, 0x34, 0x38, 0x3c, 0x44, 0x4c, 0x50, 0x54, 0x5c, 0x78, 0x7c, 0x80, 0x84];
const COMMERCIAL = [OTHER, MERCH, SPONSOR, MERCH_DEAL];

let logFile = null;
function log(line) {
  if (!logFile) return;
  try { logFile.write(today() + " " + line + "\n"); logFile.flush(); } catch (e) {}
}

function today() {
  return new Date(Date.UTC(TODAY.add(2).readU16(), 0, TODAY.readU16() & 0x1ff)).toISOString().slice(0, 10);
}

// Names for the log, through FM's own text formatter (as tools/trace_parity_checks.js does).
const TEXT_CTOR = tc(0x0188f4b0, "pointer");
const TEXT_SET = tc(0x0188fd00, "void", ["pointer"]);
const TEXT_ARG = tc(0x01493e80, "void", ["int", "pointer", "int", "int", "pointer"]);
const TEXT_RENDER = tc(0x01890790, "pointer");
const TEXT_DTOR = tc(0x0188fc80, "void");
const EMPTY_TEXT = va(0x02426d58);
function nameOf(token, obj) {
  try {
    const text = Memory.alloc(0x100);
    TEXT_CTOR(text);
    TEXT_SET(text, Memory.allocUtf8String("<%" + token + "#1>"));
    TEXT_ARG(text, 1, obj, 0, 0, EMPTY_TEXT);
    const r = TEXT_RENDER(text);
    const s = readText((r.isNull() ? text : r).readPointer());
    TEXT_DTOR(text);
    return s;
  } catch (e) {
    return obj.toString();
  }
}
function readText(p) {
  const found = [];
  for (const f of [() => p.readUtf16String(), () => p.add(2).readUtf16String(), () => p.add(4).readUtf16String(),
                   () => p.readUtf8String(), () => p.add(1).readUtf8String()]) {
    try { const s = f(); if (s && /^[\p{L}\p{M} .,'\-()&0-9]{2,60}$/u.test(s)) found.push(s); } catch (e) {}
  }
  return found.length ? found.sort((a, b) => b.length - a.length)[0] : "?";
}
const clubName = (club) => nameOf("club", club);
const compName = (comp) => nameOf("comp", comp);

// Virtual call obj->vt[off](). The NativeFunction is made once per target and return type and
// kept (building one per call was the main cost of the club walk and of the per-match hooks).
const vcallFns = new Map();
function vcall(obj, off, ret) {
  const target = obj.readPointer().add(off).readPointer(), key = target.toString() + ret;
  let fn = vcallFns.get(key);
  if (!fn) { fn = new NativeFunction(target, ret, ["pointer"], "thiscall"); vcallFns.set(key, fn); }
  return fn(obj);
}

// --- Club index -------------------------------------------------------------------------------
// Walking every club in the world takes a moment, so the index is kept for up to a week (league
// membership only changes between seasons) and rebuilt for each monthly and season-end settlement.

let index = null;
const dayNumber = () => TODAY.add(2).readU16() * 366 + (TODAY.readU16() & 0x1ff);
function clubs(fresh) {
  const d = dayNumber();
  if (index && !fresh && d - index.day < 7 && d >= index.day) return index;
  const world = WORLD.readPointer();
  const n = CLUB_COUNT(world);
  const byFin = new Map(), byLeague = new Map(), byNation = new Map();
  for (let i = 0; i < n; i++) {
    try {
      const club = CLUB_AT(world, i);
      if (club.isNull()) continue;
      const fin = finOf(club);
      if (fin.isNull()) continue;
      const league = vcall(club, 0x104, "pointer");
      if (league.isNull()) continue;
      const nation = league.add(0x44).readPointer();
      if (nation.isNull()) continue;
      const c = { club, fin, league, nation, level: league.add(0xdd).readS8() };
      byFin.set(fin.toString(), c);
      push(byLeague, league.toString(), c);
      push(byNation, nation.toString(), c);
    } catch (e) {}
  }
  index = { day: d, byFin, byLeague, byNation };
  return index;
}
function push(map, key, value) {
  const list = map.get(key);
  if (list) list.push(value); else map.set(key, [value]);
}
// FIN_OF (0x014c9670) without a native call where its answer is certain. It returns [club+0x9c]
// when that is non-NULL and its vt+0x1c() returns al == 1, else 0. When vt+0x1c is a constant
// function (live code bytes "mov al,1 / xor al,al / xor eax,eax; ret", e.g. 0x004d4750 of the
// detailed CLUB_FINANCE) its answer is known from the bytes, so the world walk skips one native
// call per club; any other code (or a hooked one) is still called through FIN_OF.
const constAnswer = new Map();          // vt+0x1c target -> 1, 0, or null (not a constant function)
function constantAl(target) {
  const key = target.toString();
  let k = constAnswer.get(key);
  if (k !== undefined) return k;
  k = null;
  try {
    const b = new Uint8Array(target.readByteArray(3));
    if (b[2] === 0xc3) {
      if (b[0] === 0xb0) k = b[1] === 1 ? 1 : 0;                                   // mov al, imm8
      else if ((b[0] === 0x30 || b[0] === 0x32 || b[0] === 0x31 || b[0] === 0x33) && b[1] === 0xc0) k = 0;   // xor al,al / xor eax,eax
    }
  } catch (e) {}
  constAnswer.set(key, k);
  return k;
}
function finOf(club) {
  const f = club.add(0x9c).readPointer();
  if (f.isNull()) return NULL;
  const k = constantAl(f.readPointer().add(0x1c).readPointer());
  if (k === 1) return f;
  if (k === 0) return NULL;
  return FIN_OF(club);
}

// --- Money helpers ----------------------------------------------------------------------------

const slot = (fin, block, off) => fin.add(block + off).readS32();
function debit(c, amount) { if (amount > 0) OTHER_OUT(c.fin, amount); }
// Split amount equally over the clubs; the rounding remainder goes to the first.
function payEqually(list, amount) {
  if (amount <= 0 || !list || list.length === 0) return;
  const each = Math.floor(amount / list.length);
  list.forEach((c, i) => GRANTS_IN(c.fin, each + (i === 0 ? amount - each * list.length : 0)));
}
function median(values) {
  const v = values.slice().sort((a, b) => a - b);
  if (v.length === 0) return 0;
  return v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2;
}
// The club's broadcast money from its own league in a finance block: its TV and its prize money
// from that league. FM15 pays some leagues' TV distribution as league prize money (the Bundesliga
// and Eredivisie have no league TV at all; the Premier League's merit payments are prize money),
// so both count (user decision, 2026-10-31). Entries may be keyed by the COMP@DB or its ACT.
function leagueBroadcast(c, block) {
  const act = c.league.add(0x68).readPointer();
  let total = 0;
  for (const off of [TV_LIST, PRIZE_LIST]) {
    const list = block.add(off), end = list.add(4).readPointer();
    for (let p = list.readPointer(); p.compare(end) < 0; p = p.add(8)) {
      const comp = p.readPointer();
      if (comp.equals(c.league) || comp.equals(act)) total += p.add(4).readS32();
    }
  }
  return total;
}

// --- B1 + B2: month start (1st, before the loop clears each club's month block) --------------

// The pools only credit and debit, so the club index monthly() builds is still exact for the wage
// budgets straight after it: one world walk per month start instead of two.
let monthIndex = null;
Interceptor.attach(va(0x0063e9b8), {
  onEnter() {
    monthIndex = null;
    try { monthly(); } catch (e) { log("monthly error " + e.stack); }
    try { setAllWages(); } catch (e) { log("wage budget error " + e.stack); }
    try { reconcileOwnerMoney(); } catch (e) { log("owner money reconciliation error " + e.stack); }
  },
});

const GATE_SHARE = 0.5;                 // of league gates and season tickets, shared equally in the league
function monthly() {
  const idx = clubs(true);
  monthIndex = idx;
  const pyramid = new Map(), league = new Map();
  let tvTotal = 0, gateTotal = 0;
  for (const c of idx.byFin.values()) {
    const tv = leagueBroadcast(c, c.fin.add(MONTH));
    const gates = Math.max(0, slot(c.fin, MONTH, GATES) - (cupGates.get(c.fin.toString()) || 0)) + slot(c.fin, MONTH, TICKETS);
    const toPyramid = Math.floor(tv * 0.5), toLeague = Math.floor(tv * 0.25), toGatePool = Math.floor(gates * GATE_SHARE);
    debit(c, toPyramid + toLeague + toGatePool);
    add(pyramid, c.nation.toString(), toPyramid);
    add(league, c.league.toString(), toLeague + toGatePool);
    tvTotal += toPyramid + toLeague;
    gateTotal += toGatePool;
  }
  for (const [nation, amount] of pyramid) payEqually(idx.byNation.get(nation), amount);
  for (const [comp, amount] of league) payEqually(idx.byLeague.get(comp), amount);
  cupGates.clear();
  log(`monthly: ${idx.byFin.size} clubs, TV pooled ${tvTotal}, gates/tickets pooled ${gateTotal}, ${pyramid.size} pyramids, ${league.size} leagues`);
}
function add(map, key, amount) { map.set(key, (map.get(key) || 0) + amount); }

// Cup and friendly gates are left out of the gate pool: gates credited during a non-league
// fixture's post-match income are tallied per club for the month (lost on quit: then that month's
// cup gates are pooled too, a small error).
const cupGates = new Map();
let cupFixture = false;
Interceptor.attach(va(0x016804f0), {      // Gates In (thiscall fin, amount)
  onEnter(args) {
    if (cupFixture) add(cupGates, this.context.ecx.toString(), Math.abs(args[0].toInt32()));
  },
});
// Post-match income 0x00453c50 keeps the fixture in EDI (reports/parity/cup_tv.md). At the gate
// split (0x00454505, before any gate credit) note whether this is a league fixture: the fixture's
// competition is the home club's league and it isn't a cup round (play-offs, cups: fix+0x2b >= 0).
Interceptor.attach(va(0x00454505), {
  onEnter() {
    try {
      const fix = this.context.edi;
      const home = fix.add(0x4).readPointer().add(0x10).readPointer();
      cupFixture = fix.add(0x2b).readS8() >= 0 || !fix.add(0x10).readPointer().equals(vcall(home, 0x104, "pointer"));
    } catch (e) { cupFixture = false; }
  },
});
Interceptor.attach(va(0x00453c50), { onLeave() { cupFixture = false; } });

// --- B5: national cup TV, split equally over every club in the round ----------------------------
// At 0x0045455e (start of the post-match TV block): EDI = fixture, [esp+0x38] = the tie's TV,
// [esp+0x34] = single recipient (whole TV) or 0, EBP/EBX = home/away finance (0 if not detailed),
// (s8)[esp+0x13] = TV percentage. For a national cup tie the agent zeroes [esp+0x38], so the game
// skips both credits, and pays what the game would have paid, split over the round's detailed clubs.

const TV_IN = tc(0x01680880, "void", ["int", "pointer"]);  // (fin, amount, COMP@DB)
const TIE = tc(0x01043b10, "pointer", ["int16", "int"]);   // CUP_STAGE vt+0x10c(round, i)

Interceptor.attach(va(0x0045455e), {
  onEnter() {
    try { cupTV(this.context); } catch (e) { log("cup TV error " + e.stack); }
  },
});

function cupTV(ctx) {
  const sp = ctx.esp, fix = ctx.edi;
  const tv = sp.add(0x38).readS32();
  if (tv <= 0) return;
  const comp = fix.add(0x10).readPointer();
  const act = comp.add(0x68).readPointer();
  if (comp.add(0x44).readPointer().isNull() || act.isNull()) return;          // continental
  const type = act.add(0x85).readU8();
  if (type === 0 || type === 1 || type === 14) return;                        // league play-offs
  const s = fix.add(0x2a).readS8(), r = fix.add(0x2c).readS8();
  if (s < 0 || r < 0) return;
  const stages = act.add(0x4c).readPointer();
  if (s >= act.add(0x50).readPointer().sub(stages).toInt32() / 4) return;
  const stage = stages.add(4 * s).readPointer();
  if (vcall(stage, 0xb4, "uint8") !== 1) return;                              // not a cup stage
  const rounds = stage.add(0x38).readPointer().add(0x14).readPointer();
  const nTies = rounds.add(4 * r).readPointer().add(0x1e).readS16();
  const teamTable = stage.add(0x3c).readPointer(), nTeams = stage.add(0x40).readS16();
  const fins = [];
  for (let i = 0; i < nTies; i++) {
    const tie = TIE(stage, r, i);
    if (tie.isNull()) continue;
    for (const side of [0, 8]) {
      const t = tie.add(side).readS16();
      if (t < 0 || t >= nTeams) continue;
      const fin = finOf(teamTable.add(12 * t).readPointer().add(0x10).readPointer());
      if (!fin.isNull()) fins.push(fin);
    }
  }
  if (fins.length === 0) return;
  // What the game would have paid: all of it to a single recipient, else pct% to each detailed side.
  const single = sp.add(0x34).readPointer();
  const half = Math.trunc(Math.fround(sp.add(0x13).readS8() * Math.fround(0.01)) * tv);
  const pool = !single.isNull() ? tv : (ctx.ebp.isNull() ? 0 : half) + (ctx.ebx.isNull() ? 0 : half);
  sp.add(0x38).writeS32(0);
  const each = Math.floor(pool / fins.length);
  fins.forEach((fin, i) => TV_IN(fin, each + (i === 0 ? pool - each * fins.length : 0), comp));
}

// --- B1: final-position share at competition end ----------------------------------------------

const finalTables = new Map();   // COMP@DB -> [team, ...] in final order, from the stage end
Interceptor.attach(va(0x01018700), {
  onEnter() {
    try {
      const stage = this.context.ecx;
      const n = stage.add(0x44).readS8(), rows = stage.add(0x38).readPointer();
      const teams = [];
      for (let i = 0; i < n; i++) teams.push(rows.add(4 * i).readPointer().add(0x30).readPointer());
      finalTables.set(compOf(stage.add(0x28).readPointer()).toString(), teams);
    } catch (e) { log("stage table error " + e); }
  },
});
Interceptor.attach(va(0x00fad710), {
  onEnter() { this.act = this.context.ecx; },
  onLeave() {
    try { positionShare(this.act); } catch (e) { log("position share error " + e.stack); }
  },
});

// COMP@DB and its ACTUAL_COMP point at each other (COMP+0x68, ACT+0x3c); stage+0x28 may hold
// either, so normalise to the COMP@DB, which is also the key of the per-competition TV lists.
function compOf(p) {
  try { if (p.add(0x68).readPointer().add(0x3c).readPointer().equals(p)) return p; } catch (e) {}
  return p.add(0x3c).readPointer();
}

// The table captured at the league stage's end is held in memory only. With the 2nd-7th play-off
// (tools/parity_playoff.js) a top league now finishes after the play-off final, up to a few
// weeks later, so a save loaded in between has no capture: then the table is read from the
// competition's own stages (the highest-index finished league stage with the most rows; row i =
// position i). The play-off's cup stage is never a league stage, so its entrants are not read.
function tableFromStages(act) {
  let best = null, bestN = 0;
  const b = act.add(0x4c).readPointer();
  const n = b.isNull() ? 0 : act.add(0x50).readPointer().sub(b).toInt32() / 4;
  for (let i = 0; i < n; i++) {
    const s = b.add(4 * i).readPointer();
    if (s.isNull() || vcall(s, 0xc4, "uint8") !== 1) continue;                 // 1 = league stage
    if (s.add(0x10).readU8() === 0 && s.add(0x82).readU8() === 0) continue;     // not finished (0x010182d0)
    const k = s.add(0x44).readS8();
    if (k >= bestN && k > 0) { best = s; bestN = k; }
  }
  if (!best) return null;
  const rows = best.add(0x38).readPointer(), teams = [];
  for (let i = 0; i < bestN; i++) teams.push(rows.add(4 * i).readPointer().add(0x30).readPointer());
  return teams;
}

function positionShare(act) {
  const comp = compOf(act);
  let teams = finalTables.get(comp.toString());
  finalTables.delete(comp.toString());
  if (comp.add(0x44).readPointer().isNull() || comp.add(0xdd).readS8() >= 100) return;   // continental, youth
  if ([0, 1, 14].includes(act.add(0x85).readU8())) {
    // Also when the last capture is a smaller later stage (a split league's relegation round).
    const fromStages = tableFromStages(act);
    if (fromStages && (!teams || fromStages.length > teams.length)) {
      log(`position share: ${compName(comp)} table read from its stages (${fromStages.length} rows; capture ${teams ? teams.length + " rows" : "missing"})`);
      teams = fromStages;
    }
  }
  if (!teams) return;
  const idx = clubs(true);
  const members = idx.byLeague.get(comp.toString());
  if (!members) return;
  const n = teams.length;
  const shares = [];
  let pot = 0, weights = 0;
  teams.forEach((team, i) => {
    const c = idx.byFin.get(finOf(team.add(0x10).readPointer()).toString());
    if (!c || !c.league.equals(comp)) return;
    const base = Math.floor(leagueBroadcast(c, BLOCK_FOR(c.fin, comp)) * 0.25);
    debit(c, base);
    pot += base;
    shares.push({ c, weight: n - i });
    weights += n - i;
  });
  if (weights === 0) return;
  let paid = 0;
  shares.forEach((s, i) => {
    const amount = i === shares.length - 1 ? pot - paid : Math.floor(pot * s.weight / weights);
    GRANTS_IN(s.c.fin, amount);
    paid += amount;
  });
  log(`position share: ${compName(comp)} (level ${comp.add(0xdd).readS8()}), ${shares.length} clubs, pot ${pot}`);
}

// --- C: national cups play like the DFB-Pokal (rules part) ------------------------------------
// FM rebuilds each cup stage's CUP_SETTINGS from data every season; 0x0103e360 (ecx = CUP_STAGE)
// runs once per stage setup, after loading and any per-cup override, before byes and placement
// (reports/parity/cup_rules_memory.md). For national cups (main and league cups) every round becomes a single match
// with extra time and penalties, no replays, the lower-division club at home (same division:
// random). Entry: the top two divisions all enter the same round (cupEntry below).

const HOME_MASK = uint64("0x6300000000").or(0x1 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x2000 | 0x20000 |
  0x40000 | 0x80000 | 0x800000 | 0x2000000 | 0x4000000 | 0x10000000);
const MATCH_CLEAR = 0x4 | 0x8 | 0x20 | 0x40 | 0x100 | 0x400 | 0x800;

Interceptor.attach(va(0x0103e360), {
  onEnter() {
    try { cupRules(this.context.ecx); } catch (e) { log("cup rules error " + e.stack); }
  },
});

function cupRules(stage) {
  const comp = compOf(stage.add(0x28).readPointer());
  const act = comp.add(0x68).readPointer();
  const type = act.add(0x85).readU8();
  const domestic = !comp.add(0x44).readPointer().isNull();
  const settings = stage.add(0x38).readPointer();
  const begin = settings.add(0x14).readPointer(), end = settings.add(0x18).readPointer();
  const rounds = end.sub(begin).toInt32() / 4;
  // Every senior national knockout cup: domestic, not a league or league play-off (types 0, 1,
  // 14), not a youth/reserve competition (type 23), and more than one round, which leaves out
  // one-off super cups.
  const main = domestic && ![0, 1, 14, 23].includes(type) && rounds > 1;
  log(`cup stage: ${compName(comp)} id ${comp.add(8).readU32()} type ${type} domestic ${domestic} rounds ${rounds} entrants ${stage.add(0x40).readS16()}${main ? " -> parity rules" : ""}`);
  if (!main) return;
  for (let i = 0; i < rounds; i++) {
    const round = begin.add(4 * i).readPointer();
    const draw = round.add(0x10).readU64();
    round.add(0x10).writeU64(draw.and(HOME_MASK.not()).and(uint64(0x8).not()).or(0x2));
    round.add(0x2b).writeU8(0);                                 // replays
    round.add(0x2c).writeU8(1);                                 // legs
    round.add(0x1a).writeU16(round.add(0x1a).readU16() & ~3);   // series rules
    for (const m of [0x18, 0x26, 0x28]) round.add(m).writeU16((round.add(m).readU16() & ~MATCH_CLEAR) | 0x3);
  }
  cupEntry(stage, comp, act, settings);
}

// Entry: every club of the top two divisions enters the same round, with no byes for them
// (reports/parity/cup_entry.md, section 4). FUN_0103e360 then gives round r the entrants
// [off_r, off_r + nmxt_r) of the list at stage+0x3c, so the list is re-sorted deepest division
// first with the top-two clubs last, and the per-round counts are rewritten so that the sum of
// nmxt equals N exactly (a shortfall would cut the end of the list: the top clubs). Cups that
// already comply (FA Cup, DFB-Pokal) and cups the plan can't fit are left with vanilla entry.

const DEL_ROUND = tc(0x0103e440, "void", ["int", "pointer"]);   // (CUP_SETTINGS, index, ACT)

const DEFAULT_SETTINGS_LOADER = va(0x00fb4af0);                  // ACTUAL_COMP vt+0x30 of data-driven cups
// Switched off (user, 2026-10-31: cup bracketing is the least important part of the mode, and a
// crash in the draw news followed the first restructured draws). Every cup keeps FM's own entry;
// the parity match rules above still apply.
const CUP_ENTRY_ENABLED = false;

function cupEntry(stage, comp, act, settings) {
  if (!CUP_ENTRY_ENABLED) return;
  const name = compName(comp);
  if (!stage.add(0x44).readPointer().isNull()) return;          // draw already placed
  // Cups whose rounds FM builds in its own code (Coppa Italia and others) may place clubs by the
  // original bracket, so their entry is left alone; a restructured code-built cup is the likely
  // cause of a crash in the draw news (reports/parity/test4).
  if (!act.readPointer().add(0x30).readPointer().equals(DEFAULT_SETTINGS_LOADER)) {
    log(`cup entry: ${name} left vanilla (rounds built in code)`);
    return;
  }
  const roundList = () => {
    const b = settings.add(0x14).readPointer(), n = settings.add(0x18).readPointer().sub(b).toInt32() / 4;
    return Array.from({ length: n }, (_, i) => b.add(4 * i).readPointer());
  };
  const rs = roundList(), n = rs.length, F = n - 1;
  const N = stage.add(0x40).readS16(), arr = stage.add(0x3c).readPointer();
  const teams = (r) => r.add(0x1c).readS16(), ties = (r) => r.add(0x1e).readS16(), entrants = (r) => r.add(0x20).readS16();
  if (n < 2 || teams(rs[F]) !== 2 || ties(rs[F]) !== 1 || rs.some((r, i) => i < F && teams(r) === 2)) {
    log(`cup entry: ${name} left vanilla (not a plain knockout)`);
    return;
  }

  const nation = comp.add(0x44).readPointer();
  const ents = [];
  for (let i = 0; i < N; i++) {
    const e = arr.add(12 * i), team = e.readPointer();
    let lvl = 127, top = false;
    if (!team.isNull()) {
      const league = team.add(0x30).readPointer();
      if (!league.isNull()) {
        lvl = league.add(0xdd).readS8();
        top = lvl >= 0 && lvl <= 1 && league.add(0x44).readPointer().equals(nation);
      }
    }
    ents.push({ bytes: e.readByteArray(12), lvl, top, i });
  }
  const T = ents.filter((e) => e.top).length;
  if (T === 0) return;
  if (vanillaComplies(rs, N, ents, teams, ties, entrants)) {
    log(`cup entry: ${name} already complies (T ${T}, N ${N})`);
    return;
  }
  const p = entryPlan(n, N, T);
  if (!p) {
    log(`cup entry: ${name} left vanilla (N ${N}, T ${T}: no fitting bracket)`);
    return;
  }
  ents.sort((a, b) => (a.top - b.top) || (a.top ? 0 : b.lvl - a.lvl) || (a.i - b.i));
  ents.forEach((e, i) => arr.add(12 * i).writeByteArray(e.bytes));
  for (let r = 0; r < n; r++) {
    rs[r].add(0x20).writeS16(p.nmxt[r]);
    rs[r].add(0x1c).writeS16(p.ntms[r]);
    rs[r].add(0x1e).writeS16(p.ntms[r] >> 1);
  }
  for (let k = 0; k < p.emptyLeading; k++) DEL_ROUND(settings, 0, act);
  const S = roundList().reduce((sum, r) => sum + entrants(r), 0);
  log(`cup entry: ${name} N ${N}, top two ${T} enter a ${p.P}-team round; rounds ${p.ntms.slice(p.emptyLeading).join("/")}${S !== N ? ` BUG: entrant slots ${S} != ${N}` : ""}`);
}

// The game's surplus rule applied to copies: then all top clubs must sit in one round's slice,
// with even rounds from there on and no later entrants.
function vanillaComplies(rs, N, ents, teams, ties, entrants) {
  const t = rs.map(teams), m = rs.map(ties), x = rs.map(entrants);
  let S = x.reduce((a, b) => a + b, 0);
  if (S < N) return false;
  while (S > N && t.length > 1) {
    t[0] -= 2; m[0] -= 1; x[0] -= 2; x[1] += 1; S--;
    if (t[0] < 2) { t.shift(); m.shift(); x.shift(); }
  }
  let off = 0, R = -1;
  const tops = ents.map((e, i) => (e.top ? i : -1)).filter((i) => i >= 0);
  for (let r = 0; r < x.length; r++) {
    if (tops.every((i) => i >= off && i < off + x[r])) { R = r; break; }
    off += x[r];
  }
  if (R < 0 || t[R] !== 2 * m[R]) return false;
  for (let r = R + 1; r < x.length; r++) if (x[r] !== 0 || t[r] !== 2 * m[r]) return false;
  return true;
}

// Round sizes by original index: P = smallest power of two >= T that the data's rounds allow;
// earlier rounds turn the L lower clubs into exactly P - T winners, the surplus draining as byes
// the way FUN_0103e360 does, so every round size is even. null = no fitting bracket.
function entryPlan(n, N, T) {
  const F = n - 1, L = N - T;
  for (let k = Math.max(1, Math.ceil(Math.log2(Math.max(T, 2)))); ; k++) {
    const P = 1 << k, R = F + 1 - k, W = P - T;
    if (R < 0 || W > L) return null;
    if (L > W * (1 << R) || (L > 0 && W === 0)) continue;
    const A = new Array(R + 1).fill(0);
    A[R] = T;
    A[0] += W * (1 << R);
    let E = W * (1 << R) - L, j = 0;
    while (E > 0) {
      if (j < R && A[j] >= 2) { A[j] -= 2; A[j + 1] += 1; E--; } else j++;
    }
    const nmxt = [], ntms = [];
    let carry = 0, emptyLeading = 0;
    for (let r = 0; r < n; r++) {
      const x = r <= R ? A[r] : 0, t = carry + x;
      nmxt.push(x);
      ntms.push(t);
      carry = t >> 1;
      if (t === 0) emptyLeading++;
    }
    return { P, R, W, nmxt, ntms, emptyLeading };
  }
}

// Diagnostic: FM's "cup draw made" news (0x00a54a10, (CUP_STAGE, CUP_ROUND)) walks the drawn
// round's ties; it crashed once after a restructured cup's draw. Log each call so a repeat names
// the cup.
Interceptor.attach(va(0x00a54a10), {
  onEnter(args) {
    try {
      const stage = args[0], round = args[1];
      log(`draw news: ${compName(compOf(stage.add(0x28).readPointer()))} round ${round.readU8()} teams ${round.add(0x1c).readS16()} ties ${round.add(0x1e).readS16()}`);
    } catch (e) { log("draw news log error " + e); }
  },
});

// --- B3: re-route non-commercial Other In and owner sponsorship -----------------------------

const OWNER_OTHER = [0x00de5f40, 0x00af3b51, 0x00af3b5c, 0x00f217b9, 0x00f21879, 0x01684b8d, 0x01686b35, 0x00b8af23,
                     0x01684e03];   // annual owner money (CL club, rep < 7000, balance < 30m)
const EXCLUDED_OTHER = [0x00659506, 0x00c6bd78, 0x00e68163, 0x0084af53, 0x0167aa07, 0x0065413f, 0x0167df9e, 0x0095638e,
                        0x00af3baa, 0x00af3c18];   // takeover pays off loans: cash-neutral (income_sources.md 3)
const OWNER_SPONSOR = [0x00e0e79e, 0x01ec479a];   // sugar-daddy annual money; takeover follow-up
const routeOf = new Map();
OWNER_OTHER.forEach((a) => routeOf.set(va(a).toString(), "owner"));
EXCLUDED_OTHER.forEach((a) => routeOf.set(va(a).toString(), "excluded"));

Interceptor.attach(va(0x01680540), {      // Other In (thiscall fin, amount)
  onEnter(args) {
    const route = routeOf.get(this.returnAddress.toString());
    if (!route) return;
    const amount = Math.abs(args[0].toInt32());
    if (amount === 0) return;
    args[0] = ptr(0);                     // Other In skips a zero amount
    try {
      if (route === "owner") investAndLevy(this.context.ecx, amount, this.returnAddress);
      else GRANTS_IN(this.context.ecx, amount);
    } catch (e) { log("re-route error " + e); }
  },
});
const ownerSponsor = new Set(OWNER_SPONSOR.map((a) => va(a).toString()));
Interceptor.attach(va(0x0167fdc0), {      // Sponsor In (thiscall fin, amount); no zero check, so pass 0
  onEnter(args) {
    if (!ownerSponsor.has(this.returnAddress.toString())) return;
    const amount = Math.abs(args[0].toInt32());
    args[0] = ptr(0);
    try { investAndLevy(this.context.ecx, amount, this.returnAddress); } catch (e) { log("re-route error " + e); }
  },
});

// --- B3: commercial levy at each club's season rollover ---------------------------------------

// Wages Out (two slots) are paid to every club every month, so they show whether a club's season
// block was reset recently: fin+0x45c, meant to be the rollover date, stayed 1900 in the trace.
const wages = (fin, block) => slot(fin, block, 0x10) + slot(fin, block, 0x14);
const rolledOver = (fin) => wages(fin, SEASON) < 0.5 * wages(fin, LAST_SEASON);

Interceptor.attach(va(0x016842b0), {      // CLUB_FINANCE vt+0x1b0 (thiscall fin, ...)
  onEnter() { this.fin = this.context.ecx; this.before = wages(this.fin, SEASON); },
  onLeave() {
    if (wages(this.fin, SEASON) === this.before || !rolledOver(this.fin)) return;   // guard said no
    try { commercialLevy(this.fin); } catch (e) { log("commercial levy error " + e.stack); }
    try {
      const idx = clubs(), c = idx.byFin.get(this.fin.toString());
      const r = c && setWages(idx, c);
      if (r) log(`wage budget: ${clubName(c.club)} (${compName(c.league)}) ${r.before} -> ${r.after} a week (kept revenue ${r.kept}, cash ${r.cash})`);
    } catch (e) { log("wage budget error " + e.stack); }
  },
});

// Clubs that have already rolled over hold the finished season in the last-season block; the
// others still hold it in the season block.
const completedSeason = (c) => (rolledOver(c.fin) ? LAST_SEASON : SEASON);
const commercial = (c, block) => COMMERCIAL.reduce((sum, off) => sum + slot(c.fin, block, off), 0);

const COMMERCIAL_THRESHOLD = 1.0, COMMERCIAL_LEVY = 0.75;   // levy on commercial income above threshold x the league median
function commercialLevy(fin) {
  const idx = clubs();
  const c = idx.byFin.get(fin.toString());
  if (!c) return;
  const members = idx.byLeague.get(c.league.toString());
  const m = median(members.map((o) => commercial(o, completedSeason(o))));
  const excess = commercial(c, LAST_SEASON) - COMMERCIAL_THRESHOLD * m;
  if (excess <= 0) return;
  const levy = Math.floor(excess * COMMERCIAL_LEVY);
  debit(c, levy);
  payEqually(idx.byNation.get(c.nation.toString()), Math.floor(levy / 2));
  payEqually(members, levy - Math.floor(levy / 2));
  log(`commercial levy: ${clubName(c.club)} (${compName(c.league)}) commercial ${commercial(c, LAST_SEASON)}, league median ${m}, levy ${levy}`);
}

// --- B4: owner levy ---------------------------------------------------------------------------

// Revenue a club keeps from a season: the 13 revenue slots (pool Grants included) minus what the
// pools take from it (B1 75% of its league broadcast money, B2 GATE_SHARE of gates and season
// tickets) and the B3 commercial levy due on that season. Worked out from the season's own income,
// not from its Other Out: the commercial levy is debited at the next rollover, into the following
// season's block, so Other Out was a season late (PSG 2015: 164m levied the day its wage budget
// was set from the un-levied 294m).
const leagueCommercialMedian = new Map();     // league + block + day -> median commercial income
function commercialLevyOn(idx, c, block) {
  const key = `${c.league}:${block}:${dayNumber()}`;
  let m = leagueCommercialMedian.get(key);
  if (m === undefined) {
    m = median(idx.byLeague.get(c.league.toString()).map((o) => commercial(o, block)));
    if (leagueCommercialMedian.size > 500) leagueCommercialMedian.clear();
    leagueCommercialMedian.set(key, m);
  }
  return COMMERCIAL_LEVY * Math.max(0, commercial(c, block) - COMMERCIAL_THRESHOLD * m);
}
function keptRevenue(idx, c, block) {
  const revenue = REVENUE.reduce((s, off) => s + slot(c.fin, block, off), 0);
  const pooled = 0.75 * leagueBroadcast(c, c.fin.add(block)) + GATE_SHARE * (slot(c.fin, block, GATES) + slot(c.fin, block, TICKETS));
  return revenue - pooled - commercialLevyOn(idx, c, block);
}
// B4 owner luxury tax (user decision): owners may put in any amount, in any form (top-ups, loss
// cover, bailouts, takeover money); the club keeps all of it, as cash (B6 counts only a share of the
// club's cash a year towards wages), and the owner pays OWNER_TAX of it on top, shared equally by
// the nation's pyramid. One rate for every route (user decision, 2031: 100%; was 50%).
// Nothing is debited from the club: taking the tax out of the club's accounts made it a loss that
// FM's owners covered again (taxed again), which roughly doubled owner money and inflated every
// club's income through the Grants (EPL owner money 740m -> 1337m, 2019 -> 2021).
// Investment In is classified by its real caller (income_sources.md 2): FM calls it through the
// wrapper 0x01680879 (CLUB_FINANCE vt+0xf8), whose caller's return address is [esp+0x10] at entry.
// Exempt, not owner money: bank loans booked as Investment In, the parent's subsidy to a B team,
// owner contributions to stadium builds. Loss cover is labelled in the log only.
// The amount is what FM booked in the season Investment slot, not the argument: with a parent club
// FM books it as the B team's affiliate income instead (the slot does not move).
const OWNER_TAX = 1.0;
const SEASON_INVESTMENT = SEASON + INVESTMENT;          // fin+0x248
const WRAPPER_RET = va(0x01680879).toString();
const callerSet = (list) => new Set(list.map((a) => va(a).toString()));
const EXEMPT_CALLERS = callerSet([
  0x00b88d7d, 0x0063f26f, 0x00971cd4, 0x00971d6c,      // bank loans
  0x00b8976e,                                          // parent club's subsidy to its B team
  0x00803a8f, 0x00803cf7, 0x0080419b, 0x00804228,      // owner contributions to stadium builds
]);
const LOSS_COVER_CALLERS = callerSet([
  0x01684be4, 0x01684cd5,                              // annual owner review (rollover 0x016842b0)
  0x00b8ae69, 0x00b8af18,                              // monthly loss cover (0x00b8a700)
  0x01684b8d, 0x00b8af23,                              // the same paid as Other In (re-routed, B3)
]);

const ownerSeen = new Map();                 // fin -> owner money booked this month
const hexAddr = (p) => "0x" + (p.sub(mod.base).add(0x400000).toUInt32() >>> 0).toString(16);
function ownerLevy(fin, booked, used, balance, caller, how) {
  ownerSeen.set(fin.toString(), (ownerSeen.get(fin.toString()) || 0) + booked);
  const idx = clubs();
  const c = idx.byFin.get(fin.toString());
  if (!c) return;
  const kind = EXEMPT_CALLERS.has(caller.toString()) ? "exempt" : LOSS_COVER_CALLERS.has(caller.toString()) ? "loss cover" : "owner";
  const levy = kind === "exempt" ? 0 : Math.floor(booked * OWNER_TAX);
  if (levy > 0) payEqually(idx.byNation.get(c.nation.toString()), levy);   // paid on top: not debited from the club
  log(`owner money: ${clubName(c.club)} (${compName(c.league)}) ${booked} ${kind} via ${hexAddr(caller)}${how}, balance ${balance}, used ${used}, levy ${levy}${levy > 0 ? " (paid on top, shared by the pyramid)" : ""}`);
}

// Owner money re-routed from Other In / Sponsor In (B3). Frida does not run the Investment In
// listener for a call made inside another listener's callback (Gum's re-entrancy guard): 2030/31
// EPL owner money of 775.7m was never levied (wage_gap.md 3.3). So the levy is applied here; the
// flag keeps the listener from levying twice should it fire after all.
let rerouting = false;
function investAndLevy(fin, amount, via) {
  const used = slot(fin, SEASON, INVESTMENT), balance = BALANCE(fin);
  rerouting = true;
  try { INVEST(fin, amount, 1); } finally { rerouting = false; }
  const booked = slot(fin, SEASON, INVESTMENT) - used;
  if (booked <= 0) return;
  try { ownerLevy(fin, booked, used, balance, via, " (re-routed)"); } catch (e) { log("owner levy error " + e.stack); }
}

Interceptor.attach(va(0x01e36f80), {      // Investment In (stdcall fin, amount, flag)
  onEnter(args) {
    this.fin = null;
    if (rerouting) return;
    try {
      const ra = this.returnAddress.toString() === WRAPPER_RET ? this.context.esp.add(0x10).readPointer() : this.returnAddress;
      this.fin = args[0];
      this.caller = ra;
      this.used = this.fin.add(SEASON_INVESTMENT).readS32();
      this.balance = BALANCE(this.fin);
    } catch (e) { this.fin = null; log("owner money error " + e.stack); }
  },
  onLeave() {
    if (!this.fin) return;
    try {
      const booked = this.fin.add(SEASON_INVESTMENT).readS32() - this.used;
      if (booked > 0) ownerLevy(this.fin, booked, this.used, this.balance, this.caller, "");
    } catch (e) { log("owner levy error " + e.stack); }
  },
});

// Monthly reconciliation: the growth of each club's Investment In this season against the
// injections the hooks saw; a difference means owner money reaching the club by a route that
// bypasses 0x01e36f80. Skipped across a club's season reset.
const ownerSlotPrev = new Map();             // fin -> season Investment In at the last month start
function reconcileOwnerMoney() {
  const idx = clubs();
  const unseen = [];
  for (const c of idx.byFin.values()) {
    const k = c.fin.toString(), cur = slot(c.fin, SEASON, INVESTMENT), prev = ownerSlotPrev.get(k);
    if (prev !== undefined && cur >= prev) {
      const gap = cur - prev - (ownerSeen.get(k) || 0);
      if (Math.abs(gap) > 10000) unseen.push(`${clubName(c.club)} (${compName(c.league)}) ${gap}`);
    }
    ownerSlotPrev.set(k, cur);
  }
  ownerSeen.clear();
  log(`owner money reconciliation: ${unseen.length ? `${unseen.length} club(s) with owner money the hooks did not see: ${unseen.join("; ")}` : "every injection seen"}`);
}

// --- B6: wage budgets from revenue ---------------------------------------------------------

// FM sets a club's weekly wage budget from its current wage bill (about 1.05-1.3x) and its cash,
// not from its revenue; the one revenue-based cap is off in every loaded league (comp+0xe0 = 0),
// so 2014's wage bills and owner money persist (wage_gap.md 1). Here the budget is set to
// WAGE_SHARE of last season's kept revenue plus CASH_SHARE of the club's cash, per week, so it
// follows income both ways:
//  - lowered to it, but never below WAGE_FLOOR x the current bill (squads shrink only as contracts
//    end) nor below the league's median budget (a promoted club's lower-division revenue would
//    otherwise squeeze the poorest clubs);
//  - raised to it, only while the club's balance is not negative, and at most FM's hard cap.
// Applied after FM's rollover budget and at every month start (board requests, the budget slider
// and FM's transfer-to-wage conversion move it again).
// Owner money (sugar-daddy payments, takeover money, overdraft clearance) and loans are capital,
// not income (user decision, 2031: counted in full, owner money became wages one for one; PSG
// 2.5bn and Man City 1.75bn over 17 seasons, Benfica's 273m of loans counted as owner money). They
// count only through the cash they leave in the bank: CASH_SHARE a year of the balance, so an
// injection is written off over about five years as it is spent, loans fade as they are repaid,
// and money that only covered losses (no balance left) adds nothing. Read from FM's own balance,
// so nothing is held in memory.
const WAGE_SHARE = 0.8, CASH_SHARE = 0.2, WAGE_FLOOR = 0.8, FM_WAGE_CAP = 5000000;
const BOARD_BUDGET = 0x70, BUDGET_ADDON = 0x4c, BILL = 0x7c, BILL_ALT = 0x78;   // weekly; budget = +0x70 + +0x4c
const wageBudget = (fin) => fin.add(BOARD_BUDGET).readS32() + fin.add(BUDGET_ADDON).readS32();
function setWages(idx, c) {
  const kept = keptRevenue(idx, c, LAST_SEASON);   // the last completed season (empty in a new game's first season)
  if (kept <= 0) return null;      // no completed season yet
  const cash = Math.max(0, BALANCE(c.fin));
  const base = WAGE_SHARE * kept + CASH_SHARE * cash;
  const share = Math.min(FM_WAGE_CAP, Math.floor(base / 52));
  const addon = c.fin.add(BUDGET_ADDON).readS32(), board = c.fin.add(BOARD_BUDGET).readS32(), before = board + addon;
  let target;
  if (before > share) {
    const med = median(idx.byLeague.get(c.league.toString()).map((o) => wageBudget(o.fin)));
    const bill = c.fin.add(BILL).readS32() || c.fin.add(BILL_ALT).readS32();
    target = Math.max(share, Math.floor(WAGE_FLOOR * bill), Math.floor(med));
    if (target >= before) return null;
  } else if (before < share && BALANCE(c.fin) >= 0) {
    target = share;
  } else return null;
  c.fin.add(BOARD_BUDGET).writeS32(Math.max(0, target - addon));
  return { before, after: Math.max(0, target - addon) + addon, kept, cash };
}
function setAllWages() {
  const idx = monthIndex || clubs(true);
  let up = 0, down = 0, change = 0;
  for (const c of idx.byFin.values()) {
    try {
      const r = setWages(idx, c);
      if (r) { if (r.after > r.before) up++; else down++; change += r.after - r.before; }
    } catch (e) {}
  }
  log(`wage budgets: ${up} raised, ${down} lowered, net change ${change} a week`);
}

recv("config", (msg) => {
  try { logFile = new File(msg.log, "a"); } catch (e) {}
  log("parity agent started");
  send({ started: true });
});
