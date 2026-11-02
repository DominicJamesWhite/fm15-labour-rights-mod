// Frida agent for parity mode: continental competitions (reports/parity/continental_format.md and
// continental_money.md). To be loaded and eternalized next to tools/parity_agent.js
// (MODE_AGENTS["parity"]); logs to the file given by recv("config").
//
// Two parts:
//
// FORMAT (table FORMATS, each entry switchable; master switch FORMAT_ENABLED): the Champions
// League, Europa League (only together with the CL), Copa Libertadores and AFC Champions League run
// as a single knockout cup stage at their final-knockout stage index. Each class's builder is
// replaced. Primary rule (CL, Libertadores, AFC): each member nation's league champion and cup
// winner (or the losing cup finalist, or the league runner-up when the nation has no cup; the two
// split champions for Apertura/Clausura nations; two seeded reputation-weighted top-division clubs
// for unloaded nations) plus the title holder. Secondary rule (EL): the two best-placed top-division
// clubs per member nation not in the CL (secondaryQualifiers()). The
// qualifying rounds are merged in front of the knockout rounds at settings load (ACT vt+0x30),
// counts and rules are set at 0x0103e360 (two legs, one-match final at a neutral venue, random
// draws, country protection in each club's first round), class pre-draw rules and CL->EL hand-offs
// are switched off and no data stage is created afterwards. The same is done for the CAF Champions
// League, CONCACAF Champions League and OFC Champions League (primary rule), and the Copa
// Sudamericana, AFC Cup and CAF Confederation Cup (secondary rule, excluding the primary cup's
// field). Competitions whose data has too few rounds for their field get extra rounds: copies of a
// data round parsed again from the competition's own record, dated at fixed day offsets from the
// first knockout round (FORMATS[].extra). Competitions whose season init is a whole vt+0x10 are
// replaced at that function (initReplace; the OFC's is the shared base 0x00fb3230, dispatched by
// class). Every risky step is preceded by a "<comp>: about to <step>" log line.
//
// MONEY (every continental competition, table COMPETITIONS): vanilla continental CompPay credits
// are suppressed (dummy club: no credit, no news). When the competition finishes, its season total
// T (fixed prize money plus, for the CL/EL, the TV market pool for the actual field) is paid in one
// settlement from the field FM saved in its stages: 40% participation (equal per club), 20%
// performance by stage reached (both as Prize money), 40% solidarity (equal per member nation, then
// equal per detailed club of the nation's pyramid, as Grants). Clubs without a full CLUB_FINANCE
// receive nothing and their shares are not paid. Nothing is held in memory.
// Anything unverified is marked GUESS and listed in reports/parity/continental_build.md.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const TODAY = va(0x0239ebf4);
const WORLD = va(0x02428ee0);
const COMP_MANAGER = va(0x024257fc);      // [mgr+4] = game comp manager, [mgr+8..+0xc] = national entries

const tc = (addr, ret, args) => new NativeFunction(va(addr), ret, ["pointer"].concat(args || []), "thiscall");
const CLUB_COUNT = tc(0x0151db30, "int");
const CLUB_AT = tc(0x0151da10, "pointer", ["int"]);
const FIN_OF = tc(0x014c9670, "pointer");                  // club -> CLUB_FINANCE, or 0 if not detailed
const PRIZE_IN = tc(0x016805d0, "void", ["int", "pointer"]); // CLUB_FINANCE vt+0xf0 (fin, amount, COMP@DB)
const GRANTS_IN = tc(0x0167feb0, "void", ["int"]);
const VEC_FREE = tc(0x00f64f80, "void");                   // vector<T*> destructor (frees storage, zeroes header)

// Stage building (continental_format.md 1.1; signatures checked by disassembly, see build report).
const OPERATOR_NEW = new NativeFunction(va(0x02055715), "pointer", ["uint32"], "mscdecl");
const STAGE_BASE_CTOR = tc(0x01075950, "pointer", ["int", "pointer"]);          // (stage, index, owner) ret 8
const CUP_ENTRANTS = tc(0x0103ebb0, "void", ["pointer", "pointer", "int", "int"]); // (stage, &vector<TEAM*>, pots, sort, seedFromRep) ret 0x10
const STAGE_INSERT = tc(0x00fa0e60, "int", ["pointer", "int"]);                  // (ACT, stage, amount) ret 8; 1 = ok
const REGISTER_TEAMS = tc(0x00f9cbb0, "void", ["pointer", "int", "int", "int", "pointer", "pointer", "int", "int"]); // ret 0x20
const PARSE_SETTINGS = tc(0x00fb4b10, "pointer", ["pointer", "int", "pointer"]); // (ACT, record, stage index, &s16 n) ret 0xc
const VEC_PUSH = tc(0x00fc3520, "void", ["pointer"]);                            // (vector*, &ptr) ret 4
const DEL_ROUND = tc(0x0103e440, "void", ["int", "pointer"]);                    // (CUP_SETTINGS, index, ACT) ret 8
const EMPTY_RECORD = va(0x02426d60);
// Dates ({u16 day of year 1-based | time slot << 9, u16 year}, as CUP_ROUND+0x06 and +0x02).
const DATE_ADD = tc(0x01c1ed10, "pointer", ["pointer", "int"]);  // (&date; &out, days) ret 8; negative days via 0x01c1ee00
const DATE_DIFF = tc(0x01c1f940, "int", ["pointer"]);            // (&a; &b) ret 4: a - b in days
const NULL_DATE = va(0x023a01c4);          // FM's "no date" (1 Jan 1900), written for draw dates "1900"/"stage setup day"
const SET_STATUS = tc(0x00fc04f0, "void", ["int"]);              // (ACT; s16 status) ret 4: ACT+0x8c, sub-comps too

const CUP_STAGE_VT = va(0x021ea9c0);
const DEAD_STAGE_VT = va(0x021ec84c);     // placeholder stage FM puts in unused slots (comp_finish.md)
const isDeadStage = (stage) => !stage.isNull() && stage.readPointer().equals(DEAD_STAGE_VT);
const VIRTUAL_CUP_STAGE_VT = va(0x0224d7cc);
const SEEDING_VTS = new Set([0x0223cca0, 0x02202d60, 0x0220be48, 0x0221bdf8, 0x02247af8, 0x02223298].map((a) => va(a).toString()));

// The first design paid shares at each tie result from a hook inside FM's cup tie code
// (0x01040c5c); it crashed the game (reports/parity/test5), so everything is now settled when the
// competition finishes. Suppressing the vanilla payments was proven safe on its own.
const SUPPRESS_VANILLA = true;

const EUR = 0.8, USD = 0.60606;            // internal units per EUR / USD (continental_money.md 1.2, trace)

let logFile = null;
function log(line) {
  if (!logFile) return;
  try { logFile.write(today() + " [continental] " + line + "\n"); logFile.flush(); } catch (e) {}
}
function today() {
  return new Date(Date.UTC(TODAY.add(2).readU16(), 0, TODAY.readU16() & 0x1ff)).toISOString().slice(0, 10);
}

// Names for the log, through FM's own text formatter (as tools/parity_agent.js does).
const TEXT_CTOR = tc(0x0188f4b0, "pointer");
const TEXT_SET = tc(0x0188fd00, "void", ["pointer"]);
const TEXT_ARG = tc(0x01493e80, "void", ["int", "pointer", "int", "int", "pointer"]);
const TEXT_RENDER = tc(0x01890790, "pointer");
const TEXT_DTOR = tc(0x0188fc80, "void");
const EMPTY_TEXT = va(0x02426d58);
function nameOf(token, obj) {
  try {
    if (obj.isNull()) return "-";
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
const teamName = (team) => nameOf("team", team);
const nationName = (nation) => nameOf("nation", nation);

// Virtual call obj->vt[off](...). NativeFunctions are made once per target and signature and kept
// (one per call made every club walk pay for a NativeFunction per detailed club).
const vfnCache = new Map();
function vfnOf(target, ret, args) {
  const key = `${target}|${ret}|${args.join(",")}`;
  let fn = vfnCache.get(key);
  if (!fn) { fn = new NativeFunction(target, ret, args, "thiscall"); vfnCache.set(key, fn); }
  return fn;
}
function vcall(obj, off, ret) {
  return vfnOf(obj.readPointer().add(off).readPointer(), ret, ["pointer"])(obj);
}
// FIN_OF (0x014c9670) without a native call where its answer is certain (as parity_agent.js): it
// returns [club+0x9c] when that is non-NULL and its vt+0x1c() returns al == 1, else 0. A constant
// vt+0x1c (live bytes "mov al,1 / xor al,al / xor eax,eax; ret") is answered from its bytes; any
// other code is still called through FIN_OF.
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

// COMP@DB and its ACTUAL_COMP point at each other (COMP+0x68, ACT+0x3c); normalise to the COMP@DB.
function compOf(p) {
  try { if (p.add(0x68).readPointer().add(0x3c).readPointer().equals(p)) return p; } catch (e) {}
  return p.add(0x3c).readPointer();
}

// --- Small readers ---------------------------------------------------------------------------

// MSVC vector<T*> header {begin, end, capacity} at p.
function readVec(p, max) {
  const begin = p.readPointer(), end = p.add(4).readPointer();
  if (begin.isNull()) return [];
  const n = end.sub(begin).toInt32() / 4;
  if (n < 0 || n > (max || 20000) || n !== Math.floor(n)) throw new Error("bad vector at " + p);
  const out = [];
  for (let i = 0; i < n; i++) out.push(begin.add(4 * i).readPointer());
  return out;
}
// A zero-filled vector header whose storage the game may allocate (pass to a getter, then VEC_FREE).
function gameVec() { return zeroed(12); }
function zeroed(size) {                     // Memory.alloc, explicitly zero-filled
  const p = Memory.alloc(size);
  for (let i = 0; i < size; i += 4) p.add(i).writeU32(0);
  return p;
}
// A read-only vector<T*> in agent memory, for game functions that only read their argument.
function agentVec(ptrs) {
  const buf = Memory.alloc(Math.max(4, 4 * ptrs.length));
  ptrs.forEach((p, i) => buf.add(4 * i).writePointer(p));
  const v = Memory.alloc(12);
  v.writePointer(buf);
  v.add(4).writePointer(buf.add(4 * ptrs.length));
  v.add(8).writePointer(buf.add(4 * ptrs.length));
  return { vec: v, buf };
}

const isCupStage = (stage) => { const vt = stage.readPointer(); return vt.equals(CUP_STAGE_VT) || vt.equals(VIRTUAL_CUP_STAGE_VT); };
const roundsOf = (settings) => readVec(settings.add(0x14), 64);
const ntms = (r) => r.add(0x1c).readS16(), nmmt = (r) => r.add(0x1e).readS16(), nmxt = (r) => r.add(0x20).readS16();
function roundName(r) {                     // stage-name id of a CUP_ROUND ([r+0xc]+8), -1 if none
  try { const n = r.add(0xc).readPointer(); return n.isNull() ? -1 : n.add(8).readS32(); } catch (e) { return -1; }
}

// Teams of any stage through its own getter (stage vt+0x64(&vector, includeEmpty), as 0x00fa0e60 does).
function stageTeams(stage) {
  const v = gameVec();
  vfnOf(stage.readPointer().add(0x64).readPointer(), "int", ["pointer", "pointer", "int"])(stage, v, 0);
  try { return readVec(v, 4096).filter((t) => !t.isNull()); } finally { VEC_FREE(v); }
}

// TEAM <-> CLUB. A team's club is team+0x10 (team+0x23 != 0 means a national team); a club's first
// team is *(club+0x10) (vector begin). toTeam accepts either and returns the first team, or null.
function clubOfTeam(team) {
  try {
    if (team.isNull() || team.add(0x23).readU8() !== 0) return null;
    const club = team.add(0x10).readPointer();
    return club.isNull() ? null : club;
  } catch (e) { return null; }
}
function firstTeam(club) {
  try {
    const b = club.add(0x10).readPointer();
    return b.isNull() || b.equals(club.add(0x14).readPointer()) ? null : b.readPointer();
  } catch (e) { return null; }
}
function toTeam(p) {
  try {
    if (p.isNull()) return null;
    const club = clubOfTeam(p);
    if (club && p.equals(firstTeam(club))) return p;             // p is a first team
    const t = firstTeam(p);                                        // p is a club
    if (t && p.equals(clubOfTeam(t))) return t;
  } catch (e) {}
  return null;
}

// Club reputation word team+0x64, decoded the way FUN_00f94050 does (pick.c). GUESS: this is the
// reputation FM's fallback pick uses (reports/parity/continental_format.md section 4).
function reputation(team) {
  const p = team.add(0x64), b = p.toUInt32() & 0xf, w = p.readU16();
  const rotr = (x, n) => (n === 0 ? x : (((x >>> n) | (x << (16 - n))) & 0xffff));
  let u = ~rotr(w, b) & 0xffff;
  u = ~rotr(u, 12) & 0xffff;
  const r = rotr(u, b);
  return r >= 0x8000 ? r - 0x10000 : r;
}

// --- Club indexes ----------------------------------------------------------------------------

// Detailed clubs by league nation (COMP+0x44), as parity_agent's pyramid. Rebuilt per settlement.
function detailedByNation() {
  const world = WORLD.readPointer(), n = CLUB_COUNT(world), byNation = new Map();
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
      push(byNation, nation.toString(), { club, fin });
    } catch (e) {}
  }
  return byNation;
}
// Every club (detailed or not) with its first team, league, level and nations; and every nation seen.
function allClubs() {
  const world = WORLD.readPointer(), n = CLUB_COUNT(world);
  const byLeagueNation = new Map(), nations = new Map(), clubNation = new Map(), byBased = new Map();
  for (let i = 0; i < n; i++) {
    try {
      const club = CLUB_AT(world, i);
      if (club.isNull()) continue;
      const own = club.add(0x60).readPointer();
      if (!own.isNull()) nations.set(own.toString(), own);
      const team = firstTeam(club);
      if (!team) continue;
      const league = team.add(0x30).readPointer();
      if (league.isNull()) continue;
      const nation = league.add(0x44).readPointer();
      if (nation.isNull()) continue;
      nations.set(nation.toString(), nation);
      clubNation.set(club.toString(), nation.toString());
      const c = { club, team, league, level: league.add(0xdd).readS8(), fin: finOf(club) };
      push(byLeagueNation, nation.toString(), c);
      if (!own.isNull()) push(byBased, own.toString(), c);     // by the club's own nation (basedFallback)
    } catch (e) {}
  }
  return { byLeagueNation, nations, clubNation, byBased };
}
function push(map, key, value) {
  const list = map.get(key);
  if (list) list.push(value); else map.set(key, [value]);
}
// Split amount equally over the clubs; the rounding remainder goes to the first.
function payEqually(list, amount) {
  if (amount <= 0 || !list || list.length === 0) return;
  const each = Math.floor(amount / list.length);
  list.forEach((c, i) => GRANTS_IN(c.fin, each + (i === 0 ? amount - each * list.length : 0)));
}

// --- Confederations ---------------------------------------------------------------------------

// The confederation's seeding object: [[[CONTINENT+0x54]+0x20]+0x50] (path used by ACT 0x00fbcdc0).
function seedingOf(continent) {
  try {
    if (continent.isNull()) return null;
    const s = continent.add(0x54).readPointer().add(0x20).readPointer().add(0x50).readPointer();
    return !s.isNull() && SEEDING_VTS.has(s.readPointer().toString()) ? s : null;
  } catch (e) { return null; }
}
// Member nations of a competition's confederation: the seeding object's member list
// (vector<NATION_CONT_INFO*> at +4, NATION* at info+0) plus every nation seen on a club whose
// continent (nation+0xdc) is the competition's (COMP+0x40), plus the table's guests. A world
// competition (no continent, or world: true) counts every nation seen.
function memberNations(comp, entry, all) {
  const continent = comp.add(0x40).readPointer(), members = new Map();
  const world = entry.world || continent.isNull();
  const seeding = world ? null : seedingOf(continent);
  if (seeding) {
    try { for (const info of readVec(seeding.add(4), 512)) { const n = info.readPointer(); if (!n.isNull()) members.set(n.toString(), n); } } catch (e) {}
  }
  for (const n of all.nations.values()) {
    try { if (world || n.add(0xdc).readPointer().equals(continent)) members.set(n.toString(), n); } catch (e) {}
  }
  for (const id of entry.guests || []) {
    for (const n of all.nations.values()) if (n.add(8).readS32() === id) members.set(n.toString(), n);
  }
  return { list: Array.from(members.values()), seeding, world };
}

// --- MONEY ------------------------------------------------------------------------------------
// Vanilla season totals in internal units (continental_money.md 2.4 unless noted). marketPool() is
// the CL/EL type-8 pool, a stub returning the vanilla constant until the reviewer's per-season
// computation replaces it. entrants = vanilla number of clubs in the competition (participation
// divisor); a converted format uses its own stage's entrant count instead.

const COMPETITIONS = [
  { name: "Champions League", vt: 0x02235244, fixed: 426.5e6, entrants: 77 },
  { name: "Europa League", vt: 0x02239c10, fixed: 120.2e6, entrants: 195 },
  { name: "UEFA Super Cup", vt: 0x021fb3f4, fixed: (3.0e6 + 2.2e6) * EUR, entrants: 2 },       // code 0x010d7cb0
  { name: "Copa Libertadores", vt: 0x0221ce1c, fixed: 51.9e6 * USD, entrants: 38, guests: [0x17b] },
  { name: "Copa Sudamericana", vt: 0x02204d5c, fixed: 46 * 2 * 120000 * USD, entrants: 47 },  // GUESS: 46 ties x 120k USD each side
  { name: "Recopa Sudamericana", vt: 0x0220f784, fixed: (300000 + 200000) * USD, entrants: 2 }, // stream 394
  { name: "AFC Champions League", vt: 0x02218a1c, fixed: 6.51e6, entrants: 44 },
  { name: "AFC Cup", vt: 0x0224298c, fixed: 1236384, entrants: 36 },                         // GUESS: code + data, see report
  { name: "AFC President's Cup", vt: 0x021ed404, fixed: 190909, entrants: 16 },              // code 16 x 15k USD + final
  { name: "CAF Champions League", vt: 0x022349b4, fixed: 9.1e6, entrants: 64 },
  { name: "CAF Confederation Cup", vt: 0x021f1070, fixed: 1.32e6, entrants: 72 },
  { name: "CAF Super Cup", vt: 0x022476b0, fixed: 0, entrants: 2 },                           // stream 2: no money
  { name: "CONCACAF Champions League", vt: 0x021f14b8, fixed: 0, entrants: 24 },              // no money tags
  { name: "OFC Champions League", vt: 0x02224448, fixed: 110000 * USD, entrants: 15 },
  { name: "Club World Cup", vt: 0x0220a048, fixed: 16.5e6 * USD, entrants: 7, world: true },  // stream 479
];
const moneyByVt = new Map(COMPETITIONS.map((c) => [va(c.vt).toString(), c]));
const moneyOf = (act) => { try { return act.isNull() ? null : moneyByVt.get(act.readPointer().toString()) || null; } catch (e) { return null; } };

// The pot T of a competition's season = its fixed prize money (vanilla tables and code constants)
// plus, for the CL and EL, the TV market pool worked out for the actual field (market_pool.md).
const pot = (entry) => Math.floor(entry.fixed);

// CL: FM's per-nation base (0x010d63f0, stdcall nation, internal units) summed over the distinct
// nations of the clubs that reached the last 32 (user decision: the same 32 clubs vanilla pays). The
// +-20% league-reputation drift FM applies per club is left out (zero in a game's first season).
// EL: FM's band by nation level (0x015ec7a0) for each of the last 8, plus the semi-final and final
// bonuses. Both in internal units.
const NATION_BASE = new NativeFunction(va(0x010d63f0), "int", ["pointer"], "stdcall");
const NATION_LEVEL = tc(0x015ec7a0, "uint8");
const nationOfTeam = (team) => { const c = clubOfTeam(team); return c ? c.add(0x60).readPointer() : null; };
const elBand = (x) => (x >= 18 ? 3.5e6 : x >= 15 ? 2.0e6 : x >= 11 ? 1.0e6 : x >= 6 ? 5e5 : 2.5e5);

function marketPool(entry, field) {
  if (entry.name === "Champions League") {
    const nations = new Map();
    for (const f of field) { if (f.reached > 32) continue; const n = nationOfTeam(f.team); if (n) nations.set(n.toString(), n); }
    let total = 0;
    for (const n of nations.values()) total += NATION_BASE(n);
    return { total, detail: `${nations.size} nations of the last 32` };
  }
  if (entry.name === "Europa League") {
    let total = Math.round((2 * 1112500 + 2 * 797000) * EUR), k = 0;
    for (const f of field) {
      if (f.reached > 8) continue;
      const n = nationOfTeam(f.team);
      if (n) { total += Math.round(elBand(NATION_LEVEL(n)) * EUR); k++; }
    }
    return { total, detail: `${k} quarter-finalists` };
  }
  return { total: 0, detail: "" };
}

const PARTICIPATION = 0.4, PERFORMANCE = 0.2, SOLIDARITY = 0.4;
// Performance in % of the performance pot by stage reached: winner, runner-up, then losers by the
// size of the round they went out in. A group stage counts as the round of its size, so the 32-club
// CL group stage's 16 eliminated clubs get the last-32 share. Nothing earlier. Where tiers are
// missing (super cups, Club World Cup) the existing ones are scaled to fill 100%.
const WINNER_PCT = 30, RUNNER_UP_PCT = 15;
const LOSER_PCT = new Map([[4, 7.5], [8, 3.75], [16, 1.5625], [32, 0.78125]]);
const performancePct = (f) =>
  (f.place === "winner" ? WINNER_PCT : f.place === "runner-up" ? RUNNER_UP_PCT : LOSER_PCT.get(f.reached) || 0);

// 1. Suppress every vanilla continental CompPay credit (0x0091a160, args (club, amount, ACT, ...)):
// a zero-filled dummy club has a null finance at +0x9c, so CompPay credits nothing and posts no news.
const DUMMY_CLUB = zeroed(0x400);
if (SUPPRESS_VANILLA) Interceptor.attach(va(0x0091a160), {
  onEnter(args) {
    try {
      if (moneyOf(args[2])) args[0] = DUMMY_CLUB;
    } catch (e) { log("CompPay hook error " + e.stack); }
  },
});

// 2. The whole settlement when the competition finishes (0x00fad710, ECX = ACT; parity_agent.js
// hooks the same function for leagues): all of T is paid at once from the field FM saved in its
// stages. The competition-finished step runs once per edition, so nothing is paid twice, and
// nothing is held in memory beforehand.
Interceptor.attach(va(0x00fad710), {
  onEnter() {
    this.act = this.context.ecx;
    try { captureTable(this.act); } catch (e) { log("final table capture error " + e.stack); }
    try { cacheRecords(this.act); } catch (e) { log("season record cache error " + e.stack); }
    try {
      const f = formatOf(this.act);
      if (f && converted(this.act, f)) repairRanking(this.act, f);
    } catch (e) { log("season ranking repair error " + e.stack); }
  },
  onLeave() {
    try {
      const entry = moneyOf(this.act);
      if (entry) settle(entry, this.act, false);
    } catch (e) { log("settlement error " + e.stack); }
  },
});

// FM records an edition in the competition history (COMP+0x64 and the history list) inside
// 0x00fad710: 0x00fb02c0(-1) reads winner and runner-up from the season ranking (ACT+0x6c, entries
// at +0x34c: +4 TEAM, +0x13/+0x14/+0x15 levels from the round a club went out in) with 0x00fcac20,
// which gives up when more than one entry holds level 0 or level 1 at +0x14 (reports/parity/
// el_history.md). Editions built before levelDonorRounds (below) left their first-round losers at the
// final's loser level, so FM never recorded them. Just before the record, every entry at that level
// other than the two finalists is moved to the level above the highest earlier round, as if it had
// gone out there; then FM records the edition itself. Does nothing for an edition built with
// distinct levels.
function repairRanking(act, f) {
  const season = act.add(0x6c).readPointer();
  const stage = readVec(act.add(0x4c), 64)[f.koIndex];
  if (season.isNull() || !stage || stage.isNull() || !isCupStage(stage) || stage.add(0x10).readU8() === 0) return;
  const settings = stage.add(0x38).readPointer();
  if (settings.isNull()) return;
  const rounds = roundsOf(settings);
  if (rounds.length < 2) return;
  const ru = rounds[rounds.length - 1].add(0x5e).readU8();
  if (ru === 0xff) return;
  const tie = PO_TIE(stage, rounds.length - 1, 0);
  if (tie.isNull()) return;
  const table = stage.add(0x3c).readPointer(), count = stage.add(0x40).readS16();
  const finalists = [tie.readS16(), tie.add(8).readS16()].filter((i) => i >= 0 && i < count).map((i) => table.add(12 * i).readPointer().toString());
  if (finalists.length !== 2) return;
  const earlier = rounds.slice(0, -1).map((r) => r.add(0x5e).readU8()).filter((v) => v !== 0xff);
  if (!earlier.length) return;
  const level = Math.max(ru, ...earlier) + (rounds[0].add(0x5e).readU8() > ru && rounds[0].add(0x5e).readU8() !== 0xff ? 0 : 1);
  let moved = 0;
  for (const e of readVec(season.add(0x34c), 4096)) {
    if (e.isNull() || e.add(0x14).readU8() !== ru || finalists.includes(e.add(4).readPointer().toString())) continue;
    for (const off of [0x13, 0x14, 0x15]) if (e.add(off).readU8() === ru) e.add(off).writeU8(level);
    moved++;
  }
  if (moved) log(`${f.name}: ${moved} season ranking entries at the final's loser level ${ru} moved to level ${level}, so FM records the edition's winner`);
}

// FM records the edition's winner and runner-up in the competition history only after the
// finished step, so a settlement that needs the history (shared runner-up code) waits for the
// next game day, picked up at the daily competition step (0x00fac810).
// The daily step runs for every competition every game day, so its listener is only attached once a
// settlement is first deferred (rare: one edition in all test runs); until then the hook costs
// nothing. It is attached from the deferring 0x00fad710 callback, which FM calls from inside
// 0x00fac810, so the next day's first call is caught exactly as before. Once attached it stays.
const pendingSettle = [];
const dayNumber = () => TODAY.add(2).readU16() * 512 + (TODAY.readU16() & 0x1ff);
let pendingHook = null;
function deferSettle(p) {
  pendingSettle.push(p);
  if (pendingHook) return;
  try { pendingHook = attachDailyStep(); } catch (e) { log("daily step hook error, delayed settlement lost: " + e.stack); }
}
function attachDailyStep() {
  return Interceptor.attach(va(0x00fac810), {
    onEnter() {
      if (!pendingSettle.length) return;
      const d = dayNumber();
      for (let i = pendingSettle.length - 1; i >= 0; i--) {
        const p = pendingSettle[i];
        if (p.day === d) continue;
        pendingSettle.splice(i, 1);
        try { settle(p.entry, p.act, true); } catch (e) { log("delayed settlement error " + e.stack); }
      }
    },
  });
}

// The field: every team in any of the competition's stages, with the smallest round size it
// reached. Cup stages: team entry status (+6: -1 still in, the index of the round it went out in,
// 0x1e winner, 0x1f runner-up) over the stage's rounds. Other stages (groups): the stage's size.
function fieldOf(act, retry) {
  const byTeam = new Map(), samples = [];
  let historyPending = false;
  const note = (team, reached, place) => {
    if (team.isNull()) return;
    const key = team.toString(), f = byTeam.get(key);
    if (!f) byTeam.set(key, { team, reached, place });
    else if (reached < f.reached) { f.reached = reached; f.place = place; }
  };
  for (const stage of readVec(act.add(0x4c), 64)) {
    if (stage.isNull() || isDeadStage(stage)) continue;
    if (isCupStage(stage)) {
      const rounds = roundsOf(stage.add(0x38).readPointer());
      const table = stage.add(0x3c).readPointer(), count = stage.add(0x40).readS16();
      // Status is a placing code from the round data (0x01040d44, 0x01041067): a round's losers
      // get its +0x5c; the final's (no next round, +0x59 = +0x5a = 0xff) winner its +0x5b, or
      // 0x1e/0x1f when the data leaves them 0xff. Only a two-team final makes a winner/runner-up;
      // a qualifying stage's survivors count as taking part.
      const last = rounds.length ? rounds[rounds.length - 1] : null;
      const isFinal = last && ntms(last) === 2 && last.add(0x59).readU8() === 0xff && last.add(0x5a).readU8() === 0xff;
      const code = (b) => (b === 0xff ? null : (b << 24) >> 24);
      const winCode = isFinal ? (code(last.add(0x5b).readU8()) ?? 0x1e) : null;
      const ruCode = isFinal ? (code(last.add(0x5c).readU8()) ?? 0x1f) : null;
      const outIn = new Map();                         // loser code -> round size
      rounds.forEach((r) => { const c = code(r.add(0x5c).readU8()); if (c !== null && !outIn.has(c)) outIn.set(c, ntms(r)); });
      // An earlier round can share the final's loser code (the EL's first round: FM writes 1 there
      // from its own data whatever the round holds). Then the runner-up is the finalist in the final
      // tie with that code, or else the one FM recorded in the competition history (COMP+0x64).
      let ruTeam = null;
      if (isFinal) {
        const losers = [];
        for (let i = 0; i < count; i++) if (table.add(12 * i + 6).readS8() === ruCode) losers.push(table.add(12 * i).readPointer());
        // First choice: the final's tie (CUP_STAGE vt+0x10c, tie +0 / +8 = home / away entry index):
        // the finalist carrying the runner-up code.
        try {
          const tie = PO_TIE(stage, rounds.length - 1, 0);
          if (losers.length > 1 && !tie.isNull()) {
            const ends = [tie.readS16(), tie.add(8).readS16()].filter((i) => i >= 0 && i < count);
            const ru = ends.filter((i) => table.add(12 * i + 6).readS8() === ruCode);
            if (ends.length === 2 && ru.length === 1) {
              ruTeam = table.add(12 * ru[0]).readPointer();
              log(`${losers.length} teams share the runner-up code ${ruCode}: runner-up ${teamName(ruTeam)} from the final tie`);
            }
          }
        } catch (e) { log("final tie read error " + e.stack); }
        if (losers.length > 1 && ruTeam === null) {
          const h = history(act.add(0x3c).readPointer());
          let win = null;
          for (let i = 0; i < count; i++) if (table.add(12 * i + 6).readS8() === winCode) win = table.add(12 * i).readPointer();
          const ok = h.winner && win && sameClub(h.winner, win) && h.runnerUp && losers.some((t) => sameClub(t, h.runnerUp));
          ruTeam = ok ? losers.find((t) => sameClub(t, h.runnerUp)) : NULL;
          if (!ok && !retry) historyPending = true;
          log(`${losers.length} teams share the runner-up code ${ruCode}: ${ok ? "runner-up " + teamName(ruTeam) + " from the history" : retry ? "history still not current, no runner-up share" : "history not current yet, settling tomorrow"}`);
        }
        if (losers.length > 1) {
          const earlier = rounds.slice(0, -1).find((r) => code(r.add(0x5c).readU8()) === ruCode);
          outIn.set(ruCode, earlier ? ntms(earlier) : ntms(rounds[0]));
        }
      }
      for (let i = 0; i < count; i++) {
        const e = table.add(12 * i), team = e.readPointer(), status = e.add(6).readS8();
        if (samples.length < 6) samples.push(status);
        if (isFinal && status === winCode) note(team, 1, "winner");
        else if (isFinal && status === ruCode && (ruTeam === null || team.equals(ruTeam))) note(team, 2, "runner-up");
        else if (status !== -1 && outIn.has(status)) note(team, outIn.get(status), "");
        else note(team, 1e9, "");                     // still in, qualified onwards, or unknown: participation only
      }
    } else {
      const teams = stageTeams(stage);
      for (const t of teams) note(t, teams.length, "");
    }
  }
  return { field: [...byTeam.values()], samples, historyPending };
}

function settle(entry, act, retry) {
  const comp = act.add(0x3c).readPointer();
  const { field, samples, historyPending } = fieldOf(act, retry);
  if (historyPending) { deferSettle({ entry, act, day: dayNumber() }); return; }
  if (field.length === 0) { log(`${entry.name}: finished with no field found, nothing paid`); return; }
  const mp = marketPool(entry, field);
  const T = pot(entry) + mp.total;
  if (T <= 0) { log(`${entry.name}: finished, no prize money`); return; }
  const totalPct = field.reduce((s, f) => s + performancePct(f), 0);
  const scale = totalPct > 0 ? 100 / totalPct : 0;
  const each = Math.floor(PARTICIPATION * T / field.length);
  let paid = 0, paidClubs = 0;
  for (const f of field) {
    const club = clubOfTeam(f.team);
    if (!club) continue;
    const fin = FIN_OF(club);
    if (fin.isNull()) continue;                            // not detailed: its share is not paid
    const amount = each + Math.floor(PERFORMANCE * T * performancePct(f) * scale / 100);
    PRIZE_IN(fin, amount, comp);
    paid += amount;
    paidClubs++;
    if (f.place) log(`${entry.name}: ${f.place} ${clubName(club)} ${amount}`);
  }
  log(`${entry.name}: settled T ${T} (fixed ${pot(entry)}, market pool ${mp.total}${mp.detail ? ", " + mp.detail : ""}); ` +
      `field ${field.length} clubs, ${each} participation each, performance scale ${scale.toFixed(3)}; ` +
      `paid ${paid} to ${paidClubs} detailed clubs; first statuses ${samples.join(",")}`);
  solidarity(entry, comp, act, Math.floor(SOLIDARITY * T), `field ${field.length}`);
}

// 4. Solidarity at the final: equal per member nation (all members count), then equal per
// detailed club of that nation's pyramid. Members without detailed clubs are simply not paid.
function solidarity(entry, comp, act, amount, what) {
  if (amount <= 0) return;
  const all = allClubs();
  const m = memberNations(comp, entry, all);
  if (m.list.length === 0) { log(`solidarity: ${entry.name} no member nations found, nothing paid`); return; }
  const byNation = detailedByNation();
  const per = Math.floor(amount / m.list.length);
  let nations = 0, clubs = 0;
  for (const n of m.list) {
    const list = byNation.get(n.toString());
    if (!list) continue;
    payEqually(list, per);
    nations++;
    clubs += list.length;
  }
  let registered = -1;
  try { const s = act.add(0x6c).readPointer(); if (!s.isNull()) registered = readVec(s.add(0x34c), 4096).length; } catch (e) {}
  log(`solidarity (${what}): ${entry.name} pot ${amount}, ${m.list.length} members (seeding list ${m.seeding ? "yes" : "no"}${m.world ? ", world" : ""}), ` +
      `${per} each, paid to ${nations} nations / ${clubs} clubs; season object lists ${registered} teams`);
}

// --- FORMAT: continental cups as one knockout stage -------------------------------------------
// Master switch: with FORMAT_ENABLED false no format hook is installed and every competition keeps
// FM's format (the money rules still apply). Each FORMATS entry has its own enabled flag as well.
const FORMAT_ENABLED = true;

// One table entry per converted competition (reports/parity/continental_build.md section 1):
//   compId        COMP@DB id, found with 0x01494420 (used to find a partner competition's ACT)
//   koIndex       final-knockout stage slot; the whole competition runs there
//   donorStages   stages whose rounds are parsed and put in front of the knockout rounds
//   capacity      2^(number of rounds after the merge): the largest field the rounds can hold
//   stageBuilder  replaced builder (thiscall, ECX = ACT, no stack arguments, plain ret, one caller
//                 that afterwards marks the competition running with 0x00fc04f0)
//   skipBuilders  further builders of the same ABI that must do nothing once converted
//   skipWhenConverted  functions (ECX = this ACT, no stack arguments, plain ret) skipped once converted
//   settingsLoad  ACT vt+0x30 of the class (thiscall (ACT; stage index, &s16 n) ret 8), hooked onLeave
//   preDrawNullRound  vt+0x29c that tests its round argument first: called with a null round
//   preDrawSkip   vt+0x29c body (thiscall (ACT; stage, round) ret 8) replaced by the base no-op
//   deactivateCodes  entry codes of ACT+0x14c places the vanilla caller still handles after the
//                 builder (CL code 0 = direct group entrants): their active byte +5 is cleared
//   rule          "primary" (champion + cup winner) or "secondary" (one club per nation)
//   excludeFieldOf  secondary rule: clubs in this competition's field are not eligible
//   pair          competitions that must run converted together (CL and EL)
//   entryOnly     the format is not changed, only the entry (installEntryOnly; no entry uses it now)
//   salt          seeds the reputation-weighted picks so a recomputation gives the same clubs
// Fields used by the competitions added after the first four (continental_build.md section 8):
//   initReplace   the class's whole season init (ACT vt+0x10, thiscall (ACT; arg) ret 4) instead of a
//                 stageBuilder; after a build the competition is marked running with 0x00fc04f0(-2)
//                 as every class init does. 0x00fb3230 is the base vt+0x10 of every competition: one
//                 replacement dispatches by class and calls the original for everything else.
//   extra         { template: [stage, round], offsets: [days...] }: when the field needs more rounds
//                 than donors + knockout have, copies of that data round (parsed again from the
//                 record) go between the donor rounds and the knockout rounds, the c-th last at
//                 offsets[len - c] days from the first knockout round's first match. Their draw date
//                 is FM's "no date" (drawn when their teams are known, as the merged AFC R16).
//   register      false: no season-object registration (the vanilla builder has none); an array:
//                 the three values the vanilla init passes to 0x00f9cbb0 (default -1, -1, -1)
//   vanillaEntrants  koIndex 0 only: the vanilla stage sits in the same slot, so a stage with exactly
//                 this many entrants is vanilla (the Sudamericana's fixed 47)
//   memberTags    secondary cups with their own membership: NATION_CONT_INFO tags of FM's allocation
//                 (any > 0 = member); memberIds is the static fallback if the tags can't be read
//   basedFallback a member nation without its own league pyramid uses the clubs based there that
//                 play abroad (Canada in CONCACAF; only for formats that set it)
//   eligibilitySkip  class vt+0x10c (thiscall (ACT; team, x) ret 8, bool) answered "yes" once converted
//   entryCode     byte written to team+0x6b of each entrant (the vanilla builders' entry-stage code).
//                 CL 6 / EL 4: UEFA's squad registration (eur_c_get_squad_selection_teams 0x010d33a0
//                 -> 0x010d3580) registers a club at a deadline only if (signed) team+0x6b >= that
//                 deadline's stage code (CL 6,5,2,1,0; EL 4,3,2,1,0). 0xff (-1) is below every code,
//                 so no converted club was ever registered and FM rejected its unregistered players
//                 (eligibility reason 22, 0x005bd3b0). 6 / 4 are the vanilla codes of the earliest
//                 (first qualifying round) entrants, registered at every deadline. See
//                 reports/parity/virtual_players_fix.md.
const FORMATS = [
  {
    name: "Champions League",
    enabled: true,
    compId: 0x13db92,              // 1301394
    vt: 0x02235244,
    koIndex: 3,                    // R16/QF/SF/F in data
    donorStages: [0],              // Q1/Q2/Q3/PO
    capacity: 256,                 // 4 + 4 rounds
    stageBuilder: 0x010d3b10,      // stage-0 builder, called by vt+0x10 0x010d37a0 at 0x010d37ed
    skipBuilders: [0x010d3ea0],    // stage-1 (league path) builder, called at 0x010d37f4
    settingsLoad: 0x010d7750,      // CL vt+0x30 (calls 0x00fb4b10 itself, not the base)
    deactivateCodes: [0],          // 0x010d3821.. marks and registers code-0 places after the builders
    entryCode: 6,                  // as 0x010d3b9f writes for Q1 entrants: registered at every CL deadline
    rule: "primary",
    holder: true,
    pair: "Europa League",
    salt: 1,
  },
  {
    name: "Europa League",
    enabled: true,
    compId: 0x13db94,              // 1301396
    vt: 0x02239c10,
    koIndex: 2,                    // R32/R16/QF/SF/F in data
    donorStages: [0],              // Q1/Q2/Q3/PO
    capacity: 512,                 // 4 + 5 rounds
    stageBuilder: 0x010d8330,      // whole init, called by vt+0x10 0x010d8310 at 0x010d8313
    // CL -> EL hand-offs (ECX = EL ACT): 0x010d8d40 builds the EL groups with CL losers,
    // 0x010d9280 the R32 with CL thirds. Called from the CL and EL vt+0x38 (0x010d3920, 0x010dac30).
    skipWhenConverted: [0x010d8d40, 0x010d9280],
    settingsLoad: 0x010dad70,      // EL vt+0x30 (rewrites stage-0 counts; stage 2 is a plain parse)
    preDrawSkip: 0x010d9db0,       // EL vt+0x29c (slot holds the thunk 0x010d9da0): fixed R32 mapping
    entryCode: 4,                  // as 0x010d843f writes for Q1 entrants: registered at every EL deadline
    rule: "secondary",
    excludeFieldOf: "Champions League",
    holder: false,
    pair: "Champions League",
    salt: 2,
  },
  {
    name: "Copa Libertadores",
    enabled: true,
    compId: 0x1900f,               // 102415
    vt: 0x0221ce1c,
    koIndex: 4,                    // final knockout stage slot (R16/QF/SF/F in data)
    donorStages: [0],              // stage 0's preliminary round goes in front of the knockout rounds
    capacity: 32,                  // 1 + 4 rounds
    stageBuilder: 0x01156480,      // stage-0 builder called by vt+0x10 0x01156460
    settingsLoad: 0x00fb4af0,      // the base vt+0x30
    preDrawNullRound: 0x01158010,  // vt+0x29c: same-nation semi-final rule
    // sam_c_get_squad_selection_teams 0x01155af0 (group 1): deadlines 0/1 (28 Jan, 21 Feb) register
    // only code 1 (vanilla preliminary-round entrants, 0x0115652c), deadline 2 only codes != 1,
    // 3/4 all. Our field starts in the preliminary round, so it gets the preliminary code.
    entryCode: 1,
    rule: "primary",
    holder: true,
    guests: [0x17b],               // Mexico (nation id used by 0x01157ab0)
    // GUESS: Apertura/Clausura nations in the FM15 database, matched by FM's own nation name; ids
    // can be added once the C2 log shows them.
    splitNames: ["Bolivia", "Chile", "Colombia", "Ecuador", "Paraguay", "Peru", "Uruguay", "Venezuela", "Mexico"],
    splitIds: [0x17b],
    salt: 3,
  },
  {
    name: "AFC Champions League",
    enabled: true,
    compId: 0x1f136,               // 127286
    vt: 0x02218a1c,
    koIndex: 3,                    // R16/QF/SF/F in data
    donorStages: [0],              // East play-offs, 3 single-leg rounds
    capacity: 128,                 // 3 + 4 rounds
    stageBuilder: 0x0109edc0,      // stages 0 and 1, called by vt+0x10 0x0109ed70 at 0x0109ed73
    settingsLoad: 0x0109fad0,      // AFC vt+0x30 (a plain parse; shared with three other classes)
    // asi_c_get_squad_selection_teams 0x0109e8a0 (group 0): the first deadline (index 2, 27 Jan,
    // play-offs) registers only codes 2..7 (vanilla play-off entrants 0x0109eea0..0x0109f1a9);
    // 0xff (-1) missed it. 6 (as 0x0109f0e9) is even, so vt+0x390 0x0109f700 still answers true
    // for every argument, exactly as for 0xff.
    entryCode: 6,
    rule: "primary",
    holder: true,
    salt: 4,
  },
  {
    // No comps.dbc record: vt+0x30 0x01158f40 builds 6 rounds in code (names 25/26/6/17/18/20, dates
    // from vt+0x40 0x01159fb0) whatever the entrant count, so the whole competition runs in stage 0
    // with those rounds; 0x0103e360 sizes them for our field and deletes the empty leading ones.
    // The vanilla init 0x01158750 (47 places, fixed pots, mapping 0x010659f0) is replaced.
    name: "Copa Sudamericana",
    enabled: true,
    compId: 0x4d87f,               // 317567
    vt: 0x02204d5c,
    koIndex: 0,                    // the vanilla stage slot too
    donorStages: [],
    capacity: 64,                  // 6 code-built rounds
    vanillaEntrants: 47,           // 0x01158750 builds only with exactly 47 (0xb8/4 + 1)
    stageBuilder: 0x01158750,      // called by vt+0x10 0x01158730 at 0x01158733, then 0x00fc04f0(-2)
    entryCode: 0xff,               // vanilla writes 0; sam_c group 2 (0x01155af0) doesn't test +0x6b
    register: false,               // 0x01158750 registers nothing
    rule: "secondary",
    excludeFieldOf: "Copa Libertadores",
    guests: [0x17b],               // as the Libertadores table
    salt: 5,
  },
  {
    name: "CAF Champions League",
    enabled: true,
    compId: 0x1f143,               // 127299 (stream 0)
    vt: 0x022349b4,
    koIndex: 2,                    // SF/F in data
    donorStages: [0],              // 28/6/7, two legs each (Feb-Apr)
    // 5 data rounds = 32; two places per member nation (about 55) need 7. Added rounds copy stage 0
    // round 2 (name 7, two legs), dated before the SF (late Sep) in the old group-stage months.
    extra: { template: [0, 2], offsets: [-147, -105, -63] },
    capacity: 256,                 // 5 + 3 rounds
    stageBuilder: 0x01099c90,      // stage-0 builder, called by vt+0x10 0x01099c70 at 0x01099c73
    settingsLoad: 0x00fb4af0,      // base vt+0x30
    // afr_c_get_squad_selection_teams 0x010999e0 doesn't test +0x6b: it takes clubs whose team+0x50
    // (or [team+0x54]+0x7c) is this competition (0x01099b90), which markEntrant sets.
    entryCode: 0xff,
    register: false,               // 0x01099c90 registers nothing
    rule: "primary",
    holder: true,
    // The Confederation Cup's vanilla stage 0 waits for 8 CL R16 losers (data fate action 53 in CL
    // stage 0, not applied once that stage is a donor), and a vanilla CL would add them to a
    // converted Confederation Cup's dead stage 0: the two change together.
    pair: "CAF Confederation Cup",
    salt: 6,
  },
  {
    name: "CAF Confederation Cup",
    enabled: true,
    compId: 0xb75fa6,              // 12017574 (stream 1)
    vt: 0x021f1070,
    koIndex: 2,                    // SF/F in data
    donorStages: [0],              // 28/6/7/8, two legs each (Feb-Apr)
    extra: { template: [0, 3], offsets: [-84] },   // only if more than 64 entrants
    capacity: 128,                 // 6 + 1 rounds
    initReplace: 0x0109c970,       // vt+0x10 itself (no direct caller), ret 4
    settingsLoad: 0x00fb4af0,      // base vt+0x30
    entryCode: 0xff,               // registered through team+0x50 as the CAF Champions League
    register: [5000, 3000, 6000],  // as 0x0109c970 at 0x0109ca50..0x0109ca6c
    rule: "secondary",
    excludeFieldOf: "CAF Champions League",
    holder: false,
    pair: "CAF Champions League",
    salt: 7,
  },
  {
    name: "CONCACAF Champions League",
    enabled: true,
    compId: 0x30a3d11,             // 51002641 (stream 333)
    vt: 0x021f14b8,
    koIndex: 1,                    // QF/SF/F in data (stage 0 is the groups)
    donorStages: [],
    // 3 data rounds = 8; about 40 member nations need 7. Added rounds copy the QF (name 17, two
    // legs), dated Aug-Nov (the old group months) from the QF's late-February first leg.
    extra: { template: [1, 0], offsets: [-231, -203, -175, -147, -119] },
    capacity: 256,                 // 3 + 5 rounds
    initReplace: 0x0113b860,       // vt+0x10 itself (no direct caller), ret 4; also forces a Canadian club
    settingsLoad: 0x00fb4af0,      // base vt+0x30
    entryCode: 0xff,               // as 0x0113b860 writes; nam_c has no squad-selection script
    rule: "primary",
    holder: true,
    basedFallback: true,           // Canada: its clubs play in US leagues
    // GUESS: Apertura/Clausura nations, matched by FM's own nation name (as the Libertadores table).
    splitNames: ["Mexico", "Costa Rica", "Honduras", "Guatemala", "El Salvador", "Panama", "Nicaragua", "Belize"],
    splitIds: [0x17b],
    salt: 8,
  },
  {
    name: "OFC Champions League",
    enabled: true,
    compId: 0x1f135,               // 127285 (stream 356)
    vt: 0x02224448,
    koIndex: 2,                    // SF/F in data (stage 0 a 4-team league, stage 1 the groups)
    donorStages: [],
    // 2 data rounds = 4; about 11 member nations need 5. Added rounds copy the SF (two legs),
    // dated Dec-Mar from its late-April first leg.
    extra: { template: [2, 0], offsets: [-133, -98, -70, -42] },
    capacity: 64,                  // 2 + 4 rounds
    initReplace: 0x00fb3230,       // the base vt+0x10 (OFC has no override): shared, dispatched by class
    settingsLoad: 0x00fb4af0,      // base vt+0x30
    entryCode: 0xff,               // oce_c 0x01147690 drops only code 0 at its first deadline (16 Sep)
    rule: "primary",
    holder: true,
    salt: 9,
  },
  {
    name: "AFC Cup",
    enabled: true,
    compId: 0xf49e7,               // 1001959 (stream 13)
    vt: 0x0224298c,
    koIndex: 2,                    // R16 (one leg)/QF/SF/F in data
    donorStages: [0],              // play-offs 149/150, one leg each (Feb)
    capacity: 64,                  // 2 + 4 rounds
    initReplace: 0x0109fbd0,       // vt+0x10 itself (base 0x00fb3230, then -2 unless -5), ret 4
    settingsLoad: 0x010a0690,      // AFC Cup vt+0x30 (stage 0: re-bracket; stage 2: plain parse)
    // vt+0x10c: false (and team+0x50 cleared) for a club whose nation has a club registered with the
    // ACL outside its stages 0/1 (0x010a3f10): every nation once the ACL is converted.
    eligibilitySkip: 0x010a08d0,
    entryCode: 0xff,               // vt+0x390 0x010a0a30 returns 1 for codes outside 0-13; asi_c lists only ACL clubs
    rule: "secondary",
    excludeFieldOf: "AFC Champions League",
    holder: false,
    // AFC Cup places in FM's own allocation (ASI_SEEDING, table 0x023a1fc8, re-ranked each year by
    // 0x010a2a70): tags afcw/afce/awq2/awq1/aeq2/aeq1. Fallback: the nation ids with AFC Cup places in
    // the 2015 table (West 107 115 117 120 123 130 137 139 146, East 108 111 112 113 125 126 127 134 145).
    memberTags: [0x61666377, 0x61666365, 0x61777132, 0x61777131, 0x61657132, 0x61657131],
    memberIds: [107, 115, 117, 120, 123, 130, 137, 139, 146, 108, 111, 112, 113, 125, 126, 127, 134, 145],
    salt: 10,
  },
];
const formatByName = new Map(FORMATS.map((f) => [f.name, f]));
// Only formats whose hooks are all installed (and whose pair partner is too) are active; every hook
// looks the competition up here, so an inactive format leaves its competition vanilla.
const activeByVt = new Map();
const formatOf = (act) => { try { return act.isNull() ? null : activeByVt.get(act.readPointer().toString()) || null; } catch (e) { return null; } };
const step = (f, what) => log(`${f.name}: about to ${what}`);

// Converted = a cup stage sits at the knockout slot and every earlier slot is empty. Read from the
// ACT's stage vector, which is saved, so it survives a reload and a fallback season stays vanilla.
function converted(act, f) {
  const stages = readVec(act.add(0x4c), 64);
  if (stages.length <= f.koIndex || stages[f.koIndex].isNull() || !isCupStage(stages[f.koIndex])) return false;
  for (let i = 0; i < f.koIndex; i++) if (!stages[i].isNull() && !isDeadStage(stages[i])) return false;
  // koIndex 0 (Sudamericana): the vanilla stage sits in the same slot; FM's fixed field size tells them apart.
  if (f.vanillaEntrants && stages[f.koIndex].add(0x40).readS16() === f.vanillaEntrants) return false;
  return true;
}

// COMP@DB by id (0x01494420, thiscall on [[0x02428ee0]+0x18], ret 4; as at 0x010dacef) and its ACT.
const COMP_BY_ID = tc(0x01494420, "pointer", ["int"]);
const STAGE_NAME = COMP_BY_ID;                // the same id lookup on the stage-name table [[WORLD]+0x54]
function actOfFormat(f) {
  try {
    const comp = COMP_BY_ID(WORLD.readPointer().add(0x18).readPointer(), f.compId);
    if (comp.isNull()) return null;
    const act = comp.add(0x68).readPointer();
    return !act.isNull() && act.readPointer().equals(va(f.vt)) ? act : null;
  } catch (e) { return null; }
}

// --- NATION STRENGTH: each confederation's nation strengths compressed toward the median -------
// nation+0x20c (s16, 5..190) is the nation's "continental strength" (reports/parity/reputation.md,
// League reputation and Nation strength readers). Once a year per confederation FM moves it by its
// coefficient rank (0x00fd8860, +-2/4/6) and then sets every league's reputation from it
// (0x00fd8af0: top league = s, lower divisions keep their share), then re-ranks the competitions
// (0x00fd8db0). Hooked at the entry of 0x00fd8af0 (stdcall, continent; its only caller is
// 0x00fd8860), so FM's own step has run and FM's rescale and ranking then use our values. Rule:
// target = median strength of the confederation's nations (nation+0xdc == continent, s > 0, the set
// 0x00fd8860 and 0x00fd8af0 walk); d = target - s; |d| <= 2 no change, else
// s' = s + sign(d) * max(1, round(K * |d|)), clamped 5..190. An order guard then holds nations back
// so that every strict inequality stays strict and ties stay tied (no swaps): ordering readers
// (FM's next rank step, 0x00efcf00, 0x00f19d00) see smaller gaps only. Everything is computed
// first and written only when the whole result checks out, so an error leaves FM's values as they are.
const STRENGTH_K = 0.05;                   // share of the distance to the median closed per year
const STRENGTH_MIN = 5, STRENGTH_MAX = 190; // FM's own clamp (0x00fd8860, 0x00fd8590)
const STRENGTH_DEAD_ZONE = 2;              // |target - s| at or below this: unchanged
const strengthDone = new Set();            // "<world key>|<continent>|<year>"; cleared by checkWorld()
const strengthLevel = (s) => Math.max(1, Math.floor(s / 10 + 0.5));   // FM's nation level (0x015ec7a0)

// League reputation COMP+0x80 (obfuscated s16; market_pool.md dec16).
function compReputation(comp) {
  const p = comp.add(0x80), k = p.and(0xf).toInt32(), raw = p.readU16();
  const rol = ((raw << k) | (raw >>> (16 - k))) & 0xffff;
  const u = ~(rol ^ 0xecf1) & 0xffff;
  const r = ~((u >>> 7) | (u << 9)) & 0xffff;
  return r > 32767 ? r - 65536 : r;
}
// The nation's top league (nation+0x1fc = its competition id, set by 0x00fd8590), or null.
function topLeagueOf(nation) {
  try {
    const id = nation.add(0x1fc).readS32();
    if (id < 0) return null;
    const comp = COMP_BY_ID(WORLD.readPointer().add(0x18).readPointer(), id);
    return comp.isNull() ? null : comp;
  } catch (e) { return null; }
}

// Every nation of the confederation with s > 0. FM walks the world's nation list (0x01534990 by
// index), but that call is unproven live; the seeding object's member list (as cacheRecords reads
// it every season) gives the same members by plain reads. No seeding object: no compression.
function confederationNations(continent) {
  const seeding = seedingOf(continent), out = [], seen = new Set();
  if (!seeding) return out;
  for (const info of readVec(seeding.add(4), 512)) {
    const nation = info.readPointer();
    if (nation.isNull() || seen.has(nation.toString()) || !nation.add(0xdc).readPointer().equals(continent)) continue;
    seen.add(nation.toString());
    const s = nation.add(0x20c).readS16();
    if (s > 0) out.push({ nation, s });
  }
  return out;
}

// The new strengths for one confederation: [{ nation, s, s2 }] (s2 === s where unchanged), plus the median.
function compressStrengths(list) {
  const sorted = list.map((x) => x.s).sort((a, b) => a - b), m = sorted.length;
  const target = m % 2 ? sorted[(m - 1) >> 1] : Math.round((sorted[m / 2 - 1] + sorted[m / 2]) / 2);
  const proposed = (s) => {
    const d = target - s;
    if (Math.abs(d) <= STRENGTH_DEAD_ZONE) return s;
    const step = Math.sign(d) * Math.max(1, Math.round(STRENGTH_K * Math.abs(d)));
    return Math.min(STRENGTH_MAX, Math.max(STRENGTH_MIN, s + step));
  };
  // Groups of equal old strength, strongest first; one value per group keeps ties tied.
  const values = [...new Set(list.map((x) => x.s))].sort((a, b) => b - a);
  const next = new Map(values.map((s) => [s, proposed(s)]));
  // Order guard. Nations above the target move down: from the group nearest the target upwards,
  // each stays at least one above the group below it. Nations below move up: from the group nearest
  // the target downwards, each stays at least one below the group above it. Movers are only held
  // back (between old and proposed), never pushed past their old value.
  for (let i = values.length - 1; i >= 0; i--) {
    const s = values[i], v = next.get(s);
    if (v < s && i + 1 < values.length) next.set(s, Math.min(s, Math.max(v, next.get(values[i + 1]) + 1)));
  }
  for (let i = 0; i < values.length; i++) {
    const s = values[i], v = next.get(s);
    if (v > s && i > 0) next.set(s, Math.max(s, Math.min(v, next.get(values[i - 1]) - 1)));
  }
  for (let i = 0; i + 1 < values.length; i++) {
    if (!(next.get(values[i]) > next.get(values[i + 1]))) throw new Error(`order guard failed at ${values[i]}/${values[i + 1]}`);
  }
  return { target, out: list.map((x) => ({ nation: x.nation, s: x.s, s2: next.get(x.s) })) };
}

function strengthFlags(a, b) {
  const f = [];
  for (const t of [100, 160]) if ((a < t) !== (b < t)) f.push(`crosses ${t}`);
  const la = strengthLevel(a), lb = strengthLevel(b);
  for (const t of [12, 7]) if ((la < t) !== (lb < t)) f.push(`crosses level ${t}`);
  return f.length ? ` [${f.join(", ")}]` : "";
}

function installStrength() {
  log("about to attach the nation strength hook 0x00fd8af0");
  Interceptor.attach(va(0x00fd8af0), {
    onEnter(args) {
      this.watch = null;
      try {
        checkWorld();
        const continent = args[0], year = TODAY.add(2).readU16();
        const key = `${cacheWorld}|${continent}|${year}`;
        if (strengthDone.has(key)) { log(`strength: ${continent} ${year} already compressed this year, skipped`); return; }
        strengthDone.add(key);
        const list = confederationNations(continent);
        if (list.length < 2) { log(`strength: ${continent} ${year} ${list.length} nation(s), nothing to do`); return; }
        const { target, out } = compressStrengths(list);
        const changed = out.filter((x) => x.s2 !== x.s);
        // Everything is computed; now write (plain s16, as FM stores it).
        for (const x of changed) x.nation.add(0x20c).writeS16(x.s2);
        log(`strength: confederation ${continent} ${year}: ${list.length} nations, median ${target}, K ${STRENGTH_K}, ${changed.length} changed`);
        for (const x of changed.sort((a, b) => b.s - a.s)) {
          log(`strength: ${x.nation.add(8).readS32()} ${nationName(x.nation)} s ${x.s} -> ${x.s2}, level ${strengthLevel(x.s)} -> ${strengthLevel(x.s2)}${strengthFlags(x.s, x.s2)}`);
        }
        // The 5 strongest nations' top leagues, for the before/after line once FM has rescaled.
        this.watch = out.sort((a, b) => b.s2 - a.s2).slice(0, 5).map((x) => {
          const comp = topLeagueOf(x.nation);
          return { nation: x.nation, comp, before: comp ? compReputation(comp) : null };
        });
      } catch (e) { log("strength compression error (FM values left as they were) " + e.stack); }
    },
    onLeave() {
      try {
        if (!this.watch) return;
        log("strength: top leagues after FM's rescale: " + this.watch.map((w) =>
          `${nationName(w.nation)} ${w.comp ? `${w.before} -> ${compReputation(w.comp)}` : "no league"}`).join("; "));
      } catch (e) { log("strength report error " + e.stack); }
    },
  });
}

// --- Hook installation (after the log file is open, so every step is logged) ------------------

function installFormats() {
  if (!FORMAT_ENABLED) { log("format change off (FORMAT_ENABLED false)"); return; }
  try {
    log("about to attach the knockout rules hook 0x0103e360");
    Interceptor.attach(va(0x0103e360), { onEnter() { try { knockoutRules(this.context.ecx); } catch (e) { log("knockout rules error " + e.stack); } } });
    log("about to replace the data-stage creator 0x00fb4c00");
    Interceptor.replace(va(0x00fb4c00), createCallback);
  } catch (e) { log("format hooks not installed, every competition stays vanilla: " + e.stack); return; }
  const settingsHooked = new Set();
  for (const f of FORMATS) {
    if (!f.enabled) { log(`${f.name}: format disabled in FORMATS, vanilla`); continue; }
    try {
      if (f.entryOnly) { installEntryOnly(f); continue; }
      installFormat(f, settingsHooked);
      f.installed = true;
    } catch (e) { log(`${f.name}: hook installation failed, competition stays vanilla: ${e.stack}`); }
  }
  for (const f of FORMATS) {
    if (!f.installed) continue;
    const partner = f.pair ? formatByName.get(f.pair) : null;
    if (f.pair && !(partner && partner.installed)) {
      log(`${f.name}: partner ${f.pair} is not converted, so this one stays vanilla too (they must change together)`);
      continue;
    }
    activeByVt.set(va(f.vt).toString(), f);
  }
  log(`format change active for: ${FORMATS.filter((f) => activeByVt.has(va(f.vt).toString())).map((f) => f.name).join(", ") || "none"}`);
}

function installFormat(f, settingsHooked) {
  // P1. Replace the stage builder (or the whole season init). On any refusal or error the original
  // runs (vanilla season).
  if (f.initReplace) installInit(f);
  else installBuilder(f);

  // P1b. Builders and hand-offs that must do nothing once the competition is converted.
  f.skipCallbacks = [];
  for (const addr of (f.skipBuilders || []).concat(f.skipWhenConverted || [])) {
    step(f, `replace 0x${addr.toString(16)} (skipped once converted)`);
    const orig = new NativeFunction(va(addr), "void", ["pointer"], "thiscall");
    const cb = new NativeCallback(function (act) {
      let skip = false;
      try { skip = formatOf(act) === f && converted(act, f); } catch (e) { log(`${f.name}: skip check error at 0x${addr.toString(16)}: ${e.stack}`); }
      if (skip) { log(`${f.name}: 0x${addr.toString(16)} skipped (converted)`); return; }
      orig(act);
    }, "void", ["pointer"], "thiscall");
    f.skipCallbacks.push(cb);
    Interceptor.replace(va(addr), cb);
  }

  // P2. Merge rounds at settings load (one listener per address, dispatched by the ACT's class).
  // Formats without one (Sudamericana: rounds built in code, enough of them) keep FM's settings.
  if (f.settingsLoad && !settingsHooked.has(f.settingsLoad)) {
    settingsHooked.add(f.settingsLoad);
    step(f, `attach the settings hook 0x${f.settingsLoad.toString(16)}`);
    Interceptor.attach(va(f.settingsLoad), {
      onEnter(args) { this.act = this.context.ecx; this.idx = args[0].toInt32() & 0xff; },
      onLeave(ret) {
        try {
          if (ret.isNull()) return;
          const g = formatOf(this.act);
          if (!g || g.settingsLoad !== f.settingsLoad || this.idx !== g.koIndex || !converted(this.act, g)) return;
          mergeRounds(this.act, g, ret);
        } catch (e) { log("round merge error " + e.stack); }
      },
    });
  }

  // Class eligibility check (vt+0x10c) answered "yes" for a converted competition.
  if (f.eligibilitySkip) {
    step(f, `replace the eligibility check 0x${f.eligibilitySkip.toString(16)}`);
    const orig = new NativeFunction(va(f.eligibilitySkip), "uint8", ["pointer", "pointer", "int"], "thiscall");
    f.eligibilityCallback = new NativeCallback(function (act, team, x) {
      try { if (formatOf(act) === f && converted(act, f)) return 1; } catch (e) { log(`${f.name}: eligibility check error ${e.stack}`); }
      return orig(act, team, x);
    }, "uint8", ["pointer", "pointer", "int"], "thiscall");
    Interceptor.replace(va(f.eligibilitySkip), f.eligibilityCallback);
  }

  installPreDraw(f);
}

// Season inits replaced whole (initReplace), one replacement per address: the shared base
// 0x00fb3230 runs for every competition and only builds for the format that names it.
const initHooks = new Map();
function installInit(f) {
  const addr = f.initReplace;
  if (initHooks.has(addr)) return;
  step(f, `replace the season init 0x${addr.toString(16)}`);
  const original = new NativeFunction(va(addr), "void", ["pointer", "int"], "thiscall");
  const cb = new NativeCallback(function (act, arg) {
    let g = null, done = false;
    try {
      g = formatOf(act);
      if (g && g.initReplace === addr) done = initKnockout(act, g);
      else g = null;
    } catch (e) {
      try { done = !!g && converted(act, g); } catch (e2) {}
      log(`${g ? g.name : "season init"}: build error${done ? " after the stage was built" : ", vanilla start"}: ${e.stack}`);
      if (done) try { step(g, "mark the competition running (0x00fc04f0, -2)"); SET_STATUS(act, -2); } catch (e3) {}
    }
    if (!done) {
      if (g) {
        try {
          const p = g.pair && formatByName.get(g.pair), pact = p && actOfFormat(p);
          if (pact && pact.add(0x64).readU16() === act.add(0x64).readU16() && converted(pact, p))
            log(`${g.name}: WARNING pair split: ${g.pair} is already converted this season but ${g.name} starts vanilla (CHECK: stalls or hand-off errors)`);
        } catch (e) {}
        step(g, "run the vanilla season init");
      }
      original(act, arg);
    }
  }, "void", ["pointer", "int"], "thiscall");
  initHooks.set(addr, { original, cb });
  Interceptor.replace(va(addr), cb);
}
function initKnockout(act, f) {
  if (converted(act, f)) { log(`${f.name}: season init called with the knockout stage already built, nothing done`); return true; }
  if (!buildKnockout(act, f)) return false;
  step(f, "mark the competition running (0x00fc04f0, -2)");
  SET_STATUS(act, -2);
  return true;
}

function installBuilder(f) {
  step(f, `replace the stage builder 0x${f.stageBuilder.toString(16)}`);
  const original = new NativeFunction(va(f.stageBuilder), "void", ["pointer"], "thiscall");
  f.callback = new NativeCallback(function (act) {
    let done = false;
    try {
      if (formatOf(act) === f) done = buildKnockout(act, f);
    } catch (e) {
      try { done = converted(act, f); } catch (e2) {}            // never add a vanilla stage next to a built stage
      log(`${f.name}: build error${done ? " after the stage was built" : ", vanilla start"}: ${e.stack}`);
    }
    if (!done) {
      try {
        const p = f.pair && formatByName.get(f.pair), pact = p && actOfFormat(p);
        if (pact && pact.add(0x64).readU16() === act.add(0x64).readU16() && converted(pact, p))
          log(`${f.name}: WARNING pair split: ${f.pair} is already converted this season but ${f.name} starts vanilla (CHECK: stalls or hand-off errors)`);
      } catch (e) {}
      step(f, "run the vanilla builder");
      original(act);
    }
  }, "void", ["pointer"], "thiscall");
  Interceptor.replace(va(f.stageBuilder), f.callback);
}

// P5. Pre-draw hooks.
function installPreDraw(f) {
  if (f.preDrawNullRound) {
    step(f, `attach the pre-draw hook 0x${f.preDrawNullRound.toString(16)}`);
    Interceptor.attach(va(f.preDrawNullRound), {
      onEnter(args) {
        try {
          const act = this.context.ecx;
          if (formatOf(act) === f && converted(act, f)) args[1] = NULL;     // it tests the round first and returns
        } catch (e) { log("pre-draw hook error " + e.stack); }
      },
    });
  }
  if (f.preDrawSkip) {
    step(f, `replace the pre-draw body 0x${f.preDrawSkip.toString(16)}`);
    const orig = new NativeFunction(va(f.preDrawSkip), "void", ["pointer", "pointer", "pointer"], "thiscall");
    f.preDrawCallback = new NativeCallback(function (act, stage, round) {
      let skip = false;
      try { skip = formatOf(act) === f && converted(act, f); } catch (e) { log("pre-draw skip error " + e.stack); }
      if (skip) return;                                                     // as the base vt+0x29c 0x004422e0 (ret 8)
      orig(act, stage, round);
    }, "void", ["pointer", "pointer", "pointer"], "thiscall");
    Interceptor.replace(va(f.preDrawSkip), f.preDrawCallback);
  }
}

// Entry-only competitions whose entry cannot be changed safely: log the reason and the vanilla init.
function installEntryOnly(f) {
  log(`${f.name}: entry change not implemented, vanilla format and entry kept (${f.reason || "see continental_build.md"})`);
  if (!f.observe) return;
  step(f, `attach the observation hook 0x${f.observe.toString(16)}`);
  Interceptor.attach(va(f.observe), {
    onEnter() {
      try {
        const act = this.context.ecx;
        if (act.readPointer().equals(va(f.vt))) log(`${f.name}: vanilla init with ${readVec(act.add(0x14c), 1024).length} places (entry unchanged)`);
      } catch (e) { log(`${f.name}: observation error ${e.stack}`); }
    },
  });
}

// --- Building the knockout stage ---------------------------------------------------------------

function buildKnockout(act, f) {
  const comp = act.add(0x3c).readPointer();
  const year = act.add(0x64).readU16();
  if (!partnerAllows(act, f, year)) return false;
  let exclude = null;
  if (f.rule === "secondary") {
    exclude = primaryField(f, year);
    if (!exclude) return false;
  }
  const teams = chooseEntrants(act, comp, f, { year, exclude });
  if (teams.length < 2 || teams.length > f.capacity) {
    log(`${f.name}: ${teams.length} entrants, outside 2..${f.capacity}: vanilla start`);
    return false;
  }
  shuffle(teams);
  // Byes go to the last entries (each round takes its new entrants in table order, CUP_ROUND+0x22),
  // so the league champions go last: a random subset of them when there are fewer byes, random
  // other clubs fill any byes left over.
  if (teams.champions && teams.champions.size) {
    const isChamp = (t) => { const c = clubOfTeam(t); return !!c && teams.champions.has(c.toString()); };
    const ordered = teams.filter((t) => !isChamp(t)).concat(teams.filter(isChamp));
    teams.splice(0, teams.length, ...ordered);
    const P = 1 << Math.floor(Math.log2(teams.length)), byes = teams.length === P ? 0 : 2 * P - teams.length;
    log(`${f.name}: ${teams.filter(isChamp).length} champions placed last for the ${byes} byes: ${teams.slice(teams.length - byes).map(teamName).join(", ")}`);
  }
  const saved = [];
  const v = agentVec(teams);
  let inserted = false;
  try {
    step(f, `mark ${teams.length} entrants`);
    teams.forEach((t) => saved.push(markEntrant(t, comp, f.entryCode)));
    step(f, "allocate and construct the knockout stage");
    const stage = OPERATOR_NEW(0x48);
    if (stage.isNull()) throw new Error("operator new failed");
    STAGE_BASE_CTOR(stage, f.koIndex, NULL);
    stage.writePointer(CUP_STAGE_VT);
    for (const off of [0x38, 0x3c, 0x44]) stage.add(off).writePointer(NULL);
    step(f, "fill the stage entrants (0x0103ebb0)");
    CUP_ENTRANTS(stage, v.vec, NULL, 0, 0);
    step(f, `insert and set up stage ${f.koIndex} (0x00fa0e60)`);
    inserted = (STAGE_INSERT(act, stage, 0) & 0xff) === 1;    // on failure the game deletes or ignores the stage
    if (!inserted) throw new Error("stage insert/setup failed");
  } catch (e) {
    if (inserted) throw e;
    restoreMarks(saved);
    log(`${f.name}: ${e.message}, vanilla start`);
    return false;
  }
  // From here the stage exists: never fall back to the vanilla builder (it would add stage 0).
  // FM only finishes a competition (and restarts it next season) when no stage slot is NULL
  // (vt+0x330 0x00fb2150), so the slots before the knockout get dead stages, as FM itself does for
  // unused slots (0x0117e1e1, 0x010a05e7). Their type 6 counts as absent and they never finish.
  try { fillDeadSlots(act, f); } catch (e) { log(`${f.name}: dead stage error ${e.stack}`); }
  try {
    // FM finishes a competition only with at least byte ACT+0xf8 stage slots (vt+0x330 0x00fb2150).
    const slots = readVec(act.add(0x4c), 64).length, need = act.add(0xf8).readU8();
    if (slots < need) log(`${f.name}: WARNING ${slots} stage slots, ACT+0xf8 asks for ${need} (CHECK: the competition may not finish)`);
  } catch (e) {}
  if (f.register === false) log(`${f.name}: no season-object registration (the vanilla init has none)`);
  else try { step(f, "register the entrants with the season object"); registerWithSeason(act, comp, v.vec, f.register); } catch (e) { log(`${f.name}: season registration error ${e.stack}`); }
  try { step(f, "clear the markers of vanilla qualifiers left out"); clearVanillaQualifiers(act, comp, teams); } catch (e) { log(`${f.name}: marker cleanup error ${e.stack}`); }
  try { deactivateDirectPlaces(act, f); } catch (e) { log(`${f.name}: place deactivation error ${e.stack}`); }
  log(`${f.name}: knockout stage ${f.koIndex} built with ${teams.length} entrants: ${teams.map(teamName).join(", ")}`);
  return true;
}

function fillDeadSlots(act, f) {
  const stages = readVec(act.add(0x4c), 64);
  let n = 0;
  for (let i = 0; i < f.koIndex; i++) {
    if (i < stages.length && !stages[i].isNull()) continue;
    step(f, `insert dead stage ${i}`);
    const d = OPERATOR_NEW(0x3c);
    if (d.isNull()) throw new Error("operator new failed");
    STAGE_BASE_CTOR(d, i, NULL);
    d.writePointer(DEAD_STAGE_VT);
    d.add(0x38).writePointer(NULL);
    if ((STAGE_INSERT(act, d, 0) & 0xff) !== 1) log(`${f.name}: dead stage ${i} insert returned 0`);
    n++;
  }
  log(`${f.name}: ${n} dead stage(s) filled before the knockout stage`);
}

// Pairs (CL and EL) change together: refuse if the partner already runs vanilla this season.
function partnerAllows(act, f, year) {
  if (!f.pair) return true;
  const p = formatByName.get(f.pair), pact = p && actOfFormat(p);
  if (!pact) { log(`${f.name}: partner ${f.pair} not found, vanilla start`); return false; }
  const stages = readVec(pact.add(0x4c), 64).filter((s) => !s.isNull());
  // GUESS: ACT+0x64 is the season year of both and the stage vector is rebuilt at each season start.
  if (pact.add(0x64).readU16() === year && stages.length && !converted(pact, p)) {
    log(`${f.name}: ${f.pair} already runs vanilla this season, vanilla start (they must change together)`);
    return false;
  }
  return true;
}

// The field of the competition named in f.excludeFieldOf, as a Set of club pointers: its built stage
// if it already started this season, otherwise recomputed with its own rules (the reputation picks
// are seeded, so the recomputation gives the clubs its builder will choose). null = refuse.
function primaryField(f, year) {
  const p = formatByName.get(f.excludeFieldOf), pact = p && actOfFormat(p);
  if (!pact || formatOf(pact) !== p) { log(`${f.name}: ${f.excludeFieldOf} not found or not converted, vanilla start`); return null; }
  const stages = readVec(pact.add(0x4c), 64);
  let teams, how;
  if (pact.add(0x64).readU16() === year && converted(pact, p)) {
    teams = stageTeams(stages[p.koIndex]);
    how = "its stage";
  } else if (pact.add(0x64).readU16() === year && stages.some((s) => !s.isNull())) {
    log(`${f.name}: ${f.excludeFieldOf} runs vanilla this season, vanilla start`);
    return null;
  } else {
    step(f, `recompute the ${f.excludeFieldOf} field`);
    teams = chooseEntrants(pact, pact.add(0x3c).readPointer(), p, { year, quiet: true });
    how = "recomputed";
  }
  const clubs = new Set();
  for (const t of teams) { const c = clubOfTeam(t); if (c) clubs.add(c.toString()); }
  log(`${f.name}: ${clubs.size} clubs of the ${f.excludeFieldOf} field excluded (${how})`);
  return clubs;
}

// Bookkeeping per entrant, as every vanilla init does (continental_format.md 1.1).
function markEntrant(team, comp, code) {
  const ext = team.add(0x54).readPointer();
  const s = { team, ext, c50: team.add(0x50).readPointer(), c6b: team.add(0x6b).readU8(),
              x7c: ext.isNull() ? null : ext.add(0x7c).readPointer(), xa6: ext.isNull() ? 0 : ext.add(0xa6).readU8() };
  team.add(0x50).writePointer(comp);
  team.add(0x6b).writeU8(code);
  if (!ext.isNull()) { ext.add(0x7c).writePointer(NULL); ext.add(0xa6).writeU8(0); }
  return s;
}
function restoreMarks(saved) {
  for (const s of saved) {
    s.team.add(0x50).writePointer(s.c50);
    s.team.add(0x6b).writeU8(s.c6b);
    if (!s.ext.isNull()) { s.ext.add(0x7c).writePointer(s.x7c); s.ext.add(0xa6).writeU8(s.xa6); }
  }
}
// Register the entrants with the competition's season object ACT+0x6c, created the vanilla way
// ([[0x024257fc]+4]->vt+0x24(COMP, 1, -1)) if missing; then 0x00f9cbb0 as at 0x01156756.
function registerWithSeason(act, comp, vec, values) {
  let season = act.add(0x6c).readPointer();
  if (season.isNull()) {
    const mgr = COMP_MANAGER.readPointer().add(4).readPointer();
    season = new NativeFunction(mgr.readPointer().add(0x24).readPointer(), "pointer", ["pointer", "pointer", "int", "int"], "thiscall")(mgr, comp, 1, -1);
    act.add(0x6c).writePointer(season);
  }
  const [a, b, c] = Array.isArray(values) ? values : [-1, -1, -1];   // as the class's vanilla init passes them
  if (!season.isNull()) REGISTER_TEAMS(act, vec, a, b, c, NULL, season, 0, -1);
}
// GUESS (check C12): vanilla qualifiers left out keep "qualified for COMP" ([team+0x54]+0x7c) and
// may have team+0x50 = COMP; clear both so the board and UI don't count on the competition.
function clearVanillaQualifiers(act, comp, chosen) {
  const keep = new Set(chosen.map((t) => t.toString()));
  let cleared = 0;
  for (const e of readVec(act.add(0x14c), 1024)) {
    try {
      const team = e.readPointer();
      if (team.isNull() || keep.has(team.toString())) continue;
      const ext = team.add(0x54).readPointer();
      if (!ext.isNull() && ext.add(0x7c).readPointer().equals(comp)) { ext.add(0x7c).writePointer(NULL); ext.add(0xa6).writeU8(0); cleared++; }
      if (team.add(0x50).readPointer().equals(comp)) team.add(0x50).writePointer(NULL);
    } catch (e2) {}
  }
  if (cleared) log(`cleared the "qualified" marker of ${cleared} vanilla qualifiers left out`);
}
// GUESS: the CL vt+0x10 (0x010d3821..0x010d38ea) marks and registers every active code-0 place
// after the builders return; clearing the active byte +5 of those places makes it skip them.
function deactivateDirectPlaces(act, f) {
  if (!f.deactivateCodes) return;
  const places = readVec(act.add(0x14c), 1024).filter((e) => e.add(5).readU8() !== 0 && f.deactivateCodes.includes(e.add(6).readU8()));
  if (!places.length) return;
  step(f, `deactivate ${places.length} vanilla places with codes ${f.deactivateCodes.join("/")}`);
  for (const e of places) e.add(5).writeU8(0);
}
function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); const t = a[i]; a[i] = a[j]; a[j] = t; }
}

// --- Entry rules ------------------------------------------------------------------------------

// opts: year (season), exclude (Set of club pointers not eligible), quiet (no per-nation lines).
function chooseEntrants(act, comp, f, opts) {
  const all = allClubs();
  const m = memberNations(comp, { guests: f.guests }, all);
  const year = opts.year;
  const say = opts.quiet ? () => {} : log;
  if (!opts.quiet) dumpVanillaPlaces(act);
  if (f.memberTags) m.list = tagMembers(m, f, say);
  const ctx = { all, seeding: m.seeding, year, f, say, exclude: opts.exclude || new Set(), champions: new Set() };
  const chosen = [], clubs = new Set();
  const add = (t) => {
    const c = t && clubOfTeam(t);
    if (!c || clubs.has(c.toString()) || ctx.exclude.has(c.toString())) return false;
    clubs.add(c.toString());
    chosen.push(t);
    return true;
  };
  for (const n of m.list) {
    let places = [];
    try {
      if (f.rule === "secondary") places = secondaryQualifiers(n, ctx);
      else places = nationPlaces(n, ctx);
    } catch (e) { log(`entry: ${f.name} ${nationName(n)} error ${e.stack}`); }
    places.forEach(add);
  }
  if (f.holder) {
    const h = history(comp).winner;
    say(`entry: ${f.name} title holder ${h ? teamName(h) : "unknown"}${h && !add(h) ? " (already qualified)" : ""}`);
  }
  say(`entry: ${f.name} ${m.list.length} member nations (seeding list ${m.seeding ? "yes" : "no"}), season ${year}, ${chosen.length} entrants`);
  chosen.champions = ctx.champions;                 // club pointers of the league champions (byes)
  return chosen;
}

// Membership of a secondary cup with its own member list (AFC Cup): the confederation members whose
// NATION_CONT_INFO (seeding +4..+8) carries any of f.memberTags > 0. The tags are FM's allocation
// (0x010a2fd0 writes them into info+0x10 from the table at 0x023a1fc8; the AFC Cup getter
// 0x0109fc00 reads the places they produce). Entries: {+0 tag, +4 value object}; the value comes
// from the object's vt+0x14, as 0x010a0bc0 reads ACT tags. Fallback: the static ids f.memberIds.
function seedingTag(info, tag) {
  for (const e of readVec(info.add(0x10), 512)) {
    if (e.isNull() || e.readU32() !== tag) continue;
    const obj = e.add(4), vt = obj.readPointer();
    if (vt.isNull()) return 0;
    return (vfnOf(vt.add(0x14).readPointer(), "int", ["pointer"])(obj) << 24) >> 24;
  }
  return null;
}
function tagMembers(m, f, say) {
  const keep = new Set();
  let read = 0;
  if (m.seeding) {
    const infos = readVec(m.seeding.add(4), 512);
    step(f, `read the allocation tags of ${infos.length} nations`);
    for (const info of infos) {
      try {
        const n = info.readPointer();
        if (n.isNull()) continue;
        const vals = f.memberTags.map((t) => seedingTag(info, t));
        if (vals.some((v) => v !== null)) read++;
        if (vals.some((v) => v !== null && v > 0)) keep.add(n.toString());
      } catch (e) {}
    }
  }
  let how = `allocation tags (${read} nations with tags)`;
  if (!keep.size) {
    how = "the static 2015 ids (no tag found: CHECK)";
    for (const n of m.list) if (f.memberIds.includes(n.add(8).readS32())) keep.add(n.toString());
  }
  const list = m.list.filter((n) => keep.has(n.toString()));
  say(`entry: ${f.name} membership from ${how}: ${list.length} of ${m.list.length} confederation members: ${list.map(nationName).join(", ")}`);
  return list;
}

// C1: what FM itself qualified (ACT+0x14c: +0 TEAM, +5 active, +6 entry code).
function dumpVanillaPlaces(act) {
  try {
    const e = readVec(act.add(0x14c), 1024).map((p) => `${teamName(p.readPointer())}/${p.add(5).readU8()}/${p.add(6).readU8()}`);
    log(`vanilla places (${e.length}): ${e.join(", ")}`);
  } catch (err) { log("vanilla places unreadable " + err); }
}

// Shared per-nation facts for both rules.
function nationFacts(n, ctx) {
  let pyramid = ctx.all.byLeagueNation.get(n.toString()) || [];
  let inNation = (t) => { const c = t && clubOfTeam(t); return !!c && ctx.all.clubNation.get(c.toString()) === n.toString(); };
  let topLevel = 0;
  if (!pyramid.length && ctx.f && ctx.f.basedFallback && (ctx.all.byBased.get(n.toString()) || []).length) {
    // No league of its own (Canada): the clubs based there, at their highest level abroad.
    pyramid = ctx.all.byBased.get(n.toString());
    topLevel = Math.min(...pyramid.map((c) => c.level));
    const based = new Set(pyramid.map((c) => c.club.toString()));
    inNation = (t) => { const c = t && clubOfTeam(t); return !!c && based.has(c.toString()); };
  }
  const top = pyramid.filter((c) => c.level === topLevel);
  const id = n.add(8).readS32();
  const topClubs = new Set(top.map((c) => c.club.toString()));
  const inTop = (t) => { const c = t && clubOfTeam(t); return !!c && topClubs.has(c.toString()); };
  const free = (t) => { const c = t && clubOfTeam(t); return !!c && !ctx.exclude.has(c.toString()); };
  return { pyramid, top, id, name: `${nationName(n)} (id ${id})`, inNation, inTop, free,
           unloaded: !top.some((c) => !c.fin.isNull()) };        // no detailed top-division club
}

// Primary rule: the two places of one member nation.
function nationPlaces(n, ctx) {
  const f = ctx.f, x = nationFacts(n, ctx), say = ctx.say;
  if (x.unloaded) {
    const picks = reputationPick(x.top.length ? x.top : x.pyramid, 2, pickSeed(ctx.year, x.id, f.salt));
    say(`entry: ${f.name} ${x.name} unloaded, reputation pick from ${x.top.length || x.pyramid.length} clubs: ${picks.map(teamName).join(", ")}`);
    markChampion(ctx, picks.slice().sort((a, b) => reputation(b) - reputation(a))[0]);   // stand-in champion
    return picks;
  }
  const rec = seasonRecord(ctx.seeding, n, ctx.year);
  const comps = nationalComps(n);
  const league = comps.league ? history(comps.league) : {};
  const cup = comps.cup ? history(comps.cup) : {};
  const recLeague = rec ? rec.league.map(toTeam).filter(x.inNation) : [];
  const recCup = rec ? rec.cup.map(toTeam).filter(x.inNation) : [];
  say(`entry: ${f.name} ${x.name} record ${rec ? `year ${rec.year} idx ${rec.idx} flags ${rec.flags} league [${recLeague.slice(0, 4).map(teamName).join(", ")}] cup [${recCup.map(teamName).join(", ")}]` : "none"}; ` +
      `league ${comps.league ? compName(comps.league) : "-"} history ${league.winner ? teamName(league.winner) : "-"}/${league.runnerUp ? teamName(league.runnerUp) : "-"}; ` +
      `cup ${comps.cup ? compName(comps.cup) : "-"} history ${cup.winner ? teamName(cup.winner) : "-"}/${cup.runnerUp ? teamName(cup.runnerUp) : "-"}`);

  if (isSplit(n, f)) {
    // GUESS: FM's qualifier order (vt+0x33c override) lists the two split champions first, then the
    // best other club of the aggregate table, which is the rule when one club won both splits.
    const order = distinct(recLeague.concat([league.winner, league.runnerUp].filter(x.inNation)));
    say(`entry: ${f.name} ${x.name} split season -> ${order.slice(0, 2).map(teamName).join(", ")}`);
    markChampion(ctx, order[0]);
    return order.slice(0, 2);
  }
  const champion = [league.winner, recLeague[0]].find(x.inNation) || null;
  let second = null, why = "";
  if (comps.cup) {
    const pair = recCup.length ? recCup : [cup.winner, cup.runnerUp].filter(x.inNation);
    second = pair.find((t) => !sameClub(t, champion)) || null;
    why = second && pair[0] && sameClub(pair[0], champion) ? "losing cup finalist" : "cup winner";
  }
  if (!second) {
    second = [league.runnerUp].concat(recLeague).find((t) => x.inNation(t) && !sameClub(t, champion)) || null;
    why = comps.cup ? "league runner-up (no cup result found)" : "league runner-up (no cup)";
  }
  say(`entry: ${f.name} ${x.name} champion ${champion ? teamName(champion) : "-"}, ${why} ${second ? teamName(second) : "-"}`);
  const out = [champion, second].filter((t) => t);
  if (out.length < 2) {
    // No league/cup result found (e.g. the Gulf nations in AFC 2014): fill from the seeded
    // reputation pick, as for unloaded nations.
    const pool = (x.top.length ? x.top : x.pyramid).filter((c) => !out.some((t) => sameClub(t, c.team)));
    const picks = reputationPick(pool, 2 - out.length, pickSeed(ctx.year, x.id, f.salt));
    say(`entry: ${f.name} ${x.name} no result for ${2 - out.length} place(s), reputation pick from ${pool.length} clubs: ${picks.map(teamName).join(", ")}`);
    out.push(...picks);
  }
  markChampion(ctx, champion || out.slice().sort((a, b) => reputation(b) - reputation(a))[0]);
  return out;
}

// ===== Secondary rule: secondaryQualifiers(nation, ctx) ==========================================
// The clubs of a nation for a secondary competition (EL, Sudamericana, CAF CC, AFC Cup): the
// SECONDARY_PLACES best-placed top-division clubs not already in the primary competition, by the
// season record's league order (rec+0x1c; GUESS C2: some leagues' vt+0x33c return qualifier order
// rather than the plain table), then the league's history winner and runner-up. Unloaded nations,
// and places no listed club can fill, get the seeded reputation-weighted pick from the free
// top-division clubs. (A 2nd-7th play-off decided the place until 2031: its finals could not be
// held before the June build, reports/parity/playoff_dates.md.)
// ctx: { all (allClubs()), seeding, year, f (FORMATS entry), say (log), exclude (Set of club
// pointers already in the primary competition) }. Returns TEAM* (first teams).
const SECONDARY_PLACES = 2;
// The final table of a nation's top division (row i = position i). The season record
// (seasonRecord) was never found live ("record none" every season), which left only the history's
// winner and runner-up. FM resets a league's tables for the new season soon after it finishes,
// before the 16 June EL build for most leagues (probe, 30 June 2015), so the table is captured when
// FM finishes the league (0x00fad710, held in memory only); a save loaded in between falls back to
// the league's own finished stages if they are still there (Spain, Netherlands), then to the
// history.
const finalTables = new Map();               // nation -> { teams, day }
function leagueStagesTable(act) {            // the finished league stage with the most rows, as parity_agent.js tableFromStages
  let best = [];
  for (const st of readVec(act.add(0x4c), 64)) {
    try {
      if (st.isNull() || isDeadStage(st)) continue;
      if (vcall(st, 0xc4, "uint8") !== 1) continue;
      if (st.add(0x10).readU8() === 0 && st.add(0x82).readU8() === 0) continue;   // not finished (0x010182d0)
      const k = st.add(0x44).readS8(), rows = st.add(0x38).readPointer(), out = [];
      for (let i = 0; i < k; i++) { const t = rows.add(4 * i).readPointer().add(0x30).readPointer(); if (!t.isNull()) out.push(t); }
      if (out.length > best.length) best = out;
    } catch (e) {}
  }
  return best;
}
function topLeagueNation(act) {              // the nation when act is a domestic top-division league ACT
  if (act.isNull() || ![0, 1, 14].includes(act.add(0x85).readU8())) return null;
  const comp = act.add(0x3c).readPointer();
  if (comp.isNull() || comp.add(0xdd).readS8() !== 0 || !comp.add(0x68).readPointer().equals(act)) return null;
  const n = comp.add(0x44).readPointer();
  return n.isNull() ? null : n;
}
// Every pointer in the caches belongs to the world they were read from. A new career or a loaded
// save in the same FM session builds a new world, so they are dropped when the world's first club
// moves or the date goes backwards (a new career started in 2014 after a 2015 save kept 2015
// captures that looked fresh, live 2014-07).
let cacheWorld = null, cacheDay = 0;
function checkWorld() {
  const world = WORLD.readPointer(), d = dayNumber();
  const key = world.isNull() ? "none" : `${world}:${CLUB_AT(world, 0)}`;
  if (cacheWorld !== null && (key !== cacheWorld || d < cacheDay)) {
    log(`new career or loaded save: dropped ${finalTables.size} captured table(s), ${recordTables.size} season record(s) and ${pendingSettle.length} delayed settlement(s)`);
    finalTables.clear();
    recordTables.clear();
    strengthDone.clear();
    recordsLoaded = false;
    pendingSettle.length = 0;
  }
  cacheWorld = key;
  cacheDay = d;
}
function captureTable(act) {
  checkWorld();
  const n = topLeagueNation(act);
  if (!n) return;
  const teams = leagueStagesTable(act);
  if (teams.length) finalTables.set(n.toString(), { teams, day: dayNumber() });
}
// FM's own season record (NATION_CONT_INFO, saved with the game) holds the league order from the
// league's finish (live 2015: filled by 2 June) but is replaced by the next year's empty record on
// 16 June before the EL is built, so the lookup at the build never found it. Its league order is
// copied here whenever a competition of the nation's confederation finishes: after a reload
// between the league's finish and the build, the first competition to finish refills it.
const recordTables = new Map();              // nation -> { teams, year, day }
let recordsLoaded = false;
// The record's league entries are not TEAM or CLUB pointers (toTeam rejected all of them, 2015), so
// each entry is tried as a team/club and as an object holding one at a small offset (GUESS: a
// ranking entry like ACT+0x6c's, TEAM at +4). The working layout is logged once; a record whose
// entries resolve to nothing is logged too.
let recordEntryNote = false;
function recordTeam(p) {
  const direct = toTeam(p);
  if (direct) return { t: direct, how: "direct" };
  for (const off of [4, 0, 8, 0xc, 0x10, 0x30]) {
    try { const t = toTeam(p.add(off).readPointer()); if (t) return { t, how: `+0x${off.toString(16)}` }; } catch (e) {}
  }
  return null;
}
function cacheRecords(act) {
  checkWorld();
  const comp = act.add(0x3c).readPointer();
  const n = comp.isNull() ? NULL : comp.add(0x44).readPointer();
  if (n.isNull()) return;
  const seeding = seedingOf(n.add(0xdc).readPointer());
  if (!seeding) return;
  for (const info of readVec(seeding.add(4), 512)) {
    const m = info.readPointer();
    if (m.isNull() || (recordsLoaded && !m.equals(n))) continue;   // the whole confederation once after a load
    for (const r of readVec(info.add(4), 256)) {
      const lg = readVec(r.add(0x1c), 512);
      if (r.readU8() !== 0 || !lg.length) continue;
      const res = lg.map(recordTeam), teams = res.filter((x) => x).map((x) => x.t);
      if (!recordEntryNote) {
        recordEntryNote = true;
        log(`season record league entries for nation ${m.add(8).readS32()}: ${teams.length} of ${lg.length} resolved (${res.filter((x) => x).map((x) => x.how).filter((h, i, a) => a.indexOf(h) === i).join("/") || "none"})`);
      }
      const old = recordTables.get(m.toString());
      if (teams.length && (!old || r.add(2).readU16() >= old.year)) recordTables.set(m.toString(), { teams, year: r.add(2).readU16(), day: dayNumber() });
    }
  }
  recordsLoaded = true;
}
function leagueTable(n) {
  checkWorld();
  const cap = finalTables.get(n.toString()), rec = recordTables.get(n.toString());
  const age = (x) => dayNumber() - x.day, recOk = rec && age(rec) >= 0 && age(rec) < 200;
  if (cap && age(cap) >= 0 && age(cap) < 200) {
    if (recOk) {   // check that the record's order is the final table (continental_build.md guess C2)
      try {
        const k = Math.min(cap.teams.length, rec.teams.length);
        const same = cap.teams.slice(0, k).every((t, i) => sameClub(toTeam(t), rec.teams[i]));
        log(`season record ${rec.year} for nation ${n.add(8).readS32()}: ${same ? "same order as" : "DIFFERS from"} the captured table (${k} rows)`);
      } catch (e) { log("season record comparison error " + e); }
    }
    return { teams: cap.teams, src: "captured at the league's finish" };
  }
  if (recOk) return { teams: rec.teams, src: `FM's season record ${rec.year}` };
  for (const e of readVec(COMP_MANAGER.readPointer().add(8), 4096)) {
    try {
      if (!e.add(0xc).readPointer().equals(n)) continue;
      for (const act of readVec(e, 256)) {
        if (!topLeagueNation(act)) continue;
        const teams = leagueStagesTable(act);
        if (teams.length) return { teams, src: "the league's finished stages" };
      }
    } catch (err) {}
  }
  return null;
}
function secondaryQualifiers(n, ctx) {
  const f = ctx.f, x = nationFacts(n, ctx);
  const eligible = (t) => x.inNation(t) && x.inTop(t) && x.free(t);
  const pickFrom = (k, taken) => reputationPick((x.top.length ? x.top : x.pyramid).filter((c) => x.free(c.team) && !taken.some((t) => sameClub(t, c.team))),
                                                k, pickSeed(ctx.year, x.id, f.salt));
  if (x.unloaded) {
    const picks = pickFrom(SECONDARY_PLACES, []);
    ctx.say(`entry: ${f.name} ${x.name} unloaded, reputation pick ${picks.map(teamName).join(", ") || "-"}`);
    return picks;
  }
  const rec = seasonRecord(ctx.seeding, n, ctx.year);
  const comps = nationalComps(n);
  const league = comps.league ? history(comps.league) : {};
  const lt = leagueTable(n), table = lt && lt.teams;
  const order = (table || []).map(toTeam).concat(rec ? rec.league.map(toTeam) : [], [league.winner, league.runnerUp]);
  const best = distinct(order.filter((t) => t && eligible(t))).slice(0, SECONDARY_PLACES);
  const pos = (t) => { try { return (table || []).findIndex((r) => sameClub(toTeam(r), t)) + 1; } catch (e) { return 0; } };
  ctx.say(`entry: ${f.name} ${x.name} best-placed free clubs ${best.map((t) => `${teamName(t)}${pos(t) ? ` (${pos(t)})` : ""}`).join(", ") || "-"} ` +
          `(table ${lt ? `${table.length} rows, ${lt.src}` : "none"}; record ${rec ? `year ${rec.year} idx ${rec.idx}` : "none"})`);
  if (best.length < SECONDARY_PLACES) {
    const picks = pickFrom(SECONDARY_PLACES - best.length, best);
    ctx.say(`entry: ${f.name} ${x.name} ${SECONDARY_PLACES - best.length} place(s) not filled from the league order, reputation pick ${picks.map(teamName).join(", ") || "-"}`);
    best.push(...picks);
  }
  return best;
}

const PO_TIE = tc(0x01043b10, "pointer", ["int16", "int16"]);     // CUP_STAGE vt+0x10c (stage; round, tie) ret 8
// ================================================================================================

function markChampion(ctx, team) { const c = team && clubOfTeam(team); if (c) ctx.champions.add(c.toString()); }
const sameClub = (a, b) => !!a && !!b && clubOfTeam(a).equals(clubOfTeam(b));
function distinct(teams) {
  const out = [];
  for (const t of teams) if (t && !out.some((o) => sameClub(o, t))) out.push(t);
  return out;
}
function isSplit(n, f) {
  if ((f.splitIds || []).includes(n.add(8).readS32())) return true;
  return (f.splitNames || []).includes(nationName(n));
}

// Last winner / runner-up of a competition: COMP@DB+0x64 -> {+4 winner, +8 runner-up}, as the
// seeding code reads the main cup (0x01088d10). GUESS for leagues and for the title holder (C3).
function history(comp) {
  try {
    const h = comp.add(0x64).readPointer();
    if (h.isNull()) return {};
    return { winner: toTeam(h.add(4).readPointer()), runnerUp: toTeam(h.add(8).readPointer()) };
  } catch (e) { return {}; }
}

// The nation's top league and main cup, from the national entries [[0x024257fc]+8..+0xc]
// ({+0/+4 vector<ACT*>, +0xc NATION*}, as 0x010883a0 walks them). ACT+0x85: 0 league, 2 main cup.
function nationalComps(n) {
  const out = { league: null, cup: null };
  for (const e of readVec(COMP_MANAGER.readPointer().add(8), 4096)) {
    try {
      if (!e.add(0xc).readPointer().equals(n)) continue;
      for (const act of readVec(e, 256)) {
        if (act.isNull()) continue;
        const comp = act.add(0x3c).readPointer(), type = act.add(0x85).readU8();
        if (type === 0 && !out.league && comp.add(0xdd).readS8() === 0) out.league = comp;
        if (type === 2 && !out.cup) out.cup = comp;     // GUESS: 2 = main cup (F5)
      }
    } catch (err) {}
  }
  return out;
}

// The nation's season record in the confederation's seeding object (NATION_CONT_INFO +4..+8;
// record +0 cup index, +2 year, +7 flags, +0x1c league order, +0x40 main cup [winner, runner-up]).
// GUESS (C2): the record for this edition has year == ACT+0x64 and cup index 0; otherwise the
// latest record up to year + 1 with a league list.
function seasonRecord(seeding, n, year) {
  if (!seeding) return null;
  let info = null;
  for (const i of readVec(seeding.add(4), 512)) if (i.readPointer().equals(n)) { info = i; break; }
  if (!info) return null;
  const recs = readVec(info.add(4), 256).map((r) => ({
    idx: r.readU8(), year: r.add(2).readU16(), flags: r.add(7).readU8(),
    league: readVec(r.add(0x1c), 512), cup: readVec(r.add(0x40), 16),
  }));
  return recs.find((r) => r.year === year && r.idx === 0) ||
         recs.filter((r) => r.year <= year + 1 && r.league.length).sort((a, b) => b.year - a.year)[0] || null;
}

// Reputation-weighted draw without replacement (replaces FM's reputation + noise top-20 pick),
// seeded from (season, nation, competition) so that a recomputation or a reload gives the same clubs.
function reputationPick(clubs, k, seed) {
  const rand = mulberry32(seed >>> 0);
  const pool = clubs.map((c) => ({ team: c.team, w: Math.max(1, reputation(c.team)) }));
  const out = [];
  while (out.length < k && pool.length) {
    let r = rand() * pool.reduce((s, c) => s + c.w, 0), i = 0;
    while (i < pool.length - 1 && (r -= pool[i].w) > 0) i++;
    out.push(pool.splice(i, 1)[0].team);
  }
  return out;
}
const pickSeed = (year, nationId, salt) => (Math.imul(year, 0x9e3779b1) ^ Math.imul(nationId + 1, 0x85ebca6b) ^ Math.imul(salt, 0xc2b2ae35)) >>> 0;
function mulberry32(a) {
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// P2. Merge rounds at settings load (hook installed per class vt+0x30 by installFormat). For the
// converted knockout stage, the donor stages' rounds are parsed from the same record (0x00fb4b10)
// and put in front. Runs on every parse, so a re-parse after loading a save gets the same rounds.
function mergeRounds(act, f, settings) {
  const rec = act.add(0xc).readPointer();
  const donors = [];
  for (const idx of f.donorStages) {
    const n = Memory.alloc(2);
    n.writeS16(-1);
    step(f, `parse stage ${idx} settings for the round merge`);
    const donor = PARSE_SETTINGS(act, rec.isNull() ? EMPTY_RECORD : rec, idx, n);
    if (donor.isNull()) { log(`${f.name}: stage ${idx} settings not found, rounds not merged`); return; }
    const rounds = roundsOf(donor);
    donor.add(0x18).writePointer(donor.add(0x14).readPointer());   // donor keeps no rounds (it is never freed)
    donors.push(...rounds);
  }
  const own = roundsOf(settings);
  const clones = f.extra ? addedRounds(act, f, rec, own, donors.length) : [];
  if (!donors.length && !clones.length) return;
  const moved = donors.concat(clones.map((x) => x.r));
  step(f, `move ${moved.length} round(s) in front of ${own.length} knockout round(s)`);
  const vec = settings.add(0x14), slot = Memory.alloc(4);
  for (const r of moved) { slot.writePointer(r); VEC_PUSH(vec, slot); }
  const all = roundsOf(settings), k = donors.length, c = clones.length, old = all.length - k - c;
  const order = moved.concat(all.slice(0, old));
  const begin = vec.readPointer();
  order.forEach((r, i) => {
    begin.add(4 * i).writePointer(r);
    r.writeU8(i);                                                   // round index
    if (i >= k + c) for (const off of [0x59, 0x5a]) { const v = r.add(off).readS8(); if (v >= 0) r.add(off).writeS8(v + k + c); }
  });
  if (c) placeAddedRounds(f, order, k, clones);
  if (k) levelDonorRounds(f, order, k);
  try { for (const e of readVec(settings.add(0x20), 256)) e.add(4).writeS8(e.add(4).readS8() + k + c); } catch (e) {}  // GUESS: per-round records
  log(`${f.name}: merged ${k} round(s) from stage ${f.donorStages.join("/")}` + (c ? `, added ${c} round(s) (copies of stage ${f.extra.template.join(" round ")})` : "") +
      `; rounds ${order.map((r) => `${roundName(r)}:${ntms(r)}/${nmmt(r)}/${nmxt(r)}`).join(" ")}`);
}

// Rounds added when donors + knockout rounds are too few for the field (FORMATS[].extra). The
// field size is the knockout stage's entrant count (+0x40, set before its setup calls vt+0x30;
// the same on any later re-parse, so a reload gets the same rounds). Each added round is the
// template data round, parsed again from the competition's own record with 0x00fb4b10 (a fully
// formed CUP_ROUND; the rest of that parse is never freed), re-dated: first match = first knockout
// round's first match + offset (FM's own date arithmetic; second leg and kick-off slots are relative
// and come with the copy), draw date = FM's "no date" as the parser writes for "1900"/"stage setup
// day" draws (the merged AFC R16 has one and was drawn after the play-offs).
function addedRounds(act, f, rec, own, k) {
  if (!own.length) return [];
  const stage = readVec(act.add(0x4c), 64)[f.koIndex];
  const N = stage.add(0x40).readS16();
  const need = Math.ceil(Math.log2(Math.max(2, N))) - (k + own.length);
  if (need <= 0) return [];
  const offsets = f.extra.offsets;
  if (need > offsets.length) log(`${f.name}: ${N} entrants need ${need} added rounds, ${offsets.length} configured (CHECK: the field does not fit)`);
  const use = offsets.slice(Math.max(0, offsets.length - need));
  const [ts, tr] = f.extra.template;
  const anchor = own[0], out = [];
  const date = Memory.alloc(4), noDate = NULL_DATE.readU32();
  const names = [];
  for (const days of use) {
    const n = Memory.alloc(2);
    n.writeS16(-1);
    step(f, `parse stage ${ts} settings for an added round`);
    const s = PARSE_SETTINGS(act, rec.isNull() ? EMPTY_RECORD : rec, ts, n);
    if (s.isNull()) { log(`${f.name}: stage ${ts} settings not found, no round added`); break; }
    const rounds = roundsOf(s);
    if (rounds.length <= tr) { log(`${f.name}: stage ${ts} has no round ${tr}, no round added`); break; }
    const r = rounds[tr];
    s.add(0x18).writePointer(s.add(0x14).readPointer());       // that settings object keeps no rounds
    // The copy keeps the template's stage name (CONCACAF QF 17, OFC SF 18), and the coefficient
    // points (class vt+0x34, from [[fixture+0x1c]+8]) give the winner of every match named 17/18/20
    // a bonus, so each added round would count as a QF or SF. They take FM's own round names 6, 7,
    // 8... (no bonus) from the shared stage-name table, as the stnm reader does (0x01494420 on
    // [[WORLD]+0x54]; nothing owns or frees round+0xc, reports/parity/round_names.md). Fixtures copy
    // the name when drawn, so rounds already drawn in a save keep the old one.
    const id = 6 + out.length;
    if (![17, 18, 20].includes(roundName(r))) names.push(roundName(r));   // CAF templates: no bonus name
    else try {
      const nm = STAGE_NAME(WORLD.readPointer().add(0x54).readPointer(), id);
      if (!nm.isNull() && nm.add(8).readS32() === id) { r.add(0xc).writePointer(nm); names.push(id); }
      else names.push(`${roundName(r)} (name ${id} not found)`);
    } catch (e) { names.push(`${roundName(r)} (rename error ${e})`); }
    step(f, `date an added round ${days} days from the first knockout round`);
    DATE_ADD(anchor.add(6), date, days);
    r.add(6).writeU32(date.readU32());
    r.add(2).writeU32(noDate);
    out.push({ r, days, tr });
  }
  if (out.length) log(`${f.name}: added rounds named ${names.join(", ")} (no coefficient round bonus)`);
  return out;
}

// Indices and ranking levels of the added rounds (at order[k..k+c-1]). +0x59/+0x5a (next-round
// indices) keep the template's distance from its own index. Ranking levels: the template's would
// repeat another round's loser level, which FM's placing (and the settlement's round-reached
// codes, +0x5c) read per round; they continue the first knockout round's level upwards, as FM's own
// default filler 0x010511b0 numbers rounds from the final (winner +0x5b/+0x5d = 0, +0x5f = L - 1;
// loser +0x5c/+0x5e/+0x60 = L).
function placeAddedRounds(f, order, k, clones) {
  const c = clones.length, first = order[k + c], L0 = first.add(0x5c).readU8();
  const dates = [];
  clones.forEach((x, j) => {
    const r = x.r, i = k + j;
    for (const off of [0x59, 0x5a]) { const v = r.add(off).readS8(); if (v >= 0) r.add(off).writeS8(v - x.tr + i); }
    if (L0 !== 0xff) {
      const L = L0 + (c - j);
      r.add(0x5b).writeU8(0); r.add(0x5d).writeU8(0); r.add(0x5f).writeU8(L - 1);
      r.add(0x5c).writeU8(L); r.add(0x5e).writeU8(L); r.add(0x60).writeU8(L);
    }
    dates.push(`${r.add(8).readU16()}/${r.add(6).readU16() & 0x1ff}`);
  });
  if (L0 === 0xff) log(`${f.name}: first knockout round has no ranking level, added rounds keep the template's (CHECK settlement codes)`);
  // Order check: each added round's first match must come after the previous round's last match.
  for (let i = Math.max(1, k); i <= k + c; i++) {
    const prev = order[i - 1], cur = order[i];
    const gap = DATE_DIFF(cur.add(6), prev.add(6)) - (prev.add(0x2c).readU8() >= 2 ? prev.add(0x32).readS16() : 0);
    if (gap < 3) log(`${f.name}: WARNING round ${i} starts ${gap} day(s) after round ${i - 1} ends (CHECK the calendar)`);
  }
  log(`${f.name}: added rounds start on (year/day of year) ${dates.join(", ")}, loser levels ${clones.map((x) => x.r.add(0x5c).readU8()).join(", ")}`);
}

// Ranking levels of the donor rounds (order[0..k-1]). They come from the plain parse 0x00fb4b10, not
// the class loader: the EL's vt+0x30 (0x010dad70) renumbers its stage 0 with 0x010511b0(7), the plain
// parse leaves the data's winner 0 / loser 1 in every qualifying round. A donor loser at the final's
// loser level gives FM's season ranking more than one runner-up, so FM never records the edition in
// the competition history (repairRanking above, reports/parity/el_history.md). When a donor level is
// not above the rounds after it, the donors are numbered upwards from there as 0x010511b0 does
// (winner +0x5b/+0x5d = 0, +0x5f = L - 1; loser +0x5c/+0x5e/+0x60 = L). Donors with distinct higher
// levels (the CL's 9/8/7) are left as FM's data has them.
function levelDonorRounds(f, order, k) {
  const top = order[k].add(0x5c).readU8();                  // first added round, or first knockout round
  if (top === 0xff) return;
  const clash = order.slice(0, k).some((r) => { const v = r.add(0x5c).readU8(); return v !== 0xff && v <= top; });
  if (!clash) return;
  order.slice(0, k).forEach((r, i) => {
    const L = top + (k - i);
    r.add(0x5b).writeU8(0); r.add(0x5d).writeU8(0); r.add(0x5f).writeU8(L - 1);
    r.add(0x5c).writeU8(L); r.add(0x5e).writeU8(L); r.add(0x60).writeU8(L);
  });
  log(`${f.name}: donor round loser levels renumbered to ${order.slice(0, k).map((r) => r.add(0x5c).readU8()).join(", ")} (above ${top})`);
}

// P3. Counts and rules of the converted stage at 0x0103e360 (ECX = CUP_STAGE), before byes and
// placement. parity_agent.js hooks the same address for national cups only (continental cups have
// no nation), so the two never act on the same stage.
function knockoutRules(stage) {
  if (!isCupStage(stage)) return;
  const comp = compOf(stage.add(0x28).readPointer()), act = comp.add(0x68).readPointer();
  const f = formatOf(act);
  if (!f || stage.add(8).readS8() !== f.koIndex || !converted(act, f)) return;
  if (!readVec(act.add(0x4c), 64)[f.koIndex].equals(stage) || !stage.add(0x44).readPointer().isNull()) return;
  const settings = stage.add(0x38).readPointer();
  // Fixed cup-tie pairings from the data (CUP_SETTINGS+0x38) are tagged with the round index at load
  // and go stale once rounds are merged or deleted; FM applies them at placement whatever the draw
  // rules say, so stale ones silently drop entrants (the AFC Cup R16, afc_cup_stall.md). Drop them
  // all: every converted draw is random by design.
  try {
    const maps = settings.add(0x38), begin = maps.readPointer();
    const dropped = begin.isNull() ? 0 : maps.add(4).readPointer().sub(begin).toInt32() >> 2;
    if (dropped > 0) {
      maps.add(4).writePointer(begin);
      log(`${f.name}: ${dropped} cup-tie mapping(s) dropped (random draw)`);
    }
  } catch (e) { log(`${f.name}: cup-tie mapping drop error ${e.stack}`); }
  const N = stage.add(0x40).readS16();
  let rounds = roundsOf(settings);
  const plan = bracketPlan(rounds.length, N);
  if (!plan) { log(`${f.name}: ${N} entrants do not fit ${rounds.length} rounds, rules left as data (CHECK: entrants may be cut)`); return; }
  step(f, `write round counts for ${N} entrants over ${rounds.length} rounds`);
  rounds.forEach((r, i) => {
    r.add(0x1c).writeS16(plan.ntms[i]);
    r.add(0x1e).writeS16(plan.ntms[i] >> 1);
    r.add(0x20).writeS16(plan.nmxt[i]);
  });
  if (plan.emptyLeading) step(f, `delete ${plan.emptyLeading} empty leading round(s)`);
  for (let k = 0; k < plan.emptyLeading; k++) DEL_ROUND(settings, 0, act);
  rounds = roundsOf(settings);
  const F = rounds.length - 1;
  // Country protection in each club's first round: the opening round and, when there are byes, the
  // round the bye clubs enter (approximation: that round also protects the opening-round winners).
  const protect = plan.byes ? 2 : 1;
  step(f, `write round rules (legs, draw, final) for ${rounds.length} rounds`);
  const singleLeg = [];
  rounds.forEach((r, i) => {
    r.add(0x10).writeU64(uint64(i < protect && i < F ? 0x10 : 0));   // random, unseeded; avoid same nation
    r.add(0x2b).writeU8(0);                              // no replays
    r.add(0x1a).writeU8(r.add(0x1a).readU8() & ~3);      // no three-match series
    if (i === F) { r.add(0x2c).writeU8(1); return; }     // one-match final
    // Two legs where the competition's data already plays the round over two legs (FM has its
    // second-leg date); a round the data plays as one match (the AFC East play-offs) keeps one
    // leg. (Checked live: CUP_ROUND+0x70 is not the second-leg dates; the EL rounds have none.)
    if (r.add(0x2c).readU8() >= 2) r.add(0x2c).writeU8(2);
    else { r.add(0x2c).writeU8(1); singleLeg.push(roundName(r)); }
  });
  rounds[F].add(0x18).writeU16(0x3);                      // final: extra time + penalties
  rounds[F].add(0x2a).writeU8(3);                         // GUESS (C8): neutral venue; 4 = host
  const S = rounds.reduce((s, r) => s + nmxt(r), 0);
  log(`${f.name}: ${N} entrants, rounds ${rounds.map((r) => `${roundName(r)}:${ntms(r)}/${nmmt(r)}/${nmxt(r)}/${r.add(0x2c).readU8()}leg`).join(" ")}` +
      (singleLeg.length ? `; one leg kept (one match in the data) in rounds ${singleLeg.join(",")}` : "") +
      (S !== N ? ` BUG: entrant slots ${S} != ${N}` : ""));
}

// Round sizes by index for N entrants in n rounds ending in a final: P = largest power of two <= N
// plays the first full round, the other 2(N-P) play one round before it and P - (N-P) get byes, as
// FUN_0103e360's own reconciliation would (cup_entry.md 2); earlier rounds are emptied and deleted.
function bracketPlan(n, N) {
  if (N < 2) return null;
  const k = Math.floor(Math.log2(N)), P = 1 << k, F = n - 1;
  const rP = F + 1 - k, rE = N === P ? rP : rP - 1;
  if (rE < 0) return null;
  const ntmsA = new Array(n).fill(0), nmxtA = new Array(n).fill(0);
  if (N === P) { ntmsA[rP] = N; nmxtA[rP] = N; }
  else { ntmsA[rE] = 2 * (N - P); nmxtA[rE] = 2 * (N - P); ntmsA[rP] = P; nmxtA[rP] = 2 * P - N; }
  for (let r = rP + 1; r < n; r++) ntmsA[r] = ntmsA[r - 1] >> 1;
  return { ntms: ntmsA, nmxt: nmxtA, emptyLeading: rE, byes: N !== P };
}

// P6. No data stage is created for a converted competition (0x00fb4c00, thiscall (ACT, finished
// stage) ret 4, return value unused by its caller 0x00fb5370). Otherwise requirement-free hidden
// tables (Libertadores stages 2 and 3) or stages waiting on absent stages could appear.
const ORIGINAL_CREATE = new NativeFunction(va(0x00fb4c00), "uint8", ["pointer", "pointer"], "thiscall");
const createCallback = new NativeCallback(function (act, stage) {
  try {
    const f = formatOf(act);
    if (f && converted(act, f)) { log(`${f.name}: data stage creation skipped (converted)`); return 0; }
  } catch (e) { log("stage creation guard error " + e.stack); }
  return ORIGINAL_CREATE(act, stage);
}, "uint8", ["pointer", "pointer"], "thiscall");

// Monthly progress of each converted competition (stall check): per round, teams still in and the
// placing codes recorded so far, read from the knockout stage's team table.
// Entrants marked before entryCode was fixed (CL/EL 0xff) are never picked by UEFA's squad
// registration (0x010d3580). Rewrite team+0x6b of the converted stage's clubs that still carry this
// competition's marker (+0x50), so the next registration deadline registers them. Runs at every
// month start (game thread; the career isn't loaded yet when the agent starts).
function fixEntryCodes() {
  for (const f of activeByVt.values()) {
    if (f.entryCode === 0xff) continue;
    const act = actOfFormat(f);
    if (!act || !converted(act, f)) continue;
    const comp = act.add(0x3c).readPointer();
    const stage = readVec(act.add(0x4c), 64)[f.koIndex];
    const table = stage.add(0x3c).readPointer(), count = stage.add(0x40).readS16();
    let fixed = 0;
    for (let i = 0; i < count; i++) {
      const team = table.add(12 * i).readPointer();
      if (team.isNull() || !team.add(0x50).readPointer().equals(comp)) continue;
      if (team.add(0x6b).readU8() === f.entryCode) continue;
      team.add(0x6b).writeU8(f.entryCode);
      fixed++;
    }
    if (fixed) log(`${f.name}: entry code ${f.entryCode} written for ${fixed} of ${count} entrants (squad registration)`);
  }
}

// Monthly check that the fix above works: for each converted competition's clubs, how many real
// players FM counts as registered. Same calls as the eligibility check 0x005bc880 at
// 0x005bd1f2..0x005bd215: obj = player's virtual-base subobject vt+0x36c() (thiscall, no args), then
// FUN_007ef710(obj, team, &info, 0, 0) (cdecl; reads only info+1, the registration type in force).
// info+1 is taken from the competition's default rule group as 0x011a6b90/0x010618e0 do: group =
// ACT vt+0x3ac(0, -1) (as at 0x010d9dd2), type = group+0x4b; null group or -1 = no registration.
const VIRTUAL_PLAYER_VT = va(0x0226a558);
const IS_REGISTERED = new NativeFunction(va(0x007ef710), "uint8", ["pointer", "pointer", "pointer", "int", "int"], "mscdecl");
const REG_INFO = zeroed(8);
const REG_GETTERS = new Map();
function registrationReport(f, stage, act) {
  const group = vfnOf(act.readPointer().add(0x3ac).readPointer(), "pointer", ["pointer", "pointer", "int"])(act, NULL, -1);
  const type = group.isNull() ? -1 : group.add(0x4b).readS8();
  if (type === -1) { log(`registration: ${f.name} has no squad registration (group ${group})`); return; }
  REG_INFO.add(1).writeS8(type);
  const table = stage.add(0x3c).readPointer(), count = stage.add(0x40).readS16();
  let real = 0, reg = 0, clubs = 0, none = 0;
  for (let i = 0; i < count; i++) {
    const team = table.add(12 * i).readPointer();
    if (team.isNull()) continue;
    let r = 0, n = 0;
    for (const p of readVec(team.add(0x24), 500)) {
      if (p.isNull() || p.readPointer().equals(VIRTUAL_PLAYER_VT)) continue;
      const sub = p.add(4).add(p.add(4).readPointer().add(4).readS32());
      const fn = sub.readPointer().add(0x36c).readPointer(), key = fn.toString();
      if (!REG_GETTERS.has(key)) REG_GETTERS.set(key, new NativeFunction(fn, "pointer", ["pointer"], "thiscall"));
      const obj = REG_GETTERS.get(key)(sub);
      n++;
      if (!obj.isNull() && (IS_REGISTERED(obj, team, REG_INFO, 0, 0) & 0xff)) r++;
    }
    clubs++; real += n; reg += r;
    if (n && !r) none++;
  }
  log(`registration: ${f.name} ${reg} of ${real} real players registered (type ${type}, entry code ${f.entryCode}) over ${clubs} clubs, ${none} clubs with none`);
}

function progressReport() {
  for (const f of activeByVt.values()) {
    const act = actOfFormat(f);
    if (!act || !converted(act, f)) continue;
    const stage = readVec(act.add(0x4c), 64)[f.koIndex];
    const table = stage.add(0x3c).readPointer(), count = stage.add(0x40).readS16();
    const hist = new Map();
    for (let i = 0; i < count; i++) { const s = table.add(12 * i + 6).readS8(); hist.set(s, (hist.get(s) || 0) + 1); }
    const settings = stage.add(0x38).readPointer();
    const rounds = settings.isNull() ? [] : roundsOf(settings);
    log(`progress: ${f.name} season ${act.add(0x64).readU16()}, ${count} teams, status ` +
        `${[...hist.entries()].sort((a, b) => a[0] - b[0]).map(([s, n]) => `${s}:${n}`).join(" ")}; ` +
        `round loser codes ${rounds.map((r) => `${ntms(r)}->${r.add(0x5c).readS8()}`).join(" ")}`);
    try { registrationReport(f, stage, act); } catch (e) { log(`registration report error ${e.message}`); }
  }
}

recv("config", (msg) => {
  try { logFile = new File(msg.log, "a"); } catch (e) {}
  log(`parity continental agent started (format change ${FORMAT_ENABLED ? "on" : "off"})`);
  try { installFormats(); } catch (e) { log("format installation error " + e.stack); }
  try { installStrength(); } catch (e) { log("nation strength installation error " + e.stack); }
  if (FORMAT_ENABLED) Interceptor.attach(va(0x0063e9b8), {         // month start (as parity_agent.js)
    onEnter() {
      try { fixEntryCodes(); } catch (e) { log("entry code fix error " + e.stack); }
      try { progressReport(); } catch (e) { log("progress error " + e.stack); }
    },
  });
  send({ started: true });
});
