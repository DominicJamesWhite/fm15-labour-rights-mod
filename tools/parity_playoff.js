// Frida agent for parity mode: the 2nd-7th league play-off for each nation's single place in its
// confederation's secondary continental cup (Europa League, Copa Sudamericana, AFC Cup, CAF
// Confederation Cup). Design and verification: reports/parity/playoff_build.md (research:
// league_playoff.md). Loaded after tools/parity_continental.js (patch.py MODE_AGENTS["parity"]);
// logs to the file given by recv("config"). Every risky native call is preceded by an
// "about to <step>" line so a crash can be attributed. Anything unverified is marked GUESS.
//
// How it works:
//  1. When the last running stage of a loaded nation's top-division league ACTUAL_COMP finishes
//     (0x00fb5370 onLeave; still inside FM's daily comp step, before FM's own "is the competition
//     complete?" check), the agent reads the final table, removes the clubs that already have a
//     primary-cup place (champion; cup winner, or the losing finalist when the champion won the
//     cup, or the runner-up when there is no cup; the primary cup's title holder) and takes the
//     next six as seeds P1..P6.
//  2. If the domestic cup final is still to come (within MAX_WAIT_DAYS), it only reserves an empty
//     stage slot: an empty slot makes FM's completeness check fail (vt+0x330 0x00fb2150), so the
//     league stays open, exactly as vanilla Wales waits for its cup. The play-off is built when the
//     cup finishes (0x00fad710 onLeave for the cup), or cancelled (slot filled with a dead stage)
//     when the final is overdue.
//  3. The play-off is a code-built CUP_STAGE appended to the league ACT: rounds parsed from the
//     Welsh record's play-off stage (comp 130672 stage 3: three single-match rounds, extra time and
//     penalties, fixed draw, higher seed at home), then edited: QF P3 v P6 and P4 v P5 (4 teams),
//     SF P1 and P2 against the QF winners (tie mappings), final. Dates D+3, D+6, D+9 from the day
//     it is built. No prize money (round money zeroed), no ranking levels (so the play-off never
//     rewrites the league's final positions).
//  4. When QF0 (P3 v P6) is decided and P3 won, the semi-finals are re-seeded so P1 meets the
//     lowest-ranked survivor (the two SF home entrants are swapped before the SF draw).
//  5. The league now finishes after the play-off final (as vanilla Wales does). At that point the
//     winner gets the team marker [team+0x54]+0x7c = secondary COMP, +0xa6 = 0x50 | (target season
//     & 0xf), which secondaryQualifier() in parity_continental.js reads (it reads the still-live
//     stage first). No marker is written when the secondary cup has already been built.
//  6. The vanilla Welsh play-off (WAL_PRM stage 3, 0x0117dfc0) is replaced by a dead stage, as FM
//     itself does when Wales has too many places.

const PLAYOFF_ENABLED = true;        // master switch: false = no hook at all, every nation falls back
// No new play-offs: the EL takes each league's two best-placed free clubs instead (2031; finals could
// not be held before the June EL build). The hooks stay so saves holding a play-off stage still load
// (load guard) and a running one finishes; set true to build play-offs again.
const BUILD_ENABLED = false;
const SUPPRESS_WALES_PLAYOFF = true; // replace the vanilla Welsh stage-3 play-off by a dead stage
const RESEED_ENABLED = true;         // P1 meets the lowest-ranked survivor (hook 0x01040310)
const LOAD_GUARD_ENABLED = true;     // GUESS (L2): redirect a settings re-parse of the play-off stage
const MAX_WAIT_DAYS = 14;            // league end -> domestic cup final: wait at most this long
const CUP_FINAL_GRACE_DAYS = 5;      // cup final this many days overdue: cancel the play-off
// QF, SF, F in days after the day the stage is built. Rounds 3 days apart: at 2 days FM's clash
// check failed (GUESS: the clubs' minimum rest gap) and its rescheduler moved the matches, in odd
// years past the 16 June EL build (reports/parity/playoff_dates.md).
const ROUND_OFFSETS = [3, 6, 9];
// Round clash priority (CUP_ROUND+0x1b, copied to fixture +0x2f; template 4). From 5, FM's
// clash check skips the test against the nation's international dates (0x00ff2231), as for
// continental rounds (5-7).
const ROUND_PRIORITY = 5;
// Draw dates (CUP_ROUND +0x02/+0x04, same format as the match date). FM draws a pending round on
// its daily update as soon as today >= its draw date (0x010445a0 -> 0x01044f60, 0x0104a080). The
// template's draw dates are absolute (resolved from the Welsh dates at parse time) and so lay in
// the past: every round, the final included, was drawn on the build day before its teams existed,
// and the finals were never played (live test, June 2015). Each later round is now drawn the day
// after the previous round's match (as vanilla Wales: draw = previous round + 1 day), re-applied
// after setup from the actual (possibly moved) match dates.
const DRAW_OFFSETS = [0, 4, 7];
const STALL_DAYS = 14;               // monthly check: final this many days past and not finished (live: finished 3-11 days late)

const WALES_COMP_ID = 130672, WALES_STAGE = 3;
const WAL_PRM_VT = 0x0222bf30;
const TAG_BASE = 0x50;               // +0xa6 = TAG_BASE | (target season & 0xf); vanilla uses 0 / 0xff

// Confederations with a secondary cup. cutMonth: a play-off final in this month or later feeds
// the secondary cup of the next calendar year (the edition built after it). GUESS for the AFC Cup
// and the CAF Confederation Cup build dates (early in the year). The same table is in
// secondaryQualifier (parity_continental.js); keep them identical.
const CONFEDERATIONS = [
  { name: "UEFA", primary: 1301394, secondary: 1301396, cutMonth: 7 },
  { name: "CONMEBOL", primary: 102415, secondary: 317567, cutMonth: 8 },
  { name: "AFC", primary: 127286, secondary: 1001959, cutMonth: 3 },
  { name: "CAF", primary: 127299, secondary: 12017574, cutMonth: 3 },
];

// Split leagues whose later stages are hidden and processed into stage 0 (comps.dbc
// process_results_into_stage = 0, hide_stage): stage 0's table is the final table.
const SPLIT_CUMULATIVE_IDS = new Set([7483354, 7500000, 7860000, 136407, 130023, 45, 5395850, 130672]);

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const TODAY = va(0x0239ebf4);
const WORLD = va(0x02428ee0);
const COMP_MANAGER = va(0x024257fc);      // [mgr+8..+0xc] = national entries {vector<ACT*>, +0xc NATION*}

const tc = (addr, ret, args) => new NativeFunction(va(addr), ret, ["pointer"].concat(args || []), "thiscall");
const FIN_OF = tc(0x014c9670, "pointer");
const OPERATOR_NEW = new NativeFunction(va(0x02055715), "pointer", ["uint32"], "mscdecl");
const STAGE_BASE_CTOR = tc(0x01075950, "pointer", ["int", "pointer"]);          // (stage; index, owner) ret 8
const CUP_ENTRANTS = tc(0x0103ebb0, "void", ["pointer", "pointer", "int", "int"]); // (stage; &vector<TEAM*>, pots, sort, seedFromRep) ret 0x10
const STAGE_INSERT = tc(0x00fa0e60, "int", ["pointer", "int"]);                  // (ACT; stage, 0) ret 8; 1 = ok
const PARSE_SETTINGS = tc(0x00fb4b10, "pointer", ["pointer", "int", "pointer"]); // (ACT; record, stage index, &s16 n) ret 0xc
const COMP_BY_ID = tc(0x01494420, "pointer", ["int"]);                           // ([[0x02428ee0]+0x18]; id) ret 4
const COMP_RECORD = tc(0x015cd3a0, "pointer", ["uint32"]);                       // (COMP@DB; record index) ret 4
const VEC_RESIZE = tc(0x00fc4c00, "void", ["uint32"]);                           // (vector<T*>*; n) ret 4, new slots NULL
const TIE = tc(0x01043b10, "pointer", ["int16", "int16"]);                       // CUP_STAGE vt+0x10c (stage; round, tie) ret 8
const CUP_STAGE_VT = va(0x021ea9c0);
const VIRTUAL_CUP_STAGE_VT = va(0x0224d7cc);
const DEAD_STAGE_VT = va(0x021ec84c);
const EMPTY_RECORD = va(0x02426d60);
const MATCH_CLEAR = 0x4 | 0x8 | 0x20 | 0x40 | 0x100 | 0x400 | 0x800;          // as parity_agent.js cup rules

let logFile = null;
function log(line) {
  if (!logFile) return;
  try { logFile.write(today() + " [playoff] " + line + "\n"); logFile.flush(); } catch (e) {}
}
function today() {
  return new Date(Date.UTC(TODAY.add(2).readU16(), 0, TODAY.readU16() & 0x1ff)).toISOString().slice(0, 10);
}

// Names for the log, through FM's own text formatter (as the other parity agents do).
const TEXT_CTOR = tc(0x0188f4b0, "pointer");
const TEXT_SET = tc(0x0188fd00, "void", ["pointer"]);
const TEXT_ARG = tc(0x01493e80, "void", ["int", "pointer", "int", "int", "pointer"]);
const TEXT_RENDER = tc(0x01890790, "pointer");
const TEXT_DTOR = tc(0x0188fc80, "void");
const EMPTY_TEXT = va(0x02426d58);
function nameOf(token, obj) {
  try {
    if (!obj || obj.isNull()) return "-";
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
const compName = (comp) => nameOf("comp", comp);
const teamName = (team) => nameOf("team", team);

// --- Small readers ---------------------------------------------------------------------------

function readVec(p, max) {
  const begin = p.readPointer(), end = p.add(4).readPointer();
  if (begin.isNull()) return [];
  const n = end.sub(begin).toInt32() / 4;
  if (n < 0 || n > (max || 20000) || n !== Math.floor(n)) throw new Error("bad vector at " + p);
  const out = [];
  for (let i = 0; i < n; i++) out.push(begin.add(4 * i).readPointer());
  return out;
}
function agentVec(ptrs) {
  const buf = Memory.alloc(Math.max(4, 4 * ptrs.length));
  ptrs.forEach((p, i) => buf.add(4 * i).writePointer(p));
  const v = Memory.alloc(12);
  v.writePointer(buf);
  v.add(4).writePointer(buf.add(4 * ptrs.length));
  v.add(8).writePointer(buf.add(4 * ptrs.length));
  return { vec: v, buf };
}
// obj->vt[off] as a thiscall NativeFunction, made once per target and signature and kept (the
// stage-state reads call it twice per stage of every league they look at).
const vfnCache = new Map();
function vfn(obj, off, ret, args) {
  const target = obj.readPointer().add(off).readPointer(), sig = ["pointer"].concat(args || []);
  const key = `${target}|${ret}|${sig.join(",")}`;
  let fn = vfnCache.get(key);
  if (!fn) { fn = new NativeFunction(target, ret, sig, "thiscall"); vfnCache.set(key, fn); }
  return fn;
}
function clubOfTeam(team) {
  try {
    if (!team || team.isNull() || team.add(0x23).readU8() !== 0) return null;
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
function toTeam(p) {                         // a club or a first team -> the first team
  try {
    if (!p || p.isNull()) return null;
    const club = clubOfTeam(p);
    if (club && p.equals(firstTeam(club))) return p;
    const t = firstTeam(p);
    if (t && p.equals(clubOfTeam(t))) return t;
  } catch (e) {}
  return null;
}
const clubKey = (t) => { const c = clubOfTeam(t); return c ? c.toString() : null; };
const sameClub = (a, b) => !!a && !!b && clubKey(a) !== null && clubKey(a) === clubKey(b);
function history(comp) {                    // COMP@DB+0x64 -> {+4 winner, +8 runner-up} (GUESS, as parity_continental)
  try {
    const h = comp.add(0x64).readPointer();
    if (h.isNull()) return {};
    return { winner: toTeam(h.add(4).readPointer()), runnerUp: toTeam(h.add(8).readPointer()) };
  } catch (e) { return {}; }
}
function compById(id) {
  try { const c = COMP_BY_ID(WORLD.readPointer().add(0x18).readPointer(), id); return c.isNull() ? null : c; } catch (e) { return null; }
}

// --- Dates (CUP_ROUND +0x06 u16: day of year in bits 0-8, 1-based, upper bits kept; +0x08 u16
// year. Same layout as the current date 0x0239ebf4; verified in 0x01c1ed10 / 0x01052100) -------

const dayNum = (year, doy) => Date.UTC(year, 0, doy) / 86400000;
const todayNum = () => dayNum(TODAY.add(2).readU16(), TODAY.readU16() & 0x1ff);
function ymd(n) {
  const d = new Date(n * 86400000), y = d.getUTCFullYear();
  return { year: y, month: d.getUTCMonth() + 1, doy: Math.round((n * 86400000 - Date.UTC(y, 0, 1)) / 86400000) + 1,
           iso: d.toISOString().slice(0, 10) };
}
const roundDay = (r) => dayNum(r.add(8).readU16(), r.add(6).readU16() & 0x1ff);
function setRoundDay(r, n) {
  const d = ymd(n);
  r.add(6).writeU16((r.add(6).readU16() & 0xfe00) | d.doy);
  r.add(8).writeU16(d.year);
}
const drawDay = (r) => dayNum(r.add(4).readU16(), r.add(2).readU16() & 0x1ff);
function setDrawDay(r, n) {
  const d = ymd(n);
  r.add(2).writeU16((r.add(2).readU16() & 0xfe00) | d.doy);
  r.add(4).writeU16(d.year);
}
// After setup (whose date fix-up 0x01052100 may move match days): draw of round i = match day of
// round i-1 plus one, and never later than the round's own match day minus one. Only for rounds
// still waiting for their draw (+0x58 bit 0).
function fixDrawDays(stage) {
  const rs = roundsOf(stage.add(0x38).readPointer()), out = [];
  for (let i = 1; i < rs.length; i++) {
    if (!(rs[i].add(0x58).readU8() & 1)) { out.push(`r${i} drawn`); continue; }
    const want = roundDay(rs[i - 1]) + 1, latest = roundDay(rs[i]) - 1;
    setDrawDay(rs[i], Math.min(want, latest));
    out.push(`r${i} draw ${ymd(drawDay(rs[i])).iso}${want > latest ? " (WARNING: less than a day after the previous round)" : ""}`);
  }
  return out.join(", ");
}
const targetSeason =(finalDay, conf) => { const d = ymd(finalDay); return d.year + (d.month >= conf.cutMonth ? 1 : 0); };

// --- Stages ---------------------------------------------------------------------------------

const isCupStage = (s) => { const v = s.readPointer(); return v.equals(CUP_STAGE_VT) || v.equals(VIRTUAL_CUP_STAGE_VT); };
const isDead = (s) => !s.isNull() && s.readPointer().equals(DEAD_STAGE_VT);
const stageType = (s) => vfn(s, 0xc4, "uint8")(s);                          // 0 cup, 1 league, 6 dead
const stageDone = (s) => (vfn(s, 0x10, "uint8", ["int"])(s, 0) & 0xff) !== 0; // vt+0x10(0): finished, no side effect
const roundsOf = (settings) => readVec(settings.add(0x14), 64);
const ntms = (r) => r.add(0x1c).readS16();
const entryStatus = (stage, i) => stage.add(0x3c).readPointer().add(12 * i + 6).readU8();
const entryTeam = (stage, i) => stage.add(0x3c).readPointer().add(12 * i).readPointer();
function leagueRows(s) {                    // league table rows, row i = position i (row+0x30 TEAM*)
  const n = s.add(0x44).readS8(), rows = s.add(0x38).readPointer(), out = [];
  for (let i = 0; i < n; i++) { const t = rows.add(4 * i).readPointer().add(0x30).readPointer(); if (!t.isNull()) out.push(t); }
  return out;
}

// A loaded nation's top-division league ACT (type 0/1/14, level 0, domestic).
function leagueInfo(act) {
  try {
    if (!act || act.isNull()) return null;
    const comp = act.add(0x3c).readPointer();
    if (comp.isNull() || !comp.add(0x68).readPointer().equals(act)) return null;
    const nation = comp.add(0x44).readPointer();
    if (nation.isNull()) return null;
    if (![0, 1, 14].includes(act.add(0x85).readU8()) || comp.add(0xdd).readS8() !== 0) return null;
    const wales = act.readPointer().equals(va(WAL_PRM_VT));
    return { act, comp, nation, id: comp.add(8).readS32(), wales, minStages: Math.max(0, act.add(0xf8).readS8()) };
  } catch (e) { return null; }
}
const lname = (L) => `${compName(L.comp)} (${L.id})`;

// Our play-off stage: a cup stage at a slot past the record's stages with 6 entrants and the
// QF/SF/F shape (no vanilla league stage has it; Wales' own play-off has 5 entrants).
function isPlayoffStage(s, L) {
  if (s.isNull() || !isCupStage(s)) return false;
  if (s.add(8).readS8() < Math.max(1, L.minStages) || s.add(0x40).readS16() !== 6) return false;
  const set = s.add(0x38).readPointer();
  if (set.isNull()) return true;
  const rs = roundsOf(set);
  return rs.length === 3 && ntms(rs[0]) === 4 && ntms(rs[1]) === 4 && ntms(rs[2]) === 2;
}

// Slot states. A NULL slot below the record's stage count (byte ACT+0xf8; also a slot not yet
// allocated) is a vanilla stage still to be created: FM cannot finish the league before it exists
// (vt+0x330 0x00fb2150 fails on short vectors and NULL slots), so the play-off waits for it too.
// The Welsh stage 3 is the exception when it is suppressed. A NULL last slot at or past the
// record count is our reservation; a dead stage there means the play-off was cancelled.
const walesException = (L, i) => L.wales && SUPPRESS_WALES_PLAYOFF && i === WALES_STAGE;
function leagueState(L) {
  const stages = readVec(L.act.add(0x4c), 64);
  const st = { stages, playoff: null, declined: false, reserved: -1, pendingVanilla: false, unfinished: false, leagues: [] };
  for (let i = stages.length; i < L.minStages; i++) if (!walesException(L, i)) st.pendingVanilla = true;
  stages.forEach((s, i) => {
    if (s.isNull()) {
      if (i < L.minStages) { if (!walesException(L, i)) st.pendingVanilla = true; }
      else if (i === stages.length - 1) st.reserved = i;
      else st.pendingVanilla = true;                 // GUESS: a hole past the record count is not ours
      return;
    }
    if (isDead(s)) { if (i >= L.minStages && !(L.wales && i === WALES_STAGE)) st.declined = true; return; }
    if (isPlayoffStage(s, L)) { st.playoff = { stage: s, idx: i }; return; }
    if (!stageDone(s)) st.unfinished = true;
    if (stageType(s) === 1) st.leagues.push({ stage: s, idx: i });
  });
  return st;
}

// Final table: the highest-index finished league stage with the most rows, then (not for the
// split leagues above) a later, smaller league stage whose clubs hold positions 0..k-1 (a
// championship round such as Belgium's play-off 1) re-orders those positions. Smaller stages
// elsewhere in the table (relegation rounds, Greece's 2nd-5th mini-league) are ignored.
function finalOrder(L, st) {
  let main = null, mainRows = [];
  for (const l of st.leagues) {
    const rows = leagueRows(l.stage);
    if (rows.length >= mainRows.length) { main = l; mainRows = rows; }
  }
  if (!main) return null;
  const order = mainRows.slice(), notes = [`stage ${main.idx} (${mainRows.length} rows)`];
  if (!SPLIT_CUMULATIVE_IDS.has(L.id)) {
    for (const l of st.leagues) {
      if (l.idx <= main.idx) continue;
      const rows = leagueRows(l.stage), k = rows.length;
      if (k < 2 || k >= order.length) continue;
      const pos = rows.map((t) => order.findIndex((o) => o.equals(t))).sort((a, b) => a - b);
      if (pos.every((p, i) => p === i)) { order.splice(0, k, ...rows); notes.push(`top ${k} from stage ${l.idx}`); }
    }
  }
  return { order, note: notes.join(", ") };
}

// --- Nation facts ------------------------------------------------------------------------------

function nationActs(nation) {
  const out = [];
  for (const e of readVec(COMP_MANAGER.readPointer().add(8), 4096)) {
    try { if (e.add(0xc).readPointer().equals(nation)) for (const a of readVec(e, 256)) if (!a.isNull()) out.push(a); } catch (err) {}
  }
  return out;
}
function mainCupAct(nation) {               // GUESS (F5): ACT+0x85 == 2 is the main cup
  for (const a of nationActs(nation)) { try { if (a.add(0x85).readU8() === 2) return a; } catch (e) {} }
  return null;
}
function confOf(nation) {
  try {
    const cont = nation.add(0xdc).readPointer();
    for (const c of CONFEDERATIONS) {
      const comp = compById(c.secondary);
      if (comp && comp.add(0x40).readPointer().equals(cont)) return Object.assign({ comp }, c);
    }
  } catch (e) {}
  return null;
}
// Finalists of a cup stage's last round: the status codes FM writes for a final (0x01040d44:
// winner +0x5b, loser +0x5c, or 0x1e / 0x1f when the round leaves them 0xff).
function finalResult(stage) {
  const set = stage.add(0x38).readPointer();
  if (set.isNull()) return null;
  const rs = roundsOf(set), last = rs[rs.length - 1];
  if (!last || ntms(last) !== 2) return null;
  const tie = TIE(stage, rs.length - 1, 0);
  if (tie.isNull()) return null;
  const h = tie.readS16(), a = tie.add(8).readS16(), n = stage.add(0x40).readS16();
  if (h < 0 || a < 0 || h >= n || a >= n) return null;
  const w = last.add(0x5b).readU8(), l = last.add(0x5c).readU8();
  const winCode = w === 0xff ? 0x1e : w, ruCode = l === 0xff ? 0x1f : l;
  const sh = entryStatus(stage, h), sa = entryStatus(stage, a);
  let win = -1;
  if (sh === winCode && sa !== winCode) win = h;
  else if (sa === winCode && sh !== winCode) win = a;
  else if (sh === ruCode && sa !== 0xff) win = a;
  else if (sa === ruCode && sh !== 0xff) win = h;
  else if (sh !== 0xff && sa !== 0xff && sh !== sa) {
    // Codes not as expected (live: earlier-round losers got status 0, not 0x1e): the finalist
    // whose status is not the one the other eliminated clubs carry is the winner.
    const out = new Set();
    for (let i = 0; i < n; i++) if (i !== h && i !== a && entryStatus(stage, i) !== 0xff) out.add(entryStatus(stage, i));
    if (out.has(sa) && !out.has(sh)) win = h;
    else if (out.has(sh) && !out.has(sa)) win = a;
  }
  // Every play-off status is 0 live, finalists included. FM records the decided side in the tie
  // itself: +0x30 = 0 home won, 1 away won (0x01040bb7 / 0x01040bc4, set with the result).
  if (win < 0 && sh !== 0xff && sa !== 0xff) {
    const side = tie.add(0x30).readU8();
    if (side === 0) win = h; else if (side === 1) win = a;
    if (win >= 0) log(`final winner read from the tie (side ${side})`);
  }
  if (win < 0) {
    log(`final result unreadable: final tie ${h}v${a}, statuses ${Array.from({ length: n }, (_, i) => entryStatus(stage, i).toString(16)).join(" ")}, final codes ${w.toString(16)}/${l.toString(16)}`);
    return null;
  }
  return { winner: toTeam(entryTeam(stage, win)) || entryTeam(stage, win), runnerUp: toTeam(entryTeam(stage, win === h ? a : h)) || entryTeam(stage, win === h ? a : h) };
}
// The domestic cup's state for the play-off exclusion.
function cupState(L, now) {
  const cup = mainCupAct(L.nation);
  if (!cup) return { kind: "none" };
  const comp = cup.add(0x3c).readPointer();
  const name = compName(comp);
  const stages = readVec(cup.add(0x4c), 64).filter((s) => !s.isNull() && !isDead(s) && isCupStage(s));
  const last = stages.length ? stages[stages.length - 1] : null;
  // GUESS: the cup's ACT+0x64 equals the league's for the same season.
  if (last && cup.add(0x64).readU16() === L.act.add(0x64).readU16()) {
    if (stageDone(last)) {
      const r = finalResult(last);
      if (r) return Object.assign({ kind: "decided", name, src: "this season's final" }, r);
    } else {
      const set = last.add(0x38).readPointer(), rs = set.isNull() ? [] : roundsOf(set);
      if (rs.length) {
        const fd = roundDay(rs[rs.length - 1]);
        if (now > fd + CUP_FINAL_GRACE_DAYS) return { kind: "overdue", name, finalDay: fd };
        if (fd - now <= MAX_WAIT_DAYS) return { kind: "pending", name, finalDay: fd };
      }
    }
  }
  const h = history(comp);
  return h.winner ? { kind: "decided", name, src: "last completed final (history)", winner: h.winner, runnerUp: h.runnerUp } : { kind: "unknown", name };
}
// The primary cup's title holder, once its current edition has finished (its history is then
// this season's); null while its final is still to come.
function primaryHolder(conf) {
  const comp = compById(conf.primary);
  if (!comp) return null;
  const act = comp.add(0x68).readPointer();
  if (act.isNull()) return null;
  const live = readVec(act.add(0x4c), 64).filter((s) => !s.isNull() && !isDead(s));
  if (!live.length || live.some((s) => !stageDone(s))) return null;
  return history(comp).winner || null;
}

// --- Choosing the six -----------------------------------------------------------------------

function chooseSix(L, st, conf, cup) {
  const fo = finalOrder(L, st);
  if (!fo || fo.order.length < 8) return { error: `no usable final table (${fo ? fo.order.length + " rows" : "none"})` };
  const order = fo.order;
  if (!order.some((t) => { const c = clubOfTeam(t); return c && !FIN_OF(c).isNull(); })) return { unloaded: true };
  const champion = order[0];
  let cupPlace = null, cupWhy;
  if (cup.kind === "none" || cup.kind === "unknown" || !cup.winner) {
    cupPlace = order[1];
    cupWhy = cup.kind === "none" ? "league runner-up (no cup)" : "league runner-up (no cup result)";
  } else if (sameClub(cup.winner, champion)) {
    cupPlace = cup.runnerUp || order[1];
    cupWhy = `losing ${cup.name} finalist (champion won the cup; ${cup.src})`;
  } else {
    cupPlace = cup.winner;
    cupWhy = `${cup.name} winner (${cup.src})`;
  }
  const holder = primaryHolder(conf);
  const excluded = new Set([champion, cupPlace, holder].filter((t) => t).map(clubKey).filter((k) => k));
  const six = order.filter((t) => { const k = clubKey(t); return k && !excluded.has(k); }).slice(0, 6);
  const text = `table ${fo.note}; champion ${teamName(champion)}; primary cup place ${teamName(cupPlace)} (${cupWhy}); ` +
               `${compName(compById(conf.primary))} holder ${holder ? teamName(holder) : "not decided yet / none"}`;
  if (six.length < 6) return { error: `only ${six.length} eligible clubs; ${text}` };
  return { six, text };
}

// --- Building ---------------------------------------------------------------------------------

const step = (L, what) => log(`${lname(L)}: about to ${what}`);

function walesRecord() {
  const comp = compById(WALES_COMP_ID);
  if (!comp) return null;
  const act = comp.add(0x68).readPointer();
  if (!act.isNull()) { const r = act.add(0xc).readPointer(); if (!r.isNull()) return r; }
  const r = COMP_RECORD(comp, 0);                     // GUESS: COMP@DB+0x74 record 0 when Wales has no ACT
  return r.isNull() || r.equals(EMPTY_RECORD) ? null : r;
}
function parseTemplate(L) {
  const rec = walesRecord();
  if (!rec) throw new Error("Welsh template record (comp 130672) not found");
  const n = Memory.alloc(2);
  n.writeS16(-1);
  step(L, "parse the play-off template (Wales stage 3, 0x00fb4b10)");
  const set = PARSE_SETTINGS(L.act, rec, WALES_STAGE, n);
  if (set.isNull()) throw new Error("template parse returned null");
  return set;
}

// Counts, rules, money, dates and the semi-final tie mappings. The Welsh rounds are R0 (17,
// 2 teams), R1 (18, 4 teams, mappings: tie 0 = entrant 2 v entrant 3, tie 1 = entrant 4 v winner
// of R0 tie 0), F (20). CUP_TIE_MAPPING (0x10 bytes, built by 0x011d2d00): s16 [0] target tie,
// [1] home from tie, [2] away from tie, [3]/[4] home/away outcome (0 winner), [5] home entrant,
// [6] away entrant, byte +0xe target round. Placement (0x01058a00 / 0x01059b00) reads them at
// setup and 0x0105a7c0 frees them, so they must be right before the insert.
const PLAN = [{ ntms: 4, nmxt: 4 }, { ntms: 4, nmxt: 2 }, { ntms: 2, nmxt: 0 }];
function editSettings(L, set, dayBase) {
  const rs = roundsOf(set);
  if (rs.length !== 3) throw new Error(`template has ${rs.length} rounds, 3 expected`);
  rs.forEach((r, i) => {
    r.add(0x1c).writeS16(PLAN[i].ntms);
    r.add(0x1e).writeS16(PLAN[i].ntms >> 1);
    r.add(0x20).writeS16(PLAN[i].nmxt);
    r.add(0x2c).writeU8(1);                                     // one match
    r.add(0x2b).writeU8(0);                                     // no replay
    r.add(0x1b).writeU8(ROUND_PRIORITY);                        // no international-date test
    r.add(0x1a).writeU8(r.add(0x1a).readU8() & ~3);
    for (const m of [0x18, 0x26, 0x28]) r.add(m).writeU16((r.add(m).readU16() & ~MATCH_CLEAR) | 0x3); // extra time + penalties
    r.add(0x10).writeU64(r.add(0x10).readU64().and(uint64(0x1000000)).or(0x408)); // fixed draw + higher seed at home
    for (let o = 0x3c; o <= 0x50; o += 4) r.add(o).writeS32(0);  // no round money
    if (dayBase !== null) { setRoundDay(r, dayBase + ROUND_OFFSETS[i]); setDrawDay(r, dayBase + DRAW_OFFSETS[i]); }
  });
  const oldN = set.add(0x10).readS16();
  set.add(0x10).writeS16(6);                                    // GUESS: settings team count (0x0103ded0 writes the entrant count here)
  const maps = readVec(set.add(0x38), 64);
  const f = (p, i) => p.add(2 * i).readS16();
  const home0 = maps.find((p) => p.add(0xe).readU8() === 1 && f(p, 0) === 0 && f(p, 5) === 2);
  const away0 = maps.find((p) => p.add(0xe).readU8() === 1 && f(p, 0) === 0 && f(p, 6) === 3);
  const home1 = maps.find((p) => p.add(0xe).readU8() === 1 && f(p, 0) === 1 && f(p, 5) === 4);
  const away1 = maps.find((p) => p.add(0xe).readU8() === 1 && f(p, 0) === 1 && f(p, 2) === 0);
  if (!home0 || !away0 || !home1 || !away1) {
    throw new Error(`template tie mappings not as expected (${maps.length}: ` +
      maps.map((p) => `r${p.add(0xe).readU8()}:${[0, 1, 2, 3, 4, 5, 6].map((i) => f(p, i)).join("/")}`).join(" ") + ")");
  }
  home0.add(10).writeS16(4);                                    // SF tie 0 home: P1 (entrant 4)
  away0.add(12).writeS16(-1); away0.add(2).writeS16(-1);        // SF tie 0 away: winner of QF tie 0
  away0.add(4).writeS16(0); away0.add(6).writeS16(0); away0.add(8).writeS16(0);
  home1.add(10).writeS16(5);                                    // SF tie 1 home: P2 (entrant 5)
  away1.add(4).writeS16(1);                                     // SF tie 1 away: winner of QF tie 1
  const rl = readVec(set.add(0x44), 64).length;                 // per-team ranking overrides (0x01054650)
  if (rl) { set.add(0x48).writePointer(set.add(0x44).readPointer()); }   // GUESS: emptied (entries leaked)
  return `team count ${oldN} -> 6, ranking overrides ${rl}, date slots ${rs.map((r) => readVec(r.add(0x64), 64).length).join("/")}`;
}
// After setup (and whenever the stage is set up again): no ranking levels, so the play-off never
// rewrites the league's season ranking (0x01044c00 / 0x01044b00 skip 0xff), and no round money
// (setup's 0x0104d710 puts a default final prize on single-stage competitions).
function enforce(stage) {
  const set = stage.add(0x38).readPointer();
  if (set.isNull()) return;
  for (const r of roundsOf(set)) {
    for (let o = 0x5b; o <= 0x60; o++) r.add(o).writeU8(0xff);
    for (let o = 0x3c; o <= 0x50; o += 4) r.add(o).writeS32(0);
  }
}

function insertDead(act, idx) {
  const d = OPERATOR_NEW(0x3c);
  if (d.isNull()) throw new Error("operator new failed");
  STAGE_BASE_CTOR(d, idx, NULL);
  d.writePointer(DEAD_STAGE_VT);
  d.add(0x38).writePointer(NULL);
  return (STAGE_INSERT(act, d, 0) & 0xff) === 1;
}
// Cancel: fill the reserved slot with a dead stage (FM's own placeholder) and mark activity so the
// league's completeness check runs again on the next daily step (comp_finish.md 3.3).
function cancel(L, idx, why) {
  log(`${lname(L)}: play-off cancelled (${why}); the secondary cup entrant falls back to the best-placed eligible club`);
  if (idx < 0) return;
  step(L, `insert a dead stage in reserved slot ${idx}`);
  const ok = insertDead(L.act, idx);
  L.act.add(0x84).writeU8(1);
  log(`${lname(L)}: dead stage ${idx} ${ok ? "inserted" : "insert returned 0 (CHECK: the league may not finish)"}`);
}

function build(L, st, six, text) {
  const idx = st.reserved >= 0 ? st.reserved : Math.max(L.minStages, st.stages.length, L.wales ? WALES_STAGE + 1 : 1);
  const D = todayNum();
  let set = null;
  try {
    set = parseTemplate(L);
    step(L, "edit the template rounds and tie mappings");
    const note = editSettings(L, set, D);
    log(`${lname(L)}: template edited (${note})`);
  } catch (e) {
    if (set) { try { step(L, "free the unused template"); vfn(set, 0, "void", ["int"])(set, 1); } catch (e2) {} }
    cancel(L, st.reserved, `template: ${e.message}`);
    return;
  }
  const entrants = [six[2], six[5], six[3], six[4], six[0], six[1]];
  const seeds = [3, 6, 4, 5, 1, 2];                // GUESS: seed byte = rank, 1 best (Wales seeding [5,4,3,2,1] on worst-first entrants)
  const v = agentVec(entrants);
  let inserted = false;
  try {
    step(L, `allocate and construct the play-off stage ${idx}`);
    const s = OPERATOR_NEW(0x48);
    if (s.isNull()) throw new Error("operator new failed");
    STAGE_BASE_CTOR(s, idx, NULL);
    s.writePointer(CUP_STAGE_VT);
    for (const off of [0x38, 0x3c, 0x44]) s.add(off).writePointer(NULL);
    step(L, "fill the six entrants (0x0103ebb0)");
    CUP_ENTRANTS(s, v.vec, NULL, 0, 0);
    const table = s.add(0x3c).readPointer();
    seeds.forEach((k, i) => table.add(12 * i + 4).writeU8(k));
    s.add(0x38).writePointer(set);                 // CUP_STAGE::setup 0x0103dca0 skips ACT vt+0x30 when set
    set = null;
    step(L, `insert and set up play-off stage ${idx} (0x00fa0e60)`);
    inserted = (STAGE_INSERT(L.act, s, 0) & 0xff) === 1;
    if (!inserted) throw new Error("stage insert/setup returned 0 (FM deleted the stage)");
    enforce(s);
    const draws = fixDrawDays(s);
    const rs = roundsOf(s.add(0x38).readPointer());
    log(`${lname(L)}: play-off draw dates after setup: ${draws}`);
    const tieText = (r, t) => { const x = TIE(s, r, t); return x.isNull() ? "-" : `${x.readS16()}v${x.add(8).readS16()}`; };
    log(`${lname(L)}: play-off stage ${idx} built. ${text}. Seeds ${six.map((t, i) => `P${i + 1} ${teamName(t)}`).join(", ")}. ` +
        `Dates ${rs.map((r) => ymd(roundDay(r)).iso).join(" / ")} (priority/check mode ${rs.map((r) => `${r.add(0x1b).readU8()}/${r.add(0x2e).readU8()}`).join(" ")}); ties QF ${tieText(0, 0)} ${tieText(0, 1)}, SF ${tieText(1, 0)} ${tieText(1, 1)} ` +
        `(entrants 0-5 = P3 P6 P4 P5 P1 P2; SF away = QF winners)`);
  } catch (e) {
    if (set) { try { vfn(set, 0, "void", ["int"])(set, 1); } catch (e2) {} }
    log(`${lname(L)}: build failed: ${e.message}`);
    if (!inserted) {
      // A failed setup leaves slot idx NULL (0x00fa0fdc..0x00fa1018), which would keep the league open forever.
      const now = readVec(L.act.add(0x4c), 64);
      if (idx < now.length && now[idx].isNull()) cancel(L, idx, "build failed");
    }
  }
}

// --- Evaluation (league stage end, cup finish, periodic scan) -------------------------------

const lastNote = new Map();
function note(L, key, line) {                       // log a waiting/decline line once per state
  const k = L.act.toString() + ":" + L.act.add(0x64).readU16();
  if (lastNote.get(k) === key) return;
  lastNote.set(k, key);
  log(`${lname(L)}: ${line}`);
}

function evaluate(L, why) {
  if (!BUILD_ENABLED) return;
  const st = leagueState(L);
  if (st.playoff || st.declined || st.unfinished || st.pendingVanilla || !st.leagues.length) return;
  const conf = confOf(L.nation);
  if (!conf) { if (why === "stage end") note(L, "noconf", "no secondary continental cup for this confederation, no play-off"); return; }
  const fo = finalOrder(L, st);
  if (!fo || !fo.order.some((t) => { const c = clubOfTeam(t); return c && !FIN_OF(c).isNull(); })) {
    if (st.reserved >= 0) cancel(L, st.reserved, "nation not loaded");
    return;                                          // unloaded nation: reputation pick at the cup's build
  }
  const now = todayNum();
  const cup = cupState(L, now);
  if (cup.kind === "pending") {
    if (st.reserved < 0) {
      const idx = Math.max(L.minStages, st.stages.length, L.wales ? WALES_STAGE + 1 : 1);
      step(L, `reserve stage slot ${idx} while waiting for the ${cup.name} final`);
      VEC_RESIZE(L.act.add(0x4c), idx + 1);
    }
    note(L, "wait", `league finished; waiting for the ${cup.name} final (${ymd(cup.finalDay).iso}) before the play-off (${why})`);
    return;
  }
  if (cup.kind === "overdue") { cancel(L, st.reserved, `${cup.name} final of ${ymd(cup.finalDay).iso} not played`); return; }
  const pick = chooseSix(L, st, conf, cup);
  if (pick.unloaded) { if (st.reserved >= 0) cancel(L, st.reserved, "nation not loaded"); return; }
  if (pick.error) {
    if (st.reserved >= 0) cancel(L, st.reserved, pick.error);
    else note(L, "err", `no play-off: ${pick.error}`);
    return;
  }
  // Clear any earlier winner marker of this nation's league clubs: a new play-off is starting.
  clearMarkers(st);
  build(L, leagueState(L), pick.six, pick.text);
}

function clearMarkers(st) {
  for (const l of st.leagues) {
    for (const t of leagueRows(l.stage)) {
      try {
        const ext = t.add(0x54).readPointer();
        if (!ext.isNull() && (ext.add(0xa6).readU8() & 0xf0) === TAG_BASE) { ext.add(0xa6).writeU8(0); ext.add(0x7c).writePointer(NULL); }
      } catch (e) {}
    }
  }
}

let lastScan = -1;
function scanWaiting(force) {
  if (!BUILD_ENABLED) return;                        // it only calls evaluate(), which then does nothing
  const now = todayNum();
  if (!force && now === lastScan) return;
  lastScan = now;
  for (const e of readVec(COMP_MANAGER.readPointer().add(8), 4096)) {
    let acts;
    try { acts = readVec(e, 256); } catch (err) { continue; }
    for (const a of acts) {
      const L = leagueInfo(a);
      if (!L) continue;
      try {
        const b = L.act.add(0x4c).readPointer(), n = b.isNull() ? 0 : L.act.add(0x50).readPointer().sub(b).toInt32() / 4;
        if (n === 0 || n - 1 < L.minStages || !b.add(4 * (n - 1)).readPointer().isNull()) continue;   // cheap: no reservation
        const st = leagueState(L);
        if (st.reserved >= 0 && !st.playoff && !st.declined) evaluate(L, "scan");
      } catch (err) { log(`scan error ${err.stack}`); }
    }
  }
}

// --- Result: the winner marker at the league's finish ----------------------------------------

function onLeagueFinished(L) {
  const st = leagueState(L);
  if (!st.playoff) return;
  const s = st.playoff.stage;
  const r = stageDone(s) ? finalResult(s) : null;
  if (!r) { log(`${lname(L)}: league finished but the play-off stage ${st.playoff.idx} has no winner (CHECK)`); return; }
  const conf = confOf(L.nation);
  if (!conf) return;
  const rs = roundsOf(s.add(0x38).readPointer());
  const target = targetSeason(roundDay(rs[rs.length - 1]), conf);
  const sec = conf.comp.add(0x68).readPointer();
  let built = false;
  try {
    built = !sec.isNull() && sec.add(0x64).readU16() === target &&
            readVec(sec.add(0x4c), 64).some((x) => !x.isNull() && !isDead(x));     // GUESS: ACT+0x64 = edition year
  } catch (e) {}
  if (built) {
    log(`${lname(L)}: play-off won by ${teamName(r.winner)}, but ${compName(conf.comp)} ${target} is already built: no marker (the entrant was the fallback)`);
    return;
  }
  clearMarkers(st);
  const ext = r.winner.add(0x54).readPointer();
  if (ext.isNull()) { log(`${lname(L)}: play-off winner ${teamName(r.winner)} has no continental record (+0x54), no marker`); return; }
  ext.add(0x7c).writePointer(conf.comp);
  ext.add(0xa6).writeU8(TAG_BASE | (target & 0xf));
  log(`${lname(L)}: play-off final won by ${teamName(r.winner)} (runner-up ${teamName(r.runnerUp)}); marker written for ${compName(conf.comp)} ${target} (tag 0x${(TAG_BASE | (target & 0xf)).toString(16)})`);
}

// --- Re-seeding the semi-finals (P1 meets the lowest-ranked survivor) -------------------------
// QF0 = entrants 0 (P3) v 1 (P6). If P3 won, P1 must meet the QF1 winner: swap the SF home
// entrants (P1 <-> P2) while both semi-finals are unplayed. Ties hold entrant indices
// (0x01059b00 writes them), the QF winners arrive in the away slots through the setup links.
// GUESS: the SF fixtures are created at the SF draw (template draw date: the day after the QF).
function reseed(stage) {
  const set = stage.add(0x38).readPointer();
  if (set.isNull()) return;
  const rs = roundsOf(set);
  if (rs.length !== 3 || (rs[1].add(0x58).readU8() & 4)) return;
  const p3 = entryStatus(stage, 0), p6 = entryStatus(stage, 1);
  if (!(p3 === 0xff && p6 !== 0xff)) return;                    // P3 still in and P6 out: P3 won QF0
  const t0 = TIE(stage, 1, 0), t1 = TIE(stage, 1, 1);
  if (t0.isNull() || t1.isNull() || t0.readS16() !== 4 || t1.readS16() !== 5) return;  // done already, or not as built
  if (entryStatus(stage, 4) !== 0xff || entryStatus(stage, 5) !== 0xff) return;
  const owner = stage.add(0x28).readPointer();
  log(`${compName(owner)}: about to re-seed the play-off semi-finals (P3 ${teamName(entryTeam(stage, 0))} won QF0)`);
  t0.writeS16(5); t1.writeS16(4);
  const s0 = t0.add(0x35).readU8(); t0.add(0x35).writeU8(t1.add(0x35).readU8()); t1.add(0x35).writeU8(s0);
  log(`${compName(owner)}: semi-finals re-seeded: P1 ${teamName(entryTeam(stage, 4))} v winner of QF1, P2 ${teamName(entryTeam(stage, 5))} v ${teamName(entryTeam(stage, 0))}`);
}
function playoffOwner(stage) {                 // the league info when stage is our play-off stage
  try {
    if (stage.isNull() || !isCupStage(stage) || stage.add(0x40).readS16() !== 6) return null;
    const comp = stage.add(0x28).readPointer();
    const L = leagueInfo(comp.add(0x68).readPointer());
    return L && isPlayoffStage(stage, L) ? L : null;
  } catch (e) { return null; }
}

// --- Monthly progress / stall check --------------------------------------------------------------

function monthly() {
  scanWaiting(true);
  const now = todayNum();
  for (const e of readVec(COMP_MANAGER.readPointer().add(8), 4096)) {
    let acts;
    try { acts = readVec(e, 256); } catch (err) { continue; }
    for (const a of acts) {
      const L = leagueInfo(a);
      if (!L) continue;
      try {
        const st = leagueState(L);
        if (!st.playoff) continue;
        const s = st.playoff.stage, set = s.add(0x38).readPointer();
        const statuses = [0, 1, 2, 3, 4, 5].map((i) => entryStatus(s, i).toString(16)).join(" ");
        const rs = set.isNull() ? [] : roundsOf(set);
        const fd = rs.length ? roundDay(rs[rs.length - 1]) : now;
        const done = stageDone(s);
        log(`progress: ${lname(L)} play-off stage ${st.playoff.idx} ${done ? "finished" : "running"}, statuses ${statuses}` +
            (!done && now > fd + STALL_DAYS ? ` STALLED (final was due ${ymd(fd).iso}; the league cannot finish or restart until it ends)` : ""));
      } catch (err) { log(`progress error ${err.stack}`); }
    }
  }
}

// --- Hooks ------------------------------------------------------------------------------------

function install() {
  if (!PLAYOFF_ENABLED) { log("play-off off (PLAYOFF_ENABLED false): every nation uses the fallback rule"); return; }

  // Stage finished (thiscall (ACT; stage) ret 4), called from the daily comp step at 0x00facca3.
  // It only starts new play-offs (evaluate, scanWaiting), so it is not attached while they are off.
  if (!BUILD_ENABLED) log("stage-finished hook 0x00fb5370 not attached (new play-offs off)");
  else log("about to attach the stage-finished hook 0x00fb5370");
  if (BUILD_ENABLED) Interceptor.attach(va(0x00fb5370), {
    onEnter(args) { this.act = this.context.ecx; },
    onLeave() {
      try {
        const L = leagueInfo(this.act);
        if (L) evaluate(L, "stage end");
        scanWaiting(false);
      } catch (e) { log("stage-end error " + e.stack); }
    },
  });

  // Competition finished (ECX = ACT): league -> winner marker; domestic main cup -> waiting
  // leagues of that nation. Also hooked by parity_agent.js and parity_continental.js.
  log("about to attach the competition-finished hook 0x00fad710");
  Interceptor.attach(va(0x00fad710), {
    onEnter() { this.act = this.context.ecx; },
    onLeave() {
      try {
        const L = leagueInfo(this.act);
        if (L) { onLeagueFinished(L); return; }
        if (!BUILD_ENABLED) return;                // the rest only feeds evaluate(), off with new play-offs
        if (this.act.add(0x85).readU8() === 2) {
          const nation = this.act.add(0x3c).readPointer().add(0x44).readPointer();
          if (!nation.isNull()) for (const a of nationActs(nation)) { const M = leagueInfo(a); if (M) evaluate(M, "cup final"); }
        }
        scanWaiting(false);
      } catch (e) { log("competition-finished error " + e.stack); }
    },
  });

  // Cup stage setup (fastcall ECX = CUP_STAGE): keep levels and money off whenever our stage is
  // set up (initial build, and any re-setup after a load).
  log("about to attach the cup-stage setup hook 0x0103dca0");
  Interceptor.attach(va(0x0103dca0), {
    onEnter() { this.s = this.context.ecx; },
    onLeave() { try { if (playoffOwner(this.s)) enforce(this.s); } catch (e) { log("setup hook error " + e.stack); } },
  });

  if (RESEED_ENABLED) {
    // CUP_STAGE vt+8 (thiscall (stage; fixture, ...) ret 0x14): one call per cup result. Function
    // entry and exit only; the body is never hooked (a mid-function hook here crashed, test5).
    log("about to attach the cup-result hook 0x01040310 (re-seeding)");
    Interceptor.attach(va(0x01040310), {
      onEnter() { this.s = this.context.ecx; },
      onLeave() {
        try {
          const L = playoffOwner(this.s);
          if (!L) return;
          // The real match day (the "won by" line only comes at league finish).
          log(`${lname(L)}: play-off result recorded, statuses ${[0, 1, 2, 3, 4, 5].map((i) => entryStatus(this.s, i).toString(16)).join(" ")}`);
          reseed(this.s);
        } catch (e) { log("re-seed error " + e.stack); }
      },
    });
  }

  if (LOAD_GUARD_ENABLED) {
    // GUESS (L2): if a loaded play-off stage re-parses its settings through its league's vt+0x30,
    // the league record has no such stage; redirect the parse to the Welsh template and edit it.
    log("about to attach the settings-parse guard 0x00fb4b10");
    Interceptor.attach(va(0x00fb4b10), {
      onEnter(args) {
        this.fix = null;
        try {
          const L = leagueInfo(this.context.ecx);
          if (!L) return;
          const idx = args[1].toInt32() & 0xff, stages = readVec(L.act.add(0x4c), 64);
          const s = idx < stages.length ? stages[idx] : NULL;
          if (s.isNull() || !isCupStage(s) || !s.add(0x38).readPointer().isNull() || s.add(0x40).readS16() !== 6 || idx < Math.max(1, L.minStages)) return;
          const rec = walesRecord();
          if (!rec) return;
          args[0] = rec;
          args[1] = ptr(WALES_STAGE);
          this.fix = L;
          log(`${lname(L)}: settings re-parse of play-off stage ${idx} redirected to the Welsh template (L2: CHECK this load)`);
        } catch (e) { log("parse guard error " + e.stack); }
      },
      onLeave(ret) {
        if (!this.fix || ret.isNull()) return;
        try { log(`${lname(this.fix)}: re-parsed template edited, dates left as parsed (${editSettings(this.fix, ret, null)})`); } catch (e) { log("parse guard edit error " + e.stack); }
      },
    });
  }

  if (SUPPRESS_WALES_PLAYOFF) {
    // WAL_PRM vt+0x24 (thiscall (ACT; char stage, vector<TEAM*>*) ret 8): for stage 3 do what it
    // does itself when Wales has too many places: insert a dead stage 3 and return 0.
    log("about to replace the Welsh play-off team supply 0x0117dfc0");
    const orig = new NativeFunction(va(0x0117dfc0), "uint32", ["pointer", "int", "pointer"], "thiscall");
    const cb = new NativeCallback(function (act, idx, vec) {
      let done = false;
      try {
        if ((idx & 0xff) === WALES_STAGE) {
          const stages = readVec(act.add(0x4c), 64);
          if (stages.length <= WALES_STAGE || stages[WALES_STAGE].isNull()) {
            log("Wales: about to insert a dead stage 3 in place of the vanilla play-off");
            insertDead(act, WALES_STAGE);
          }
          done = true;
          log("Wales: vanilla Europa League play-off (stage 3) suppressed");
        }
      } catch (e) { log("Wales suppression error " + e.stack); }
      return done ? 0 : orig(act, idx, vec);
    }, "uint32", ["pointer", "int", "pointer"], "thiscall");
    install.keep = cb;
    Interceptor.replace(va(0x0117dfc0), cb);
  }

  log("about to attach the month-start hook 0x0063e9b8");
  Interceptor.attach(va(0x0063e9b8), { onEnter() { try { monthly(); } catch (e) { log("monthly error " + e.stack); } } });
  log("play-off hooks installed");
}

recv("config", (msg) => {
  try { logFile = new File(msg.log, "a"); } catch (e) {}
  log(`parity play-off agent started (play-off ${PLAYOFF_ENABLED ? "on" : "off"}, new play-offs ${BUILD_ENABLED ? "on" : "off"}, Wales suppression ${SUPPRESS_WALES_PLAYOFF}, re-seeding ${RESEED_ENABLED}, load guard ${LOAD_GUARD_ENABLED})`);
  try { install(); } catch (e) { log("installation error, play-off inactive: " + e.stack); }
  send({ started: true });
});
