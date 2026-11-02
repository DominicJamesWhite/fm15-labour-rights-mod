// Frida agent: read-only squad snapshot of clubs found by name, for the nostalgia foreign-player work
// (reports/foreign_cap). Run with tools/squad_snapshot.py.
//
// Safety: every game function is called on the game's own thread, inside a one-shot hook on the squad
// counter FUN_00f8c610 (called many times a day for every club), and only getters are called
// (name formatting into a private text object, the foreign/homegrown tests, value/age/contract
// getters, the release-cost calculator FUN_0047ca40, which only computes). Nothing is written to
// game memory. NativeFunction calls use Frida's default exception handling ("steal"), so an access
// violation inside a call becomes a JS error instead of crashing the game.

const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);

const TEXT_CTOR = new NativeFunction(va(0x0188f4b0), "pointer", ["pointer"], "thiscall");
const TEXT_SET = new NativeFunction(va(0x0188fd00), "void", ["pointer", "pointer"], "thiscall");
const TEXT_ARG = new NativeFunction(va(0x01493e80), "void", ["pointer", "int", "pointer", "int", "int", "pointer"], "thiscall");
const TEXT_RENDER = new NativeFunction(va(0x01890790), "pointer", ["pointer"], "thiscall");
const TEXT_DTOR = new NativeFunction(va(0x0188fc80), "void", ["pointer"], "thiscall");
const EMPTY = va(0x02426d58);
const IS_FOREIGN = new NativeFunction(va(0x015440e0), "uint8", ["pointer", "pointer", "int", "int"], "thiscall");
const HOMEGROWN = new NativeFunction(va(0x016033c0), "uint32", ["pointer", "pointer", "int"], "thiscall");
const PAYOUT = new NativeFunction(va(0x0047ca40), "int", ["pointer"]);
const TODAY = va(0x0239ebf4);
const AGE_DATE = va(0x023a01c4);

let targets = [];
let done = {};
let debugOnce = true;

function vfn(obj, off, ret, args) {
  return new NativeFunction(obj.readPointer().add(off).readPointer(), ret, ["pointer"].concat(args || []), "thiscall");
}

function decode(p) {
  // The rendered text object holds a pointer to the string buffer at +0. Try the likely encodings.
  if (p.isNull()) return "";
  const b0 = p.readU8();
  const candidates = [];
  try { candidates.push(p.readUtf8String()); } catch (e) {}
  try { candidates.push(p.add(1).readUtf8String()); } catch (e) {}
  try { candidates.push(p.readUtf16String()); } catch (e) {}
  try { candidates.push(p.add(2).readUtf16String()); } catch (e) {}
  try { candidates.push(p.add(4).readUtf16String()); } catch (e) {}
  const good = candidates.filter((s) => s && /^[\p{L}\p{M} .,'\-()&0-9]{2,60}$/u.test(s));
  if (debugOnce) {
    debugOnce = false;
    send({ debug: "string buffer bytes: " + hexdump(p, { length: 48, header: false, ansi: false }) + " b0=" + b0 + " candidates=" + JSON.stringify(candidates) });
  }
  return good.length ? good.sort((a, c) => c.length - a.length)[0] : "?" + (candidates[0] || "");
}

function fmt(format, obj) {
  const text = Memory.alloc(0x100);
  TEXT_CTOR(text);
  TEXT_SET(text, Memory.allocUtf8String(format));
  TEXT_ARG(text, 1, obj, 0, 0, EMPTY);
  const r = TEXT_RENDER(text);
  const s = decode((r.isNull() ? text : r).readPointer());
  TEXT_DTOR(text);
  return s;
}

function vbase(p) {
  const vb = p.add(4).readPointer();
  return p.add(4).add(vb.add(4).readS32());
}

function dateStr(word0, year) {
  const doy = (word0 & 0x1ff);
  const d = new Date(Date.UTC(year, 0, doy));
  return d.toISOString().slice(0, 10);
}

function contractDates(c) {
  // Dates are {u16 day-of-year (low 9 bits) | flags, u16 year}; list plausible ones in the contract.
  const out = [];
  for (let off = 0; off < 0x70; off += 2) {
    const w0 = c.add(off).readU16();
    const y = c.add(off + 2).readU16();
    const doy = w0 & 0x1ff;
    if (y >= 1990 && y <= 2040 && doy >= 1 && doy <= 366) out.push("+" + off.toString(16) + ":" + dateStr(w0, y));
  }
  return out.join(" ");
}

function snapshot(team, label) {
  const club = team.add(0x10).readPointer();
  const lines = [];
  const players = [];
  const today = dateStr(TODAY.readU16(), TODAY.add(2).readU16());
  lines.push(label + " (team " + fmt("<%team#1>", team) + "), snapshot " + today);
  const vectors = [[0x10, 0x14], [0x1c, 0x20]];
  for (const [b, e] of vectors) {
    const begin = club.add(b).readPointer();
    const end = club.add(e).readPointer();
    for (let t = begin; t.compare(end) < 0; t = t.add(4)) {
      const tm = t.readPointer();
      if (tm.isNull()) continue;
      const tname = fmt("<%team#1>", tm);
      const pb = tm.add(0x24).readPointer();
      const pe = tm.add(0x28).readPointer();
      for (let q = pb; q.compare(pe) < 0; q = q.add(4)) {
        const p = q.readPointer();
        if (p.isNull()) continue;
        const r = { team: tname, first: tm.equals(team) };
        try {
          const person = vbase(p);
          r.name = fmt("<%person#1>", person);
          const nation = vfn(person, 0x11c, "pointer")(person);
          r.nation = nation.isNull() ? "-" : fmt("<%nation#1>", nation);
          const others = [];
          const n = vfn(person, 0x184, "uint32")(person);
          for (let i = 0; i < n && i < 6; i++) {
            const e = vfn(person, 0x180, "pointer", ["uint32"])(person, i);
            if (e.isNull()) continue;
            const nat = e.readPointer();
            const ty = e.add(7).readU8();
            if (ty === 7 || ty === 8 || ty === 9 || ty === 0x65) others.push(nat.isNull() ? "-" : fmt("<%nation#1>", nat));
          }
          r.other = others.join(",");
          r.age = vfn(person, 0xd0, "int8", ["pointer"])(person, AGE_DATE);
          r.foreign = IS_FOREIGN(person, team, 1, 1) ? 1 : 0;
          r.homegrown = HOMEGROWN(p, team, 0) & 0xff;
          r.value = p.add(0xb4).readU32() ? p.add(0xc0).readS32() : 0;
          r.ca = vfn(p, 0x0, "uint16")(p);          // current ability (player vfunc +0, a getter)
          r.skipRetired = vfn(person, 0x2bc, "uint8")(person) & 1;
          r.skipAway = vfn(p, 0x16c, "uint8", ["int", "int"])(p, 0, 0) & 1;
          r.pendingMove = vfn(p, 0xe8, "uint8", ["pointer", "pointer"])(p, ptr(0), ptr(0)) & 1;
          const c = vfn(person, 0x1d8, "pointer")(person);
          if (!c.isNull()) {
            r.status = c.add(0x30).readU8();
            r.listed = c.add(0x32).readU8();
            r.ctype = vfn(c, 0x1c, "uint8")(c);
            r.dates = contractDates(c);
            const j = c.add(0x28);
            r.joined = dateStr(j.readU16(), j.add(2).readU16());
            r.ownContract = c.add(8).readPointer().equals(team);  // contract with this club (not a loan in)
          }
          r.rest = PAYOUT(person);
        } catch (e) {
          r.error = String(e);
        }
        players.push(r);
      }
    }
  }
  // Surplus ranking (nostalgia_foreign_cap_ai): senior foreigners (21+) counted as the game counts them
  // (not retired-like, not away), ranked by current ability; the best 3 stay, the rest are surplus.
  const counted = players.filter((r) => r.foreign && r.age >= 21 && !r.skipRetired && !r.skipAway);
  counted.sort((a, b) => b.ca - a.ca);
  counted.forEach((r, i) => (r.rank = i + 1));
  const keep = 3;
  const statusName = { 1: "Key", 2: "FirstTeam", 3: "Rotation", 4: "Backup", 5: "HotProspect", 6: "Youngster", 7: "NotNeeded" };
  lines.push("");
  lines.push("team | name | age | nation (other nationalities) | foreign | homegrown | CA | value | status | +0x32 flags | ctype | rest-of-contract wages | senior foreign rank (by CA) | flags | contract dates");
  players.sort((a, b) => (b.foreign - a.foreign) || (b.value - a.value));
  for (const r of players) {
    if (r.error) { lines.push(r.team + " | ERROR " + r.error); continue; }
    const fl = [r.skipRetired ? "retired?" : "", r.skipAway ? "away/loan" : "", r.pendingMove ? "move-arranged" : ""].filter(Boolean).join(",");
    lines.push([r.team, r.name, r.age, r.nation + (r.other ? " (" + r.other + ")" : ""), r.foreign ? "FOREIGN" : "domestic",
      r.homegrown ? "hg" + r.homegrown : "-", r.ca, r.value, (statusName[r.status] || r.status), "0x" + (r.listed || 0).toString(16),
      r.ctype, r.rest, r.rank ? (r.rank <= keep ? "#" + r.rank + " keep" : "#" + r.rank + " SURPLUS") : (r.foreign && r.age < 21 ? "junior" : ""), fl, r.dates].join(" | "));
  }
  const dom = players.filter((r) => !r.error && !r.foreign);
  const domSenior = dom.filter((r) => r.age >= 18 && !r.skipAway && !r.skipRetired);
  const forn = players.filter((r) => r.foreign);
  const firstDom = players.filter((r) => !r.error && r.first && !r.foreign && !r.skipAway && !r.skipRetired);
  const seasonStart = (TODAY.add(2).readU16() - ((TODAY.readU16() & 0x1ff) < 182 ? 1 : 0)) + "-06-01";
  const newForeign = forn.filter((r) => r.joined && r.joined >= seasonStart);
  lines.push("");
  lines.push("summary: " + players.length + " players; domestic " + dom.length + " (18+ and at the club: " + domSenior.length +
    "); foreign " + forn.length + " (counted " + counted.length + ", homegrown-in-nation " + forn.filter((r) => r.homegrown).length +
    "); keep " + keep + ", surplus beyond it: " + Math.max(0, counted.length - keep) + "; listed (+0x32 bit0): " + players.filter((r) => r.listed & 1).length +
    ", loan-listed (bit3): " + players.filter((r) => r.listed & 8).length + ", marked (bit7): " + players.filter((r) => r.listed & 0x80).length);
  const stray = counted.filter((r) => r.rank > keep && (r.listed & 1) && r.status !== 7);
  lines.push("listed surplus foreigners not Not Needed (should be none with the status hook): " + stray.length +
    (stray.length ? " (" + stray.map((r) => r.name + " " + (statusName[r.status] || r.status)).join(", ") + ")" : ""));
  lines.push("first team: " + players.filter((r) => r.first && !r.error).length + " players, domestic " + firstDom.length +
    " (" + firstDom.map((r) => r.name).join(", ") + ")");
  lines.push("best 3 senior foreigners by CA: " + counted.slice(0, 3).map((r) => r.name + " (" + r.ca + ")").join(", "));
  // Anti-churn (nostalgia_foreign_cap_ai): seniors with a contract at this club, not listed "Not Needed"
  const todayDays = (TODAY.add(2).readU16() * 365) + (TODAY.readU16() & 0x1ff);
  const churnSeniors = counted.filter((r) => r.ownContract && !((r.listed & 1) && r.status === 7));
  const recent = churnSeniors.filter((r) => r.joined && (todayDays - (Number(r.joined.slice(0, 4)) * 365 +
    Math.round((Date.parse(r.joined) - Date.UTC(Number(r.joined.slice(0, 4)), 0, 1)) / 86400000) + 1)) < 365);
  const last = churnSeniors.filter((r) => r.joined).sort((a, b) => (a.joined < b.joined ? 1 : -1))[0];
  lines.push("last senior foreign arrival: " + (last ? last.name + " " + last.joined : "none") + "; anti-churn: " +
    churnSeniors.length + " senior foreigners (own contract, not listed Not Needed), " + recent.length +
    " joined within 365 days -> foreign targets " + (churnSeniors.length >= 3 && recent.length ? "DROPPED" : "allowed"));
  // Upgrade condition: a foreign target must have a CA above the 3rd-best senior foreigner (any CA if < 3).
  lines.push("upgrade bar for foreign targets: " + (counted.length >= 3 ? "CA > " + counted[2].ca + " (" + counted[2].name + ")" : "none (< 3 senior foreigners)"));
  lines.push("foreigners who joined since " + seasonStart + " (contract +0x28 date): " +
    (newForeign.map((r) => r.name + " " + r.joined + " value " + r.value + " rank #" + (r.rank || "-")).join("; ") || "none"));
  return lines.join("\n");
}

// Clubs: the database's club table (FUN_01558e70: [[0x02428ee0]+0x14] +0x34..+0x38), entries are
// clubs whose first team is the first element of their +0x10 team vector.
const DB = va(0x02428ee0);
let busy = false;
function scan() {
  const db = DB.readPointer();
  const table = db.add(0x14).readPointer();
  let begin = table.add(0x34).readPointer();
  let end = table.add(0x38).readPointer();
  const alt = table.add(0x40).readPointer();
  send({ debug: "club table: flag " + db.add(0x1a8).readU8() + ", main " + (end.sub(begin).toInt32() >> 2) +
    ", alt " + (alt.isNull() ? "null" : (alt.add(4).readPointer().sub(alt.readPointer()).toInt32() >> 2)) });
  if (db.add(0x1a8).readU8() !== 0 || end.sub(begin).toInt32() === 0) {
    begin = alt.readPointer();
    end = alt.add(4).readPointer();
  }
  let named = 0;
  for (let c = begin; c.compare(end) < 0 && targets.some((t) => !done[t]); c = c.add(4)) {
    const club = c.readPointer();
    if (club.isNull()) continue;
    const tb = club.add(0x10).readPointer();
    if (tb.isNull() || tb.equals(club.add(0x14).readPointer())) continue;
    const team = tb.readPointer();
    if (team.isNull() || team.add(0x23).readU8() !== 0) continue;
    const name = fmt("<%team#1>", team);
    if (named++ < 3) send({ debug: "club seen: " + name });
    const hit = targets.find((t) => !done[t] && name.toLowerCase() === t.toLowerCase());
    if (hit) {
      done[hit] = true;
      send({ club: hit, text: snapshot(team, hit) });
    }
  }
  send({ finished: true, missing: targets.filter((t) => !done[t]) });
  targets = [];
}

// One-shot: run on the game's main thread between messages (user32 PeekMessageW / GetMessageW are
// called by its message loop even when the game is paused), so no game code is mid-way, then detach.
function arm() {
  const hooks = [];
  const fire = function () {
    if (busy || targets.length === 0) return;
    busy = true;
    try {
      send({ debug: "running on thread " + Process.getCurrentThreadId() });
      scan();
    } catch (e) {
      send({ debug: "error: " + e });
      targets = [];
    } finally {
      hooks.forEach((h) => h.detach());
      busy = false;
    }
  };
  for (const name of ["PeekMessageW", "GetMessageW", "PeekMessageA"]) {
    const f = Process.getModuleByName("user32.dll").findExportByName(name);
    if (f) hooks.push(Interceptor.attach(f, { onLeave: fire }));
  }
  send({ debug: "armed " + hooks.length + " hooks" });
}

recv("targets", (m) => {
  targets = m.names;
  arm();
});
send({ ready: mod.base.toString() });
