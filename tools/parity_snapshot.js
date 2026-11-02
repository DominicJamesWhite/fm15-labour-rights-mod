// Read-only season snapshot of every detailed club in the loaded first and second divisions, for
// tracking parity mode (tools/parity_snapshot.py). Top-level reads only: no hooks, no writes; the
// only calls are pure getters (club list, FIN_OF, the club's league getter, the name formatter).
// From reports/parity/wage_gap/probe_wages.js. Finance fields: f = dwords from fin+0x30 (f[16]
// +0x70 board wage budget, f[7] +0x4c add-on, f[18]/f[19] +0x78/+0x7c weekly wage bill), s / l =
// the season / last-season blocks (35 dwords from fin+0x208 / +0x2ac).
const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const WORLD = va(0x02428ee0);
const tc = (addr, ret, args) => new NativeFunction(va(addr), ret, ["pointer"].concat(args || []), "thiscall");
const CLUB_COUNT = tc(0x0151db30, "int");
const CLUB_AT = tc(0x0151da10, "pointer", ["int"]);
const FIN_OF = tc(0x014c9670, "pointer");
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
  } catch (e) { return obj.toString(); }
}
function readText(p) {
  const found = [];
  for (const f of [() => p.readUtf16String(), () => p.add(2).readUtf16String(), () => p.add(4).readUtf16String(),
                   () => p.readUtf8String(), () => p.add(1).readUtf8String()]) {
    try { const s = f(); if (s && /^[\p{L}\p{M} .,'\-()&0-9]{2,60}$/u.test(s)) found.push(s); } catch (e) {}
  }
  return found.length ? found.sort((a, b) => b.length - a.length)[0] : "?";
}
function vcall(obj, off, ret) {
  return new NativeFunction(obj.readPointer().add(off).readPointer(), ret, ["pointer"], "thiscall")(obj);
}
const ror32 = (x, n) => { n &= 31; return n === 0 ? x >>> 0 : ((x >>> n) | (x << (32 - n))) >>> 0; };
const ror16 = (x, n) => { n &= 15; x &= 0xffff; return n === 0 ? x : (((x >>> n) | (x << (16 - n))) & 0xffff); };
const rol16 = (x, n) => ror16(x, 16 - (n & 15));
function balance(fin) {
  const p = fin.add(0xc); let x = p.readU32();
  x = (~ror32(x, 7)) >>> 0; x = (~ror32(x, p.and(31).toInt32())) >>> 0; return ror32(x, 5) | 0;
}
function teamRep(team) {
  const p = team.add(100); const b = p.and(0xf).toInt32();
  let u = (~ror16(p.readU16(), b)) & 0xffff; u = (~ror16(u, 12)) & 0xffff; return ror16(u, b);
}
function leagueRep(comp) {
  const p = comp.add(0x80); const k = p.and(0xf).toInt32();
  let u = (~(rol16(p.readU16(), k) ^ 0xecf1)) & 0xffff; let r = (~ror16(u, 7)) & 0xffff; return r > 32767 ? r - 65536 : r;
}
const dw = (p, off, n) => { const a = []; for (let i = 0; i < n; i++) a.push(p.add(off + 4 * i).readS32()); return a; };
const TODAY = va(0x0239ebf4);
const out = { date: new Date(Date.UTC(TODAY.add(2).readU16(), 0, TODAY.readU16() & 0x1ff)).toISOString().slice(0, 10), clubs: [], leagues: {} };
const world = WORLD.readPointer();
const n = CLUB_COUNT(world);
for (let i = 0; i < n; i++) {
  try {
    const club = CLUB_AT(world, i);
    if (club.isNull()) continue;
    const fin = FIN_OF(club);
    if (fin.isNull()) continue;
    const league = vcall(club, 0x104, "pointer");
    if (league.isNull()) continue;
    const level = league.add(0xdd).readS8();
    if (level !== 0 && level !== 1) continue;
    const lk = league.toString();
    if (!out.leagues[lk]) out.leagues[lk] = { level, wagePct: league.add(0xe0).readS8(), rep: leagueRep(league), nation: league.add(0x44).readPointer().add(8).readS32() };
    const tb = club.add(0x10).readPointer(), te = club.add(0x14).readPointer();
    const team = (!tb.isNull() && !tb.equals(te)) ? tb.readPointer() : null;
    let att = null; try { att = club.add(0x50).readPointer().add(0x38).readS32(); } catch (e) {}
    out.clubs.push({
      i, league: lk, rep: team ? teamRep(team) : null, ca8: club.add(0xa8).readU8(), ca9: club.add(0xa9).readS8(), att,
      bal: balance(fin), f: dw(fin, 0x30, 0x24), owner: fin.add(0x31).readU8(), f32: fin.add(0x32).readU8(),
      x: dw(fin, 0xa0, 8), s: dw(fin, 0x208, 35), l: dw(fin, 0x2ac, 35),
    });
  } catch (e) {}
}
for (const lk of Object.keys(out.leagues)) out.leagues[lk].name = nameOf("comp", ptr(lk));
for (const c of out.clubs) if (out.leagues[c.league].level === 0) c.name = nameOf("club", CLUB_AT(world, c.i));
send(JSON.stringify(out));
