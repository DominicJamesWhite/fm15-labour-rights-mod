// Date stop for unattended careers (tools/fm15_cli.py holiday). Reports the game date and quits FM on request
// through the main loop's quit flag (0x024262a1, as 0x018bc080 sets it). Saving is left to FM's own
// autosave: a save request through GAME+0xbe (2) on a career that was never saved under a name shows
// "Save Game Failed" and stops the holiday (live test, 2 Nov 2026). No hooks, no calls into FM.
const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const TODAY = va(0x0239ebf4);
const QUIT = va(0x024262a1);
rpc.exports = {
  date() { return [TODAY.add(2).readU16(), TODAY.readU16() & 0x1ff]; },
  quit() { QUIT.writeU8(1); return true; },
};
