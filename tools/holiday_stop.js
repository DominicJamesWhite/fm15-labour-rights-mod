// Date stop for unattended careers (tools/fm15_cli.py holiday). Reports the game date and quits FM on request
// through the main loop's quit flag (0x024262a1, as 0x018bc080 sets it). Saving is left to FM's own
// autosave: a save request through GAME+0xbe (2) on a career that was never saved under a name shows
// "Save Game Failed" and stops the holiday (live test, 2 Nov 2026). No hooks, no calls into FM.
const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const TODAY = va(0x0239ebf4);
const QUIT = va(0x024262a1);
// After a load the game sits idle until Continue or a holiday request (new_career.md, Load).
// GO_HOLIDAY (0x00def1c0, ret 4, argument ignored) is FM's own "go on holiday" request: it queues
// 0x004df210 for the human manager with no return date. It runs once on the main thread, from the GAME
// operation pump 0x01e82130 that FM's update loop calls.
const GO_HOLIDAY = new NativeFunction(va(0x00def1c0), "void", ["int"], "stdcall");
const LOADED = va(0x02392452), PENDING_OP = va(0x0240f278 + 0xbe);
let holidayHook = null;
rpc.exports = {
  date() { return [TODAY.add(2).readU16(), TODAY.readU16() & 0x1ff]; },
  state() { return { loaded: LOADED.readU8(), pending: PENDING_OP.readU8() }; },
  goHoliday() {
    if (holidayHook) return false;
    holidayHook = Interceptor.attach(va(0x01e82130), {
      onEnter() {
        if (!holidayHook) return;
        const h = holidayHook;
        holidayHook = null;
        h.detach();
        try { GO_HOLIDAY(0); send({ holiday: "requested" }); } catch (e) { send({ holiday: "error " + e }); }
      },
    });
    return true;
  },
  quit() { QUIT.writeU8(1); return true; },
};
