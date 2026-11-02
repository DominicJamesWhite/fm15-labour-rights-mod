// Gate for auto-setup careers (tools/fm15_cli.py new-career, reports/automation/new_career.md).
// FM's auto-setup harness builds the career when the main menu is first created (0x00d31510, about
// 30 s after start-up), which can come before fm15_loader.py has written the patches and loaded the
// mode agents. Loaded with the checksum shield, this holds the main thread at the entry of 0x00d31510
// until the loader calls release(), so the career is built under the mode's rules. The wait is native
// (a CModule onEnter sleeping on a flag): a JS wait would hold the script lock the release call needs.
const mod = Process.getModuleByName("fm.exe");
const va = (a) => mod.base.add(a - 0x400000);
const released = Memory.alloc(4);
released.writeU32(0);
const cm = new CModule(`
#include <gum/guminterceptor.h>
extern volatile unsigned int released;
extern void __attribute__((stdcall)) Sleep(unsigned int ms);
void onEnter(GumInvocationContext *ic) {
  while (!released)
    Sleep(50);
}
`, { released, Sleep: Process.getModuleByName("kernel32.dll").getExportByName("Sleep") });
Interceptor.attach(va(0x00d31510), cm);

rpc.exports = {
  release() {
    released.writeU32(1);
    return true;
  },
};
send({ gate: "installed" });
