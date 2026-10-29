// Names the class of a vtable via MSVC RTTI and lists every vtable (found via RTTI locators) whose
// class hierarchy includes the same base, with the function in the given slot.
// Args: <output file> <vtable hex address> <slot byte offset hex>
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class WindowsVtableSlot extends GhidraScript {

	private String className(long col) throws Exception {
		Address td = toAddr(getInt(toAddr(col + 0xc)) & 0xffffffffL);
		StringBuilder sb = new StringBuilder();
		Address p = td.add(8);
		for (int i = 0; i < 300; i++) {
			byte b = getByte(p.add(i));
			if (b == 0) {
				break;
			}
			sb.append((char) b);
		}
		return sb.toString();
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long vt = Long.parseLong(args[1], 16);
		int slot = Integer.parseInt(args[2], 16);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			long col = getInt(toAddr(vt - 4)) & 0xffffffffL;
			w.println("vtable " + Long.toHexString(vt) + " class " + className(col));

			// Every dword in .rdata that points to a COL followed by code pointers is a vtable start.
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				if (!b.getName().equals(".rdata")) {
					continue;
				}
				for (Address a = b.getStart(); a.compareTo(b.getEnd().subtract(8)) < 0; a = a.add(4)) {
					long c = getInt(a) & 0xffffffffL;
					Address ca = toAddr(c);
					if (!currentProgram.getMemory().contains(ca) || getInt(ca) != 0) {
						continue; // COL signature is 0 on x86
					}
					Address tdPtr = ca.add(0xc);
					if (!currentProgram.getMemory().contains(tdPtr)) {
						continue;
					}
					long td = getInt(tdPtr) & 0xffffffffL;
					if (!currentProgram.getMemory().contains(toAddr(td + 8)) || getByte(toAddr(td + 8)) != '.' ||
						getByte(toAddr(td + 9)) != '?') {
						continue;
					}
					String name = className(c);
					Address slotAddr = a.add(4 + slot);
					long fn = getInt(slotAddr) & 0xffffffffL;
					if (fn == (getInt(toAddr(vt + slot)) & 0xffffffffL) || name.contains("GAME") ||
						name.contains("RULE")) {
						Function f = getFunctionAt(toAddr(fn));
						w.println(String.format("%s  %-60s slot -> %08x %s", a.add(4), name, fn,
							f == null ? "" : f.getName(true)));
					}
				}
			}
		}
	}
}
