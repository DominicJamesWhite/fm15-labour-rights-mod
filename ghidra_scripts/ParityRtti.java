// Lists every vtable (found via MSVC RTTI complete object locators in .rdata) whose class name matches any of
// the given regex alternatives (one per argument, since '|' and ',' do not survive analyzeHeadless.bat), with
// the first N slots as raw function addresses, one class per line, so overrides can be diffed offline.
// Args: <output file> <slot count> <regex>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class ParityRtti extends GhidraScript {

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
		int n = Integer.parseInt(args[1]);
		StringBuilder re = new StringBuilder();
		for (int i = 2; i < args.length; i++) {
			re.append(i > 2 ? "|" : "").append(args[i]);
		}
		Pattern p = Pattern.compile("(?i)(" + re + ")");
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				if (!b.getName().equals(".rdata")) {
					continue;
				}
				for (Address a = b.getStart(); a.compareTo(b.getEnd().subtract(8)) < 0; a = a.add(4)) {
					try {
					long c = getInt(a) & 0xffffffffL;
					if (c < 0x400000L || c > 0x7fffffffL) {
						continue;
					}
					Address ca = toAddr(c);
					if (!currentProgram.getMemory().contains(ca) || !currentProgram.getMemory().contains(ca.add(0x10)) ||
						getInt(ca) != 0) {
						continue;
					}
					long td = getInt(ca.add(0xc)) & 0xffffffffL;
					if (td < 0x400000L || td > 0x7fffffffL) {
						continue;
					}
					if (!currentProgram.getMemory().contains(toAddr(td + 9)) || getByte(toAddr(td + 8)) != '.' ||
						getByte(toAddr(td + 9)) != '?') {
						continue;
					}
					String name = className(c);
					if (!p.matcher(name).find()) {
						continue;
					}
					int off = getInt(ca.add(4));
					StringBuilder sb = new StringBuilder();
					sb.append(a.add(4)).append('\t').append(name).append("\toff=").append(off).append('\t');
					for (int i = 0; i < n; i++) {
						Address s = a.add(4 + 4 * i);
						if (!b.contains(s)) {
							break;
						}
						sb.append(String.format("%08x ", getInt(s) & 0xffffffffL));
					}
					w.println(sb);
					} catch (Exception e) {
						continue;
					}
				}
			}
		}
	}
}
