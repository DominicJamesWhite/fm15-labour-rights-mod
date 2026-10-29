// Dumps dwords around an address, resolving each to a function/symbol/string where possible,
// and lists references into the dumped range.
// Args: <output file> <hex address> <dwords before> <dwords after>
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class WindowsDumpTable extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Address center = toAddr(args[1]);
		int before = Integer.parseInt(args[2]);
		int after = Integer.parseInt(args[3]);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = -before; i <= after; i++) {
				Address a = center.add(i * 4L);
				int v = getInt(a);
				StringBuilder line = new StringBuilder(String.format("%s%s  %08x", a, i == 0 ? "*" : " ", v));
				Address t = toAddr(v & 0xffffffffL);
				if (currentProgram.getMemory().contains(t)) {
					Function f = getFunctionAt(t);
					Symbol s = getSymbolAt(t);
					Data d = getDataAt(t);
					if (f != null) {
						line.append("  fn ").append(f.getName(true));
					}
					else if (d != null && d.getValue() instanceof String) {
						line.append("  \"").append(d.getValue()).append("\"");
					}
					else if (s != null) {
						line.append("  ").append(s.getName(true));
					}
				}
				for (Reference r : getReferencesTo(a)) {
					Function f = getFunctionContaining(r.getFromAddress());
					line.append("   <- ").append(r.getFromAddress())
							.append(f == null ? "" : " " + f.getName(true));
				}
				w.println(line);
			}
		}
	}
}
