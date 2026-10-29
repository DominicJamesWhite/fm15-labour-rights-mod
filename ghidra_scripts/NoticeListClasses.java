// Lists symbols whose names or namespaces match a regex, plus vftable entries for matching classes.
// Args: <output file> <comma-separated regex alternatives>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

public class NoticeListClasses extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		// alternatives are comma-separated because '|' cannot pass through analyzeHeadless.bat
		Pattern p = Pattern.compile("(?i)(" + args[1].replace(",", "|") + ")");
		SymbolTable st = currentProgram.getSymbolTable();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Symbol s : st.getAllSymbols(true)) {
				String full = s.getName(true);
				if (!p.matcher(full).find()) {
					continue;
				}
				w.println(s.getAddress() + "\t" + s.getSymbolType() + "\t" + full);
				if (s.getName().equals("vftable")) {
					Address a = s.getAddress();
					for (int i = 0; i < 80; i++) {
						Address slot = a.add(i * 4);
						if (i > 0 && st.getPrimarySymbol(slot) != null &&
							st.getPrimarySymbol(slot).getSource() != SourceType.DEFAULT) {
							break;
						}
						int target = getInt(slot);
						Function f = getFunctionAt(toAddr(target & 0xffffffffL));
						if (f == null) {
							break;
						}
						w.println(String.format("\t[%d] +0x%x -> %s %s", i, i * 4, f.getEntryPoint(), f.getName(true)));
					}
				}
			}
		}
	}
}
