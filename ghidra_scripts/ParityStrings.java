// Lists defined strings containing any search term (case-insensitive) and the functions referencing them.
// No decompilation, so it is quick. Args: <output file> <term>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class ParityStrings extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			DataIterator it = currentProgram.getListing().getDefinedData(true);
			while (it.hasNext()) {
				Data d = it.next();
				if (!(d.getValue() instanceof String)) {
					continue;
				}
				String s = (String) d.getValue();
				String ls = s.toLowerCase();
				boolean hit = false;
				for (int i = 1; i < args.length && !hit; i++) {
					hit = ls.contains(args[i].toLowerCase());
				}
				if (!hit) {
					continue;
				}
				w.println("STRING " + d.getAddress() + " \"" + s.replace("\n", "\\n") + "\"");
				for (Reference r : getReferencesTo(d.getAddress())) {
					Function f = getFunctionContaining(r.getFromAddress());
					w.println("   ref " + r.getFromAddress() + " in " + (f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
				}
			}
		}
	}
}
