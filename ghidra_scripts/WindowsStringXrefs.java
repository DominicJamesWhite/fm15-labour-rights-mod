// For each search term, finds defined strings containing it, lists the functions referencing them,
// and decompiles those functions.
// Args: <output file> <term>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class WindowsStringXrefs extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Set<Function> toDecompile = new LinkedHashSet<>();
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			DataIterator it = currentProgram.getListing().getDefinedData(true);
			while (it.hasNext()) {
				Data d = it.next();
				if (!(d.getValue() instanceof String)) {
					continue;
				}
				String s = (String) d.getValue();
				for (int i = 1; i < args.length; i++) {
					if (!s.toLowerCase().contains(args[i].toLowerCase())) {
						continue;
					}
					w.println("STRING " + d.getAddress() + " \"" + s + "\"");
					for (Reference r : getReferencesTo(d.getAddress())) {
						Function f = getFunctionContaining(r.getFromAddress());
						w.println("   ref " + r.getFromAddress() + " in " + (f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
						if (f != null) {
							toDecompile.add(f);
						}
					}
				}
			}
			for (Function f : toDecompile) {
				if (f.getBody().getNumAddresses() > 20000) {
					w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " (too big, skipped)");
					continue;
				}
				DecompileResults r = decomp.decompileFunction(f, 120, monitor);
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " =====");
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
			}
		}
		decomp.dispose();
	}
}
