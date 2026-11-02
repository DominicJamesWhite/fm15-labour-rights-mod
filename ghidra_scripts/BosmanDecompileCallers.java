// Decompiles every function that calls one of the given functions (e.g. FUN_00fd83b0, the per-nation
// TRANSFER_RULES lookup) and keeps only those whose C output contains one of the given substrings
// (e.g. "vcall:3c" stands for "+ 0x3c))(", a call through vtable slot 0x3c; parentheses can't pass
// through analyzeHeadless.bat). Use "-" as the filter to keep everything.
// Args: <output file> <comma-separated filter substrings | -> <hex callee>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class BosmanDecompileCallers extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String[] filters = args[1].equals("-") ? new String[0] : args[1].split(",");
		Set<Function> funcs = new TreeSet<>(Comparator.comparing(Function::getEntryPoint));
		for (int i = 2; i < args.length; i++) {
			for (Reference r : getReferencesTo(toAddr(Long.parseLong(args[i], 16)))) {
				Function f = getFunctionContaining(r.getFromAddress());
				if (f != null) {
					funcs.add(f);
				}
			}
		}
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		int kept = 0;
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			w.println("// callers: " + funcs.size());
			for (Function f : funcs) {
				if (monitor.isCancelled()) {
					break;
				}
				if (f.getBody().getNumAddresses() > 30000) {
					w.println("// ===== " + f.getEntryPoint() + " " + f.getName(true) + " (too big, skipped)");
					continue;
				}
				DecompileResults r = decomp.decompileFunction(f, 120, monitor);
				if (!r.decompileCompleted()) {
					w.println("// ===== " + f.getEntryPoint() + " failed: " + r.getErrorMessage());
					continue;
				}
				String c = r.getDecompiledFunction().getC();
				boolean keep = filters.length == 0;
				for (String flt : filters) {
					keep |= c.contains(flt.startsWith("vcall:") ? "+ 0x" + flt.substring(6) + "))(" : flt);
				}
				if (!keep) {
					w.println("// (no match) " + f.getEntryPoint() + " " + f.getName(true));
					continue;
				}
				kept++;
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " =====");
				w.println(c);
			}
			w.println("// kept: " + kept);
		}
		decomp.dispose();
	}
}
