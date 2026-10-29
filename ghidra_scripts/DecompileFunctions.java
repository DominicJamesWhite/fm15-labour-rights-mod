// Decompiles the functions at the given addresses (and optionally their callers) to a text file.
// Args: <output file> <depth: 0 = just these, 1 = also callers> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DecompileFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args[0]);
		boolean withCallers = Integer.parseInt(args[1]) > 0;

		Set<Function> targets = new LinkedHashSet<>();
		Map<Function, Set<Function>> callers = new LinkedHashMap<>();
		for (int i = 2; i < args.length; i++) {
			Function f = getFunctionContaining(toAddr(args[i]));
			if (f == null) {
				printerr("No function at " + args[i]);
				continue;
			}
			targets.add(f);
			callers.put(f, f.getCallingFunctions(monitor));
		}
		if (withCallers) {
			for (Set<Function> cs : callers.values()) {
				targets.addAll(cs);
			}
		}

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
			for (Map.Entry<Function, Set<Function>> e : callers.entrySet()) {
				w.println("// " + e.getKey().getName(true) + " is called by:");
				for (Function c : e.getValue()) {
					w.println("//   " + c.getEntryPoint() + " " + c.getName(true));
				}
			}
			for (Function f : targets) {
				DecompileResults r = decomp.decompileFunction(f, 120, monitor);
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " =====");
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
			}
		}
		decomp.dispose();
		println("Wrote " + targets.size() + " functions to " + out);
	}
}
