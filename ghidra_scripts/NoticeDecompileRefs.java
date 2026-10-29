// Decompiles every function that references the given data addresses (strings, vftables...),
// plus any explicitly listed function addresses prefixed with "f".
// Args: <output file> <hex address | fHEX>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class NoticeDecompileRefs extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Map<Function, String> targets = new LinkedHashMap<>();
		for (int i = 1; i < args.length; i++) {
			if (args[i].startsWith("f")) {
				Function f = getFunctionContaining(toAddr(args[i].substring(1)));
				if (f == null) {
					f = createFunction(toAddr(args[i].substring(1)), null);
				}
				if (f != null) {
					targets.putIfAbsent(f, "listed");
				}
				continue;
			}
			for (Reference r : getReferencesTo(toAddr(args[i]))) {
				Function f = getFunctionContaining(r.getFromAddress());
				if (f != null) {
					targets.putIfAbsent(f, "refs " + args[i] + " at " + r.getFromAddress());
				}
			}
		}

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Map.Entry<Function, String> e : targets.entrySet()) {
				Function f = e.getKey();
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " (" + e.getValue() +
					", purge " + f.getStackPurgeSize() + ") =====");
				w.print("// called by:");
				for (Function c : f.getCallingFunctions(monitor)) {
					w.print(" " + c.getEntryPoint());
				}
				w.println();
				DecompileResults r = decomp.decompileFunction(f, 120, monitor);
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
			}
		}
		decomp.dispose();
		println("Wrote " + targets.size() + " functions");
	}
}
