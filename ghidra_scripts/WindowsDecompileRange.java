// Decompiles every function whose entry lies in [start, end) and writes them to a file.
// Args: <output file> <start hex> <end hex>
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;

public class WindowsDecompileRange extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		AddressSet range = new AddressSet(toAddr(args[1]), toAddr(args[2]));
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(range, true)) {
				DecompileResults r = decomp.decompileFunction(f, 60, monitor);
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " =====");
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
			}
		}
		decomp.dispose();
	}
}
