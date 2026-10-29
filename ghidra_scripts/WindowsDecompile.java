// Decompiles code at the given addresses, creating a function first if Ghidra hasn't (changes are not saved
// when run with -readOnly).
// Args: <output file> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class WindowsDecompile extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 1; i < args.length; i++) {
				Address a = toAddr(args[i]);
				Function f = getFunctionAt(a);
				if (f == null) {
					if (getInstructionAt(a) == null) {
						new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
					}
					f = createFunction(a, null);
				}
				if (f == null) {
					w.println("// could not create function at " + a);
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
