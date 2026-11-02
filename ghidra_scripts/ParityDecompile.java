// Decompiles the functions at the given addresses, first disassembling and creating any function Ghidra
// hasn't defined (e.g. targets only reached through vftables). Changes stay in memory (project is read-only).
// Args: <output file> <max instructions of disassembly to append, 0 = none> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ParityDecompile extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		int asm = Integer.parseInt(args[1]);
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 2; i < args.length; i++) {
				Address a = toAddr(args[i]);
				Function f = getFunctionAt(a);
				if (f == null) {
					f = getFunctionContaining(a);
					if (f == null) {
						disassemble(a);
						f = createFunction(a, null);
					}
				}
				if (f == null) {
					w.println("\n// ===== " + args[i] + " could not create function");
					continue;
				}
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " (size " + f.getBody().getNumAddresses() + ") =====");
				DecompileResults r = decomp.decompileFunction(f, 180, monitor);
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
				if (asm > 0) {
					InstructionIterator it = currentProgram.getListing().getInstructions(f.getEntryPoint(), true);
					for (int n = 0; n < asm && it.hasNext(); n++) {
						Instruction ins = it.next();
						if (!f.getBody().contains(ins.getAddress())) {
							break;
						}
						w.println("//   " + ins.getAddress() + "  " + ins);
					}
				}
			}
		}
		decomp.dispose();
	}
}
