// For addresses inside code Ghidra never disassembled (no containing function): walks back to the nearest
// INT3/NOP padding run (or a defined function end), disassembles from there, creates the function in
// memory (project stays read-only), decompiles it, and optionally dumps N instructions around the address.
// Args: <output file> <instructions of context around the address, 0 = none> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

public class ParityFuncAround extends GhidraScript {

	private Address findStart(Address a) throws Exception {
		Memory mem = currentProgram.getMemory();
		Address p = a;
		for (int i = 0; i < 0x8000; i++) {
			Address q = p.subtract(1);
			Function f = getFunctionContaining(q);
			if (f != null && !f.getBody().contains(a)) {
				return p; // previous function ends right here
			}
			byte b = mem.getByte(q);
			byte b2 = mem.getByte(q.subtract(1));
			if ((b == (byte) 0xcc && b2 == (byte) 0xcc) || (b == (byte) 0xcc && (p.getOffset() & 0xf) == 0)) {
				return p;
			}
			p = q;
		}
		return null;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		int ctx = Integer.parseInt(args[1]);
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 2; i < args.length; i++) {
				Address a = toAddr(args[i]);
				Function f = getFunctionContaining(a);
				if (f == null) {
					Address s = findStart(a);
					w.println("\n// ===== " + args[i] + ": start guess " + s);
					if (s != null) {
						disassemble(s);
						f = getFunctionAt(s);
						if (f == null) {
							f = createFunction(s, null);
						}
					}
				}
				if (f == null) {
					w.println("// could not create function");
				} else {
					w.println("// ===== " + args[i] + " in " + f.getEntryPoint() + " " + f.getName(true)
							+ " (size " + f.getBody().getNumAddresses() + ")");
					DecompileResults r = decomp.decompileFunction(f, 240, monitor);
					w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
				}
				if (ctx > 0) {
					Instruction ins = getInstructionContaining(a);
					if (ins == null) {
						disassemble(a);
						ins = getInstructionAt(a);
					}
					for (int n = 0; n < ctx && ins != null; n++) {
						ins = ins.getPrevious();
					}
					for (int n = 0; n < 2 * ctx && ins != null; n++) {
						w.println("//   " + ins.getAddress() + "  " + ins);
						ins = ins.getNext();
					}
				}
			}
		}
	}
}
