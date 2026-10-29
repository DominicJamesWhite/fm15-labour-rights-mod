// Finds instructions reading a global object pointer that are followed (within a few instructions)
// by a virtual call through the given vtable offset, and decompiles the containing functions.
// Args: <output file> <global hex address> <vtable offset hex> <window> <base vtable hex>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class WindowsVcallSites extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long global = Long.parseLong(args[1], 16);
		long off = Long.parseLong(args[2], 16);
		int window = Integer.parseInt(args[3]);
		long baseVt = Long.parseLong(args[4], 16);

		Listing listing = currentProgram.getListing();
		Set<Function> funcs = new LinkedHashSet<>();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			long baseFn = getInt(toAddr(baseVt + off)) & 0xffffffffL;
			Function bf = getFunctionAt(toAddr(baseFn));
			w.println(String.format("base vtable slot -> %08x %s", baseFn, bf == null ? "" : bf.getName(true)));

			int readers = 0;
			InstructionIterator it = listing.getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				boolean reads = false;
				for (int op = 0; op < ins.getNumOperands() && !reads; op++) {
					for (Object o : ins.getOpObjects(op)) {
						if ((o instanceof Address && ((Address) o).getOffset() == global) ||
							(o instanceof Scalar && ((Scalar) o).getUnsignedValue() == global)) {
							reads = true;
						}
					}
				}
				if (!reads) {
					continue;
				}
				readers++;
				Instruction n = ins.getNext();
				for (int i = 0; i < window && n != null; i++, n = n.getNext()) {
					if (n.getMnemonicString().equals("CALL") && n.toString().contains("+ 0x" + Long.toHexString(off) + "]")) {
						Function f = getFunctionContaining(n.getAddress());
						w.println(ins.getAddress() + " " + ins + "  ->  " + n.getAddress() + " " + n + "   in " +
							(f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
						if (f != null) {
							funcs.add(f);
						}
						break;
					}
				}
			}
			w.println("global readers: " + readers + ", matching functions: " + funcs.size());

			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(currentProgram);
			for (Function f : funcs) {
				if (f.getBody().getNumAddresses() > 20000) {
					w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " (too big, skipped)");
					continue;
				}
				DecompileResults r = decomp.decompileFunction(f, 120, monitor);
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " =====");
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
			}
			decomp.dispose();
		}
	}
}
