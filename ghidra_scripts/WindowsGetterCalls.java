// Finds tiny getter functions that return a global pointer, then call sites of those getters (or direct
// reads of the global) followed within a window by a virtual call at the given offset.
// Args: <output file> <global hex> <vtable offset hex> <window>
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

public class WindowsGetterCalls extends GhidraScript {

	private boolean readsGlobal(Instruction ins, long global) {
		for (int op = 0; op < ins.getNumOperands(); op++) {
			for (Object o : ins.getOpObjects(op)) {
				if ((o instanceof Address && ((Address) o).getOffset() == global) ||
					(o instanceof Scalar && ((Scalar) o).getUnsignedValue() == global)) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long global = Long.parseLong(args[1], 16);
		String slot = "+ 0x" + args[2] + "]";
		int window = Integer.parseInt(args[3]);
		Listing listing = currentProgram.getListing();

		// getters: functions of <= 4 instructions that read the global
		Set<Long> getters = new HashSet<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.getBody().getNumAddresses() > 16) {
				continue;
			}
			for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
				if (readsGlobal(ins, global)) {
					getters.add(f.getEntryPoint().getOffset());
				}
			}
		}

		Set<Function> funcs = new LinkedHashSet<>();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (long g : getters) {
				w.println(String.format("getter %08x", g));
			}
			InstructionIterator it = listing.getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				boolean start = readsGlobal(ins, global);
				if (!start && ins.getMnemonicString().equals("CALL")) {
					for (Address flow : ins.getFlows()) {
						if (getters.contains(flow.getOffset())) {
							start = true;
						}
					}
				}
				if (!start) {
					continue;
				}
				Instruction n = ins.getNext();
				for (int i = 0; i < window && n != null; i++, n = n.getNext()) {
					if (n.getMnemonicString().equals("CALL") && n.toString().contains(slot)) {
						Function f = getFunctionContaining(n.getAddress());
						w.println(ins.getAddress() + " " + ins + "  ->  " + n.getAddress() + " " + n + "   in " +
							(f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
						if (f != null) {
							funcs.add(f);
						}
						break;
					}
					if (n.getMnemonicString().equals("CALL") || n.getMnemonicString().startsWith("RET")) {
						break;
					}
				}
			}
			w.println("matching functions: " + funcs.size());
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
