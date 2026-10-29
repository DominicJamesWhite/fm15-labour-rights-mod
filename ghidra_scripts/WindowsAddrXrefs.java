// Lists every instruction referencing the given addresses (via references or immediate operands,
// including small offsets into the object) and decompiles the containing functions.
// Args: <output file> <decompile: 0|1> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class WindowsAddrXrefs extends GhidraScript {

	private static final long SPAN = 0x10;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		boolean decompile = Integer.parseInt(args[1]) > 0;
		long[] targets = new long[args.length - 2];
		for (int i = 2; i < args.length; i++) {
			targets[i - 2] = Long.parseLong(args[i], 16);
		}

		Map<Long, List<Instruction>> hits = new TreeMap<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction ins = it.next();
			for (int op = 0; op < ins.getNumOperands(); op++) {
				for (Object o : ins.getOpObjects(op)) {
					long v;
					if (o instanceof Scalar) {
						v = ((Scalar) o).getUnsignedValue();
					}
					else if (o instanceof ghidra.program.model.address.Address) {
						v = ((ghidra.program.model.address.Address) o).getOffset();
					}
					else {
						continue;
					}
					for (long t : targets) {
						if (v >= t && v < t + SPAN) {
							hits.computeIfAbsent(t, k -> new ArrayList<>()).add(ins);
						}
					}
				}
			}
		}

		Set<Function> funcs = new LinkedHashSet<>();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (long t : targets) {
				w.println(String.format("TARGET %08x", t));
				for (Instruction ins : hits.getOrDefault(t, List.of())) {
					Function f = getFunctionContaining(ins.getAddress());
					w.println("   " + ins.getAddress() + "  " + ins + "   in " +
						(f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
					if (f != null) {
						funcs.add(f);
					}
				}
			}
			if (decompile) {
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
}
