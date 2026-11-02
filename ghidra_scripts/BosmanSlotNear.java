// Lists indirect calls through a vtable slot (CALL dword ptr [R + slot]) that are preceded, within a
// window of instructions in the same function, by a call to one of the given functions or by an
// instruction whose text contains one of the given fragments. Optionally decompiles the hits.
// Used to find callers of TRANSFER_RULES slot 0x3c (bosman_number_days), where the rules object comes
// from FUN_00fd83b0 or from nation+0x4c.
// Args: <output file> <slot hex> <window> <decompile 0|1> <hex callee | frag:TEXT>...
//   (in TEXT, "_" stands for a space, e.g. frag:+_0x4c] )
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class BosmanSlotNear extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String slot = "+ 0x" + Long.toHexString(Long.parseLong(args[1], 16)) + "]";
		int window = Integer.parseInt(args[2]);
		boolean decompile = args[3].equals("1");
		Set<Long> callees = new HashSet<>();
		List<String> frags = new ArrayList<>();
		for (int i = 4; i < args.length; i++) {
			if (args[i].startsWith("frag:")) {
				frags.add(args[i].substring(5).replace("_", " "));
			} else {
				callees.add(Long.parseLong(args[i], 16));
			}
		}
		Listing listing = currentProgram.getListing();
		Set<Function> funcs = new TreeSet<>(Comparator.comparing(Function::getEntryPoint));
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			InstructionIterator it = listing.getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				if (!ins.getMnemonicString().equals("CALL")) {
					continue;
				}
				String text = ins.toString();
				if (!text.startsWith("CALL dword ptr [") || !text.endsWith(slot)) {
					continue;
				}
				Function f = getFunctionContaining(ins.getAddress());
				Instruction p = ins.getPrevious();
				String why = null;
				for (int i = 0; i < window && p != null && why == null; i++, p = p.getPrevious()) {
					if (f != null && !f.getBody().contains(p.getAddress())) {
						break;
					}
					String pt = p.toString();
					if (p.getMnemonicString().equals("CALL")) {
						for (Address flow : p.getFlows()) {
							if (callees.contains(flow.getOffset())) {
								why = p.getAddress() + " " + pt;
							}
						}
					}
					for (String fr : frags) {
						if (pt.contains(fr)) {
							why = p.getAddress() + " " + pt;
						}
					}
				}
				if (why == null) {
					continue;
				}
				w.println(ins.getAddress() + "  " + text + "   <- " + why + "   in " +
					(f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
				if (f != null) {
					funcs.add(f);
				}
			}
			w.println("functions: " + funcs.size());
			if (decompile) {
				DecompInterface decomp = new DecompInterface();
				decomp.openProgram(currentProgram);
				for (Function f : funcs) {
					if (f.getBody().getNumAddresses() > 30000) {
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
