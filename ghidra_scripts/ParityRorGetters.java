// Lists small functions (at most <max size> bytes) containing a "ROR reg,0x7" (the obfuscated-int decode used for
// CLUB_FINANCE's balance and similar fields), with their full disassembly and caller count. Finds callable getters.
// Args: <output file> <max size>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class ParityRorGetters extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long max = Long.parseLong(args[1]);
		Set<Function> seen = new LinkedHashSet<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction ins = it.next();
			if (!ins.getMnemonicString().equals("ROR") || !ins.toString().endsWith(",0x7")) {
				continue;
			}
			Function f = getFunctionContaining(ins.getAddress());
			if (f != null && f.getBody().getNumAddresses() <= max) {
				seen.add(f);
			}
		}
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Function f : seen) {
				int callers = getReferencesTo(f.getEntryPoint()).length;
				w.println("== " + f.getEntryPoint() + " size " + f.getBody().getNumAddresses() + " refs " + callers);
				InstructionIterator fi = currentProgram.getListing().getInstructions(f.getBody(), true);
				while (fi.hasNext()) {
					Instruction i = fi.next();
					w.println("   " + i.getAddress() + "  " + i);
				}
			}
		}
	}
}
