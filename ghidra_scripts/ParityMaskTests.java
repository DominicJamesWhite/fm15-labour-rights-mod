// Lists functions that TEST/AND (or BT) registers or memory against every one of the given immediates,
// e.g. the FFP income-category bits, so a "sum the categories selected by a bitmask" routine can be found.
// Args: <output file> <hex imm>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class ParityMaskTests extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Set<Long> want = new HashSet<>();
		for (int i = 1; i < args.length; i++) {
			want.add(Long.parseLong(args[i], 16));
		}
		Listing listing = currentProgram.getListing();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				Set<Long> got = new HashSet<>();
				for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
					String m = ins.getMnemonicString();
					if (!(m.equals("TEST") || m.equals("AND"))) {
						continue;
					}
					for (int op = 0; op < ins.getNumOperands(); op++) {
						for (Object o : ins.getOpObjects(op)) {
							if (o instanceof Scalar && want.contains(((Scalar) o).getUnsignedValue())) {
								got.add(((Scalar) o).getUnsignedValue());
							}
						}
					}
				}
				if (got.size() == want.size()) {
					w.println(f.getEntryPoint() + " " + f.getName() + " size " + f.getBody().getNumAddresses()
							+ " refs " + getReferencesTo(f.getEntryPoint()).length);
				}
			}
		}
	}
}
