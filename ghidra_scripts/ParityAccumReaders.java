// Lists functions that touch at least N distinct displacements in [lo, hi] (any operand, read or write),
// with every such instruction in address order plus nearby TEST/AND immediates (to spot bitmask switches).
// Args: <output file> <hex lo> <hex hi> <min distinct>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class ParityAccumReaders extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long lo = Long.parseLong(args[1], 16), hi = Long.parseLong(args[2], 16);
		int min = Integer.parseInt(args[3]);
		Listing listing = currentProgram.getListing();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				Set<Long> seen = new TreeSet<>();
				List<String> lines = new ArrayList<>();
				for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
					boolean hit = false;
					for (int op = 0; op < ins.getNumOperands(); op++) {
						for (Object o : ins.getOpObjects(op)) {
							if (o instanceof Scalar) {
								long d = ((Scalar) o).getUnsignedValue();
								if (d >= lo && d <= hi && (d & 3) == 0 && ins.toString().contains("[")) {
									seen.add(d);
									hit = true;
								}
							}
						}
					}
					String m = ins.getMnemonicString();
					if (hit || ((m.equals("TEST") || m.equals("AND")) && ins.toString().contains("0x") && !ins.toString().contains("["))) {
						lines.add("   " + ins.getAddress() + "  " + ins);
					}
				}
				if (seen.size() >= min) {
					w.println(f.getEntryPoint() + " " + f.getName() + " size " + f.getBody().getNumAddresses() + " distinct " + seen.size()
							+ " refs " + getReferencesTo(f.getEntryPoint()).length);
					for (String l : lines) {
						w.println(l);
					}
				}
			}
		}
	}
}
