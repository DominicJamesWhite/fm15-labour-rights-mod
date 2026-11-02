// Finds code that names a squad-rule type directly (bypassing the stored rule lists' contents):
//  (a) every "CMP word ptr [R + 0xc], imm" (a rule's u16 type at +0xc compared with a constant),
//  (b) every call to one of the given "rule by type" helpers, with the immediates pushed in the
//      4 instructions before the call.
// Args: <output file> <helper hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

public class StripTypeSites extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Set<Address> helpers = new HashSet<>();
		for (int i = 1; i < args.length; i++) {
			helpers.add(toAddr(args[i]));
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			InstructionIterator it = listing.getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				String text = ins.toString();
				Function f = fm.getFunctionContaining(ins.getAddress());
				String fn = f == null ? "?" : f.getEntryPoint().toString();
				if (text.startsWith("CMP word ptr [") && text.contains(" + 0xc],")) {
					w.printf("CMP  %s %-48s in %s%n", ins.getAddress(), text, fn);
					continue;
				}
				if (ins.getFlowType().isCall()) {
					for (Reference r : ins.getReferencesFrom()) {
						if (helpers.contains(r.getToAddress())) {
							StringBuilder imms = new StringBuilder();
							Instruction p = ins.getPrevious();
							for (int k = 0; k < 4 && p != null; k++, p = p.getPrevious()) {
								if (p.getMnemonicString().equals("PUSH")) {
									for (Object o : p.getOpObjects(0)) {
										if (o instanceof Scalar) {
											imms.append(" 0x").append(Long.toHexString(((Scalar) o).getUnsignedValue()));
										}
									}
								}
							}
							w.printf("CALL %s -> %s pushes[%s ] in %s%n", ins.getAddress(), r.getToAddress(), imms, fn);
						}
					}
				}
			}
		}
	}
}
