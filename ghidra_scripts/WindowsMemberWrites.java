// For every call made with ECX set to a global object, checks whether the callee writes a byte at
// [reg + offset] (i.e. this->member), and also flags memset-like REP STOS in those callees.
// Args: <output file> <global object hex> <member offset hex>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class WindowsMemberWrites extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long obj = Long.parseLong(args[1], 16);
		String member = "+ 0x" + args[2] + "]";
		Listing listing = currentProgram.getListing();

		Set<Function> callees = new LinkedHashSet<>();
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction ins = it.next();
			if (!ins.getMnemonicString().equals("MOV") || !ins.toString().startsWith("MOV ECX,0x")) {
				continue;
			}
			Object[] src = ins.getOpObjects(1);
			if (src.length != 1 || !(src[0] instanceof Scalar) || ((Scalar) src[0]).getUnsignedValue() != obj) {
				continue;
			}
			Instruction n = ins.getNext();
			for (int i = 0; i < 6 && n != null; i++, n = n.getNext()) {
				if (n.getMnemonicString().equals("CALL")) {
					for (Address flow : n.getFlows()) {
						Function f = getFunctionAt(flow);
						if (f != null) {
							callees.add(f);
						}
					}
					break;
				}
			}
		}

		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			w.println("methods called on object: " + callees.size());
			for (Function f : callees) {
				for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
					String s = ins.toString();
					String m = ins.getMnemonicString();
					boolean write = (m.equals("MOV") || m.startsWith("SET") || m.equals("AND") || m.equals("OR")) &&
						s.contains("byte ptr [") && s.indexOf(member) > 0 && s.indexOf(member) < s.indexOf(',') + 1 &&
						s.indexOf(',') > s.indexOf(member);
					if (write || m.startsWith("STOS") || s.contains("REP")) {
						w.println(f.getEntryPoint() + " " + f.getName(true) + ":  " + ins.getAddress() + "  " + s);
					}
				}
			}
		}
	}
}
