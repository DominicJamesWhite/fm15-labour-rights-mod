// For each target function, lists every call site with its containing function and the N instructions
// before the call (to read pushed arguments such as category constants).
// Args: <output file> <instructions before each call> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class ParityCallSites extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		int before = Integer.parseInt(args[1]);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 2; i < args.length; i++) {
				Address target = toAddr(args[i]);
				List<Reference> refs = new ArrayList<>(Arrays.asList(getReferencesTo(target)));
				w.println("==== TARGET " + target + " : " + refs.size() + " refs");
				for (Reference r : refs) {
					Address from = r.getFromAddress();
					Function f = getFunctionContaining(from);
					w.println("-- " + from + " " + r.getReferenceType() + " in "
							+ (f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
					Instruction ins = getInstructionAt(from);
					if (ins == null) {
						continue;
					}
					Deque<Instruction> prev = new ArrayDeque<>();
					Instruction p = currentProgram.getListing().getInstructionBefore(from);
					for (int n = 0; n < before && p != null; n++) {
						prev.addFirst(p);
						p = currentProgram.getListing().getInstructionBefore(p.getAddress());
					}
					for (Instruction q : prev) {
						w.println("     " + q.getAddress() + "  " + q);
					}
					w.println("  >> " + ins.getAddress() + "  " + ins);
				}
			}
		}
	}
}
