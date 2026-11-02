// Finds indirect calls through GAME_COMP_MANAGER vt+0x60 (CompPay 0x0091a160): every CALL [reg+0x60]
// with a read of the manager holder global (default 0x024257fc) within the preceding N instructions.
// Prints the containing function and the preceding instructions (to read the pushed type constant).
// Args: <output file> <instructions before> [global hex] [vt offset hex]
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class ParityCompPayCalls extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		int before = Integer.parseInt(args[1]);
		String glob = args.length > 2 ? args[2].toLowerCase().replace("0x", "") : "024257fc";
		String off = args.length > 3 ? args[3].toLowerCase() : "0x60";
		Listing l = currentProgram.getListing();
		int count = 0;
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			InstructionIterator it = l.getInstructions(true);
			while (it.hasNext()) {
				Instruction ins = it.next();
				if (!ins.getMnemonicString().equals("CALL")) {
					continue;
				}
				String op = ins.getDefaultOperandRepresentation(0).toLowerCase();
				if (!op.startsWith("dword ptr [") || !op.endsWith("+ " + off + "]")) {
					continue;
				}
				Deque<Instruction> prev = new ArrayDeque<>();
				Instruction p = l.getInstructionBefore(ins.getAddress());
				boolean hit = false;
				for (int n = 0; n < before && p != null; n++) {
					prev.addFirst(p);
					if (p.toString().toLowerCase().contains(glob)) {
						hit = true;
					}
					p = l.getInstructionBefore(p.getAddress());
				}
				if (!hit) {
					continue;
				}
				count++;
				Function f = getFunctionContaining(ins.getAddress());
				w.println("-- " + ins.getAddress() + " in " + (f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
				for (Instruction q : prev) {
					w.println("     " + q.getAddress() + "  " + q);
				}
				w.println("  >> " + ins.getAddress() + "  " + ins);
			}
			w.println("TOTAL " + count);
		}
	}
}
