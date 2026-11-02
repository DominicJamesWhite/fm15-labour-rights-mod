// Disassembles a range: for each "<hex start> <count>" pair, prints <count> instructions with bytes.
// Args: <output file> <hex start> <count> [<hex start> <count>]...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class PlanDisasm extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 1; i + 1 < args.length; i += 2) {
				Instruction ins = getInstructionAt(toAddr(args[i]));
				if (ins == null) {
					ins = getInstructionAfter(toAddr(args[i]));
				}
				int n = Integer.parseInt(args[i + 1]);
				Function f = getFunctionContaining(toAddr(args[i]));
				w.println("== " + args[i] + " in " + (f == null ? "-" : f.getName(true)));
				for (int k = 0; k < n && ins != null; k++) {
					StringBuilder b = new StringBuilder();
					for (byte x : ins.getBytes()) {
						b.append(String.format("%02x ", x));
					}
					w.println(ins.getAddress() + "  " + String.format("%-30s", b) + ins);
					ins = ins.getNext();
				}
			}
		}
	}
}
