// Finds instructions whose text contains every given fragment (e.g. "byte ptr" "+ 0x54]" ",0x7")
// and lists the containing function.
// Args: <output file> <fragment>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class NoticeFindStores extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			InstructionIterator it = currentProgram.getListing().getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				String s = ins.toString();
				boolean all = true;
				for (int i = 1; i < args.length && all; i++) {
					all = s.contains(args[i]);
				}
				if (all) {
					Function f = getFunctionContaining(ins.getAddress());
					w.println(ins.getAddress() + "\t" + s + "\t" + (f == null ? "?" : f.getEntryPoint() + " " + f.getName()));
				}
			}
		}
	}
}
