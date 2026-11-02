// For every function containing a non-stack access to [reg + <offset>] of the given operand size,
// decompiles it and prints the C lines mentioning "+ <offset>)" with one line of context, plus whether
// the function also mentions any of the given "signal" substrings (e.g. other fields of the same
// struct). Used to find the real readers of a struct field among many same-offset accesses.
// Args: <output file> <size 1|2|4> <hex offset> <signal>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class RepFieldContext extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String size = args[1].equals("1") ? "byte ptr" : args[1].equals("2") ? "word ptr" : "dword ptr";
		String off = args[2].toLowerCase();
		String pat = " + 0x" + off + "]";
		Set<Function> funcs = new LinkedHashSet<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Instruction ins = it.next();
			String s = ins.toString().toLowerCase();
			if (s.contains(size) && s.contains(pat) && !s.contains("[esp") && !s.contains("[ebp")) {
				Function f = getFunctionContaining(ins.getAddress());
				if (f != null) {
					funcs.add(f);
				}
			}
		}
		DecompInterface d = new DecompInterface();
		d.openProgram(currentProgram);
		String cpat = "+ 0x" + off + ")";
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Function f : funcs) {
				DecompileResults r = d.decompileFunction(f, 60, monitor);
				if (!r.decompileCompleted()) {
					w.println("== " + f.getEntryPoint() + " FAILED");
					continue;
				}
				String c = r.getDecompiledFunction().getC();
				StringBuilder sig = new StringBuilder();
				for (int i = 3; i < args.length; i++) {
					if (c.contains(args[i])) {
						sig.append(args[i]).append(' ');
					}
				}
				String[] lines = c.split("\n");
				w.println("== " + f.getEntryPoint() + " " + f.getName(true) + " size " + f.getBody().getNumAddresses()
					+ " callers " + f.getCallingFunctions(monitor).size() + " signals [" + sig.toString().trim() + "]");
				for (int i = 0; i < lines.length; i++) {
					if (lines[i].contains(cpat)) {
						w.println("   " + lines[i].trim());
					}
				}
			}
		}
		d.dispose();
	}
}
