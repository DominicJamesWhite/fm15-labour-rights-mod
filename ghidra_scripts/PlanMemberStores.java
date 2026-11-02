// Lists every instruction that stores to [reg + offset] with the given operand size (1, 2 or 4 bytes),
// e.g. all "MOV byte ptr [ESI + 0xea], AL", with the containing function and its caller count.
// Args: <output file> <size, or r<size> for any access> <hex offset>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class PlanMemberStores extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		boolean any = args[1].startsWith("r");
		String sz = any ? args[1].substring(1) : args[1];
		String size = sz.equals("1") ? "byte ptr" : sz.equals("2") ? "word ptr" : "dword ptr";
		List<String> pats = new ArrayList<>();
		for (int i = 2; i < args.length; i++) {
			pats.add(" + 0x" + args[i].toLowerCase() + "]");
		}
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			InstructionIterator it = currentProgram.getListing().getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				String m = ins.getMnemonicString();
				if (!any && !m.equals("MOV") && !m.equals("INC") && !m.equals("DEC") && !m.equals("ADD") && !m.equals("OR")
					&& !m.equals("AND")) {
					continue;
				}
				String s = ins.toString().toLowerCase();
				int comma = s.indexOf(',');
				String dst = any ? s : comma < 0 ? s : s.substring(0, comma);
				if (!dst.contains(size)) {
					continue;
				}
				for (String p : pats) {
					if (dst.contains(p)) {
						Function f = getFunctionContaining(ins.getAddress());
						w.println(ins.getAddress() + "  " + ins + "   in " + (f == null ? "-" : f.getEntryPoint() + " "
							+ f.getName(true) + " callers " + f.getCallingFunctions(monitor).size()));
					}
				}
			}
		}
	}
}
