// Lists every instruction whose operands mention [reg + offset] for the given member offsets,
// grouped by containing function. Useful for finding readers/writers of a flags field.
// Args: <output file> <hex offset>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class RulesMemberAccess extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		List<String> needles = new ArrayList<>();
		for (int i = 1; i < args.length; i++) {
			needles.add("+ 0x" + Long.toHexString(Long.parseLong(args[i], 16)) + "]");
		}
		Map<String, List<String>> byFunction = new TreeMap<>();
		FunctionManager fm = currentProgram.getFunctionManager();
		for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
			String text = ins.toString();
			for (String n : needles) {
				if (text.contains(n)) {
					Function f = fm.getFunctionContaining(ins.getAddress());
					String key = f == null ? "(no function)" : f.getEntryPoint() + " " + f.getName(true);
					byFunction.computeIfAbsent(key, k -> new ArrayList<>()).add(ins.getAddress() + "  " + text);
				}
			}
		}
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Map.Entry<String, List<String>> e : byFunction.entrySet()) {
				w.println("== " + e.getKey());
				e.getValue().forEach(l -> w.println("   " + l));
			}
		}
		println("Functions: " + byFunction.size());
	}
}
