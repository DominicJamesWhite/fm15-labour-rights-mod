// Finds functions that evaluate a squad-selection rule object: a u16 type read at [R+0xc] and a
// compare-type test "CMP byte ptr [R+0xe],0xff/0x1" on the same base register R (layout from the
// loader FUN_011c8170: value +0x8, type +0xc, compare +0xe).
// Args: <output file>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class SquadRuleReaders extends GhidraScript {

	private static final Pattern TYPE = Pattern.compile("word ptr \\[(E[A-Z]{2}) \\+ 0xc\\]");
	private static final Pattern CMP =
		Pattern.compile("CMP byte ptr \\[(E[A-Z]{2}) \\+ 0xe\\],(0xff|0x1)$");

	@Override
	public void run() throws Exception {
		List<String> lines = new ArrayList<>();
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
		while (fit.hasNext() && !monitor.isCancelled()) {
			Function f = fit.next();
			Set<String> typeRegs = new HashSet<>();
			Set<String> cmpRegs = new HashSet<>();
			List<String> sites = new ArrayList<>();
			for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				String s = ins.toString();
				Matcher m = TYPE.matcher(s);
				if (m.find()) {
					typeRegs.add(m.group(1));
					sites.add(ins.getAddress() + " " + s);
				}
				m = CMP.matcher(s);
				if (m.find()) {
					cmpRegs.add(m.group(1));
					sites.add(ins.getAddress() + " " + s);
				}
			}
			typeRegs.retainAll(cmpRegs);
			if (!typeRegs.isEmpty()) {
				lines.add(f.getEntryPoint() + " " + f.getName() + " regs=" + typeRegs + " callers=" +
					f.getCallingFunctions(monitor).size() + "\n    " + String.join("\n    ", sites));
			}
		}
		try (PrintWriter w = new PrintWriter(new File(getScriptArgs()[0]), "UTF-8")) {
			lines.forEach(w::println);
		}
		println("functions: " + lines.size());
	}
}
