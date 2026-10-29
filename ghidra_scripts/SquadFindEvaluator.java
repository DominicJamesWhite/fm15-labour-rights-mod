// Finds candidate squad-selection rule evaluators: functions with a large switch whose bound matches
// the rule-type enum (0xc8..0xd4), or that compare against several homegrown rule-type codes.
// Args: <output file>
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class SquadFindEvaluator extends GhidraScript {

	private static final Set<Long> HOMEGROWN = new HashSet<>(Arrays.asList(
		0x26L, 0x27L, 0x58L, 0x59L, 0x67L, 0x80L, 0x81L, 0x91L, 0x92L));

	@Override
	public void run() throws Exception {
		List<String> lines = new ArrayList<>();
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
		while (fit.hasNext() && !monitor.isCancelled()) {
			Function f = fit.next();
			Set<Long> hg = new TreeSet<>();
			List<String> bounds = new ArrayList<>();
			Instruction prev = null;
			for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
				String m = ins.getMnemonicString();
				if (m.equals("CMP") || m.equals("SUB") || m.equals("ADD")) {
					Scalar s = ins.getScalar(1);
					if (s != null) {
						long v = s.getUnsignedValue();
						if (HOMEGROWN.contains(v) && m.equals("CMP")) {
							hg.add(v);
						}
						if (m.equals("CMP") && v >= 0xc8 && v <= 0xd4) {
							prev = ins;
						}
					}
				}
				if (prev != null && m.equals("JMP") && ins.getNumOperands() > 0 &&
					ins.getDefaultOperandRepresentation(0).contains("*0x4")) {
					if (ins.getAddress().subtract(prev.getAddress()) < 0x30) {
						bounds.add(prev.getAddress() + ":" + prev);
					}
					prev = null;
				}
			}
			if (hg.size() >= 3 || !bounds.isEmpty()) {
				lines.add(String.format("%s %-40s homegrown_cmps=%s switch=%s", f.getEntryPoint(),
					f.getName(), hg, bounds));
			}
		}
		try (PrintWriter w = new PrintWriter(new File(getScriptArgs()[0]), "UTF-8")) {
			lines.forEach(w::println);
		}
		println("candidates: " + lines.size());
	}
}
