// Lists every instruction with one of the given immediate values, with its containing function.
// Args: <output file> <hex value>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class SquadImmediates extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Set<Long> wanted = new HashSet<>();
		for (int i = 1; i < args.length; i++) {
			wanted.add(Long.parseLong(args[i], 16));
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			InstructionIterator it = currentProgram.getListing().getInstructions(true);
			while (it.hasNext() && !monitor.isCancelled()) {
				Instruction ins = it.next();
				for (int op = 0; op < ins.getNumOperands(); op++) {
					for (Object o : ins.getOpObjects(op)) {
						if (o instanceof Scalar && wanted.contains(((Scalar) o).getUnsignedValue())) {
							Function f = fm.getFunctionContaining(ins.getAddress());
							w.printf("%s %-44s in %s%n", ins.getAddress(), ins,
								f == null ? "?" : f.getEntryPoint() + " " + f.getName());
						}
					}
				}
			}
		}
	}
}
