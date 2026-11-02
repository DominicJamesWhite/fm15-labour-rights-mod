// Lists functions that call the first target AND at least one of the other targets (e.g. callers of the
// CLUB_FINANCE accessor FUN_014c9670 that also read club reputation), with their size and caller count.
// Args: <output file> <hex first target> <hex other target>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class RepCoCallers extends GhidraScript {

	private Set<Function> callers(String hex) {
		Set<Function> out = new LinkedHashSet<>();
		for (Reference r : getReferencesTo(toAddr(hex))) {
			if (!r.getReferenceType().isCall()) {
				continue;
			}
			Function f = getFunctionContaining(r.getFromAddress());
			if (f != null) {
				out.add(f);
			}
		}
		return out;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Set<Function> first = callers(args[1]);
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 2; i < args.length; i++) {
				Set<Function> other = callers(args[i]);
				for (Function f : first) {
					if (other.contains(f)) {
						w.println(args[i] + "  " + f.getEntryPoint() + " " + f.getName(true) + " size "
							+ f.getBody().getNumAddresses() + " callers " + f.getCallingFunctions(monitor).size());
					}
				}
			}
		}
	}
}
