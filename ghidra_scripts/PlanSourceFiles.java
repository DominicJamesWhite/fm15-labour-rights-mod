// Lists the source-file path strings ("..\..\code\...") whose path contains any of the terms, and every
// function referencing each (assert/debug calls name their .cpp), plus the "DB::CLASS::method" strings
// referenced from the same functions. Args: <output file> <term>...  (no term = all source files)
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class PlanSourceFiles extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Map<Function, Set<String>> names = new HashMap<>();
		Map<String, Set<Function>> files = new TreeMap<>();
		DataIterator it = currentProgram.getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			if (!(d.getValue() instanceof String)) {
				continue;
			}
			String s = (String) d.getValue();
			boolean isFile = s.startsWith("..\\..\\code");
			boolean isName = s.startsWith("DB::") || s.matches("^[A-Z][A-Z0-9_]+::[a-z_][a-z0-9_]*.*");
			if (!isFile && !isName) {
				continue;
			}
			if (isFile && args.length > 1) {
				boolean any = false;
				for (int i = 1; i < args.length; i++) {
					any |= s.toLowerCase().contains(args[i].toLowerCase());
				}
				if (!any) {
					continue;
				}
			}
			for (Reference r : getReferencesTo(d.getAddress())) {
				Function f = getFunctionContaining(r.getFromAddress());
				if (f == null) {
					continue;
				}
				if (isFile) {
					files.computeIfAbsent(s, k -> new TreeSet<>(Comparator.comparing(Function::getEntryPoint))).add(f);
				} else {
					names.computeIfAbsent(f, k -> new TreeSet<>()).add(s.length() > 90 ? s.substring(0, 90) : s);
				}
			}
		}
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Map.Entry<String, Set<Function>> e : files.entrySet()) {
				w.println("FILE " + e.getKey() + "  (" + e.getValue().size() + " functions)");
				for (Function f : e.getValue()) {
					Set<String> n = names.getOrDefault(f, Collections.emptySet());
					w.println("   " + f.getEntryPoint() + " size " + f.getBody().getNumAddresses() + " callers "
						+ f.getCallingFunctions(monitor).size() + "  " + f.getName(true) + "  " + n);
				}
			}
		}
		println("Wrote " + files.size() + " files");
	}
}
