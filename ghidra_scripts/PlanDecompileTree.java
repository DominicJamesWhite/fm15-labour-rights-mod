// Decompiles the given functions and their callees breadth-first down to a depth, skipping tiny and huge
// functions, and writes a call outline (each function's callees with sizes and caller counts) first.
// Args: <output file> <depth> <min size> <max size> <hex address>... [-x <hex address>... = don't descend]
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class PlanDecompileTree extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args[0]);
		int depth = Integer.parseInt(args[1]);
		long min = Long.parseLong(args[2]);
		long max = Long.parseLong(args[3]);
		List<Function> roots = new ArrayList<>();
		Set<Function> excluded = new HashSet<>();
		boolean ex = false;
		for (int i = 4; i < args.length; i++) {
			if (args[i].equals("-x")) {
				ex = true;
				continue;
			}
			Function f = getFunctionContaining(toAddr(args[i]));
			if (f == null) {
				printerr("No function at " + args[i]);
				continue;
			}
			(ex ? excluded : roots).add(f);
		}
		LinkedHashMap<Function, Integer> seen = new LinkedHashMap<>();
		Deque<Function> queue = new ArrayDeque<>();
		for (Function f : roots) {
			seen.put(f, 0);
			queue.add(f);
		}
		StringBuilder outline = new StringBuilder();
		while (!queue.isEmpty()) {
			Function f = queue.poll();
			int d = seen.get(f);
			Set<Function> callees = f.getCalledFunctions(monitor);
			outline.append(f.getEntryPoint()).append(" ").append(f.getName(true)).append(" (size ")
				.append(f.getBody().getNumAddresses()).append(", depth ").append(d).append(", callers ")
				.append(f.getCallingFunctions(monitor).size()).append(")\n");
			List<Function> sorted = new ArrayList<>(callees);
			sorted.sort(Comparator.comparing(Function::getEntryPoint));
			for (Function c : sorted) {
				long size = c.getBody().getNumAddresses();
				outline.append("    -> ").append(c.getEntryPoint()).append(" ").append(c.getName(true))
					.append(" size ").append(size).append(" callers ").append(c.getCallingFunctions(monitor).size())
					.append("\n");
				if (d + 1 <= depth && !seen.containsKey(c) && size >= min && size <= max && !excluded.contains(f)
					&& !c.isThunk()) {
					seen.put(c, d + 1);
					queue.add(c);
				}
			}
		}
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
			w.println("/* CALL OUTLINE\n" + outline + "*/");
			for (Function f : seen.keySet()) {
				DecompileResults r = decomp.decompileFunction(f, 180, monitor);
				w.println("\n// ===== " + f.getEntryPoint() + " " + f.getName(true) + " (depth " + seen.get(f) + ") =====");
				w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// failed: " + r.getErrorMessage());
			}
		}
		decomp.dispose();
		println("Wrote " + seen.size() + " functions to " + out);
	}
}
