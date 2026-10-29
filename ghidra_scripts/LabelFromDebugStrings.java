// Finds debug strings of the form "CLASS::method ..." and names the functions that reference them.
// Also writes a report of every string matching the labour-rights keywords and the functions using it.
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class LabelFromDebugStrings extends GhidraScript {

	private static final Pattern QUALIFIED =
		Pattern.compile("^(?:DB::)?([A-Z][A-Z0-9_]+)::([a-z_][a-z0-9_]*)\\b");
	private static final Pattern KEYWORDS = Pattern.compile(
		"(?i)loan|transfer|contract|release.?clause|compensation|tribunal|work.?permit|" +
			"terminat|notice|bosman|pre.?contract|sell.?on|clause");

	@Override
	public void run() throws Exception {
		String outDir = getScriptArgs().length > 0 ? getScriptArgs()[0] : ".";
		SymbolTable symbols = currentProgram.getSymbolTable();
		FunctionManager functions = currentProgram.getFunctionManager();
		ReferenceManager refs = currentProgram.getReferenceManager();

		// candidate name -> set of functions referencing a string with that name
		Map<String, Set<Function>> candidates = new TreeMap<>();
		List<String> report = new ArrayList<>();

		DataIterator it = currentProgram.getListing().getDefinedData(true);
		while (it.hasNext() && !monitor.isCancelled()) {
			Data data = it.next();
			if (!(data.getValue() instanceof String)) {
				continue;
			}
			String s = (String) data.getValue();
			Matcher q = QUALIFIED.matcher(s);
			boolean keyword = KEYWORDS.matcher(s).find();
			if (!q.find() && !keyword) {
				continue;
			}

			Set<Function> users = new LinkedHashSet<>();
			for (Reference r : refs.getReferencesTo(data.getAddress())) {
				Function f = functions.getFunctionContaining(r.getFromAddress());
				if (f != null) {
					users.add(f);
				}
			}

			q.reset();
			if (q.find()) {
				candidates.computeIfAbsent(q.group(1) + "::" + q.group(2), k -> new LinkedHashSet<>())
						.addAll(users);
			}
			if (keyword) {
				StringBuilder line = new StringBuilder();
				line.append(data.getAddress()).append("\t").append(s.replace("\t", " ").replace("\n", " "));
				for (Function f : users) {
					line.append("\n\t-> ").append(f.getEntryPoint()).append(" ").append(f.getName(true));
				}
				report.add(line.toString());
			}
		}

		// Only rename when a qualified name maps to exactly one still-unnamed function.
		int renamed = 0;
		List<String> labels = new ArrayList<>();
		for (Map.Entry<String, Set<Function>> e : candidates.entrySet()) {
			if (e.getValue().size() != 1) {
				continue;
			}
			Function f = e.getValue().iterator().next();
			if (f.getSymbol().getSource() != SourceType.DEFAULT) {
				continue;
			}
			String[] parts = e.getKey().split("::");
			try {
				Namespace ns = symbols.getNamespace(parts[0], currentProgram.getGlobalNamespace());
				if (ns == null) {
					ns = symbols.createClass(currentProgram.getGlobalNamespace(), parts[0], SourceType.ANALYSIS);
				}
				f.setParentNamespace(ns);
				f.setName(parts[1], SourceType.ANALYSIS);
				labels.add(f.getEntryPoint() + "\t" + e.getKey());
				renamed++;
			}
			catch (Exception ex) {
				printerr("Could not name " + f.getEntryPoint() + " as " + e.getKey() + ": " + ex.getMessage());
			}
		}

		try (PrintWriter w = new PrintWriter(new File(outDir, "keyword_strings.txt"), "UTF-8")) {
			report.forEach(w::println);
		}
		try (PrintWriter w = new PrintWriter(new File(outDir, "named_functions.txt"), "UTF-8")) {
			labels.forEach(w::println);
		}
		println("Named " + renamed + " functions; " + report.size() + " keyword strings reported to " + outDir);
	}
}
