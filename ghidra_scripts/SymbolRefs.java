// Lists every reference to symbols with the given names (e.g. imported API functions), with the
// containing function, following thunks one level.
// Args: <output file> <symbol name>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

public class SymbolRefs extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		ReferenceManager refs = currentProgram.getReferenceManager();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 1; i < args.length; i++) {
				for (Symbol s : currentProgram.getSymbolTable().getSymbols(args[i])) {
					w.println("SYMBOL " + s.getName(true) + " @ " + s.getAddress());
					for (Reference r : refs.getReferencesTo(s.getAddress())) {
						Function f = getFunctionContaining(r.getFromAddress());
						w.println("   " + r.getFromAddress() + " " + r.getReferenceType() + "  in " +
							(f == null ? "<none>" : f.getEntryPoint() + " " + f.getName(true)));
						// thunk or IAT slot: also list who references the referencing function
						if (f != null && f.isThunk()) {
							for (Reference r2 : refs.getReferencesTo(f.getEntryPoint())) {
								Function g = getFunctionContaining(r2.getFromAddress());
								w.println("      via thunk: " + r2.getFromAddress() + " in " +
									(g == null ? "<none>" : g.getEntryPoint() + " " + g.getName(true)));
							}
						}
					}
				}
			}
		}
	}
}
