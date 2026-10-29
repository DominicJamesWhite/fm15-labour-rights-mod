// Lists functions in an address range with size and caller count.
// Args: <output file> <start hex> <end hex>
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class SquadListRange extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] a = getScriptArgs();
		try (PrintWriter w = new PrintWriter(new File(a[0]), "UTF-8")) {
			for (Function f : currentProgram.getFunctionManager()
					.getFunctions(currentProgram.getAddressFactory().getAddressSet(toAddr(a[1]), toAddr(a[2])), true)) {
				w.printf("%s size=%d callers=%d%n", f.getEntryPoint(), f.getBody().getNumAddresses(),
					f.getCallingFunctions(monitor).size());
			}
		}
	}
}
