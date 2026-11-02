// For each "<hex start> <length>" range: the function / defined data covering it, every reference into it
// (from anywhere), any instruction defined inside it, and the instructions just before and after.
// Args: <output file> <hex start> <length> [...]
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class PlanRangeRefs extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		ReferenceManager rm = currentProgram.getReferenceManager();
		Listing listing = currentProgram.getListing();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 1; i + 1 < args.length; i += 2) {
				Address start = toAddr(args[i]);
				long len = Long.parseLong(args[i + 1]);
				Address end = start.add(len - 1);
				AddressSet set = new AddressSet(start, end);
				w.println("== " + start + " .. " + end);
				Function f = getFunctionContaining(start);
				Function g = getFunctionContaining(end);
				w.println("  function at start: " + (f == null ? "-" : f.getEntryPoint() + " " + f.getName()) + "; at end: "
					+ (g == null ? "-" : g.getEntryPoint() + " " + g.getName()));
				int refs = 0;
				for (Address a : rm.getReferenceDestinationIterator(set, true)) {
					for (Reference r : rm.getReferencesTo(a)) {
						w.println("  REF to " + a + " from " + r.getFromAddress() + " " + r.getReferenceType());
						refs++;
					}
				}
				// references from instructions that point near the range (tables indexed from just before it)
				AddressSet near = new AddressSet(start.subtract(0x100), end.add(0x10));
				for (Address a : rm.getReferenceDestinationIterator(near, true)) {
					if (set.contains(a)) {
						continue;
					}
					for (Reference r : rm.getReferencesTo(a)) {
						w.println("  near-ref to " + a + " from " + r.getFromAddress() + " " + r.getReferenceType());
					}
				}
				int ins = 0;
				InstructionIterator it = listing.getInstructions(set, true);
				while (it.hasNext()) {
					it.next();
					ins++;
				}
				DataIterator di = listing.getDefinedData(set, true);
				int data = 0;
				while (di.hasNext()) {
					Data d = di.next();
					w.println("  DATA " + d.getAddress() + " " + d.getDataType().getName());
					data++;
				}
				w.println("  refs " + refs + ", instructions inside " + ins + ", defined data " + data);
				Instruction before = getInstructionBefore(start);
				Instruction after = getInstructionAfter(end);
				w.println("  before: " + (before == null ? "-" : before.getAddress() + " " + before));
				w.println("  after:  " + (after == null ? "-" : after.getAddress() + " " + after));
			}
		}
	}
}
