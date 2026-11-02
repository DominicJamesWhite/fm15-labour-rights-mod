// Finds functions that write both a "season" CLUB_FINANCE accumulator [reg + d] (d in lo..hi) and its
// "month" twin [reg + d - delta] in the same function (ADD/SUB/MOV/INC/DEC with a memory destination).
// Lists each such function with the slot pairs, mnemonics, vftable slots that point at it, and caller count.
// Args: <output file> <hex lo> <hex hi> <hex delta> [<hex vftable start> <slot count>]
//@category FM15

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

public class ParityAccumPairs extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long lo = Long.parseLong(args[1], 16), hi = Long.parseLong(args[2], 16), delta = Long.parseLong(args[3], 16);
		Map<Long, String> vslot = new HashMap<>();
		if (args.length >= 6) {
			Address vt = toAddr(args[4]);
			int n = Integer.parseInt(args[5]);
			for (int i = 0; i < n; i++) {
				long p = getInt(vt.add(4L * i)) & 0xffffffffL;
				vslot.merge(p, String.format("+0x%x", 4 * i), (a, b) -> a + "," + b);
			}
		}
		Listing listing = currentProgram.getListing();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				Map<Long, Set<String>> writes = new TreeMap<>();
				for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
					String m = ins.getMnemonicString();
					if (!(m.equals("ADD") || m.equals("SUB") || m.equals("MOV") || m.equals("INC") || m.equals("DEC"))) {
						continue;
					}
					if (ins.getNumOperands() < 1 || (ins.getOperandType(0) & OperandType.DYNAMIC) == 0) {
						continue;
					}
					for (Object o : ins.getOpObjects(0)) {
						if (o instanceof Scalar) {
							long d = ((Scalar) o).getUnsignedValue();
							if ((d >= lo && d <= hi) || (d >= lo - delta && d <= hi - delta)) {
								writes.computeIfAbsent(d, k -> new TreeSet<>()).add(m + "@" + ins.getAddress());
							}
						}
					}
				}
				StringBuilder sb = new StringBuilder();
				for (long d = lo; d <= hi; d += 4) {
					if (writes.containsKey(d) && writes.containsKey(d - delta)) {
						sb.append(String.format("   season +0x%x %s | month +0x%x %s%n", d, writes.get(d), d - delta, writes.get(d - delta)));
					}
				}
				if (sb.length() > 0) {
					long e = f.getEntryPoint().getOffset();
					int callers = getReferencesTo(f.getEntryPoint()).length;
					w.println(f.getEntryPoint() + " " + f.getName() + " size " + f.getBody().getNumAddresses() + " refs " + callers
							+ (vslot.containsKey(e) ? " vt" + vslot.get(e) : ""));
					w.print(sb);
				}
			}
		}
	}
}
