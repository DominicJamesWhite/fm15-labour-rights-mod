// Dumps raw data values from the program image: each argument "<kind>:<hex address>:<count>" where kind is
// f (float32), d (double), i (int32), h (int16), b (byte). Read-only.
// Args: <output file> <spec>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class ParityDumpData extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Memory m = currentProgram.getMemory();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 1; i < args.length; i++) {
				String[] p = args[i].split(":");
				String kind = p[0];
				Address a = toAddr(p[1]);
				int n = p.length > 2 ? Integer.parseInt(p[2]) : 1;
				for (int k = 0; k < n; k++) {
					String v;
					switch (kind) {
					case "f": v = Float.toString(Float.intBitsToFloat(m.getInt(a))); a = a.add(4); break;
					case "d": v = Double.toString(Double.longBitsToDouble(m.getLong(a))); a = a.add(8); break;
					case "i": v = Integer.toString(m.getInt(a)) + " (0x" + Integer.toHexString(m.getInt(a)) + ")"; a = a.add(4); break;
					case "h": v = Short.toString(m.getShort(a)); a = a.add(2); break;
					default: v = Integer.toString(m.getByte(a) & 0xff); a = a.add(1); break;
					}
					w.println(kind + " " + p[1] + "[" + k + "] = " + v);
				}
			}
		}
	}
}
