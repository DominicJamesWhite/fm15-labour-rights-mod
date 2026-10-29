// Dumps a function's first instructions and every RET, with bytes and file offsets, for writing patches.
// Args: <output file> <hex address>...
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.database.mem.AddressSourceInfo;

public class DumpInstructions extends GhidraScript {

	private static final int HEAD = 12;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (int i = 1; i < args.length; i++) {
				if (args[i].contains("-")) {
					// start-end: dump every instruction in the range
					String[] r = args[i].split("-");
					w.println("===== range " + args[i]);
					for (Instruction ins : currentProgram.getListing()
							.getInstructions(currentProgram.getAddressFactory().getAddressSet(toAddr(r[0]), toAddr(r[1])), true)) {
						w.println(line(ins));
					}
					continue;
				}
				Function f = getFunctionContaining(toAddr(args[i]));
				w.println("===== " + f.getEntryPoint() + " " + f.getName(true) + " (" +
					f.getCallingConventionName() + ", stack purge " + f.getStackPurgeSize() + ")");
				int n = 0;
				for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
					boolean ret = ins.getMnemonicString().startsWith("RET");
					if (n++ < HEAD || ret) {
						w.println(line(ins));
					}
				}
			}
		}
	}

	private String line(Instruction ins) throws Exception {
		Address a = ins.getAddress();
		AddressSourceInfo src = currentProgram.getMemory().getAddressSourceInfo(a);
		StringBuilder hex = new StringBuilder();
		for (byte b : ins.getBytes()) {
			hex.append(String.format("%02x ", b));
		}
		return String.format("%s  file+0x%x  %-24s %s", a, src.getFileOffset(), hex, ins);
	}
}
