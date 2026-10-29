// Applies byte patches in memory (project opened read-only, nothing saved), disassembles them and
// prints the resulting instructions.
// Args: <output file> <patch list file: one "VA hexbytes" per line, hex bytes without spaces>
//@category FM15

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;

public class NoticeVerifyPatch extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		try (PrintWriter w = new PrintWriter(new File(args[0]), "UTF-8")) {
			for (String line : java.nio.file.Files.readAllLines(new File(args[1]).toPath())) {
				if (line.isBlank()) {
					continue;
				}
				String[] p = line.trim().split("\\s+");
				Address start = toAddr(p[0]);
				byte[] bytes = new byte[p[1].length() / 2];
				for (int b = 0; b < bytes.length; b++) {
					bytes[b] = (byte) Integer.parseInt(p[1].substring(2 * b, 2 * b + 2), 16);
				}
				Address end = start.add(bytes.length - 1);
				clearListing(start, end);
				setBytes(start, bytes);
				new DisassembleCommand(new AddressSet(start, end), null, false).applyTo(currentProgram, monitor);
				w.println("===== " + start);
				for (Instruction ins : currentProgram.getListing().getInstructions(new AddressSet(start, end), true)) {
					w.println(ins.getAddress() + "  " + ins);
				}
			}
		}
	}
}
