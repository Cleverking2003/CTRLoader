package ctr;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class NamedExportEntry {
	private int nameOffset;
	private int segOffset;
	
	public int getNameOffset() {
		return nameOffset;
	}

	public int getSegOffset() {
		return segOffset;
	}

	public NamedExportEntry(BinaryReader reader) throws IOException {
		nameOffset = reader.readNextInt();
		segOffset = reader.readNextInt();
	}
}
