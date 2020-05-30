package ctr;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class PatchEntry {
	private int segOffset;
	private byte type;
	private byte refSegment;
	private int addend;
	
	public int getSegOffset() {
		return segOffset;
	}

	public byte getType() {
		return type;
	}

	public byte getRefSegment() {
		return refSegment;
	}

	public int getAddend() {
		return addend;
	}

	public PatchEntry(BinaryReader reader) throws IOException {
		segOffset = reader.readNextInt();
		type = reader.readNextByte();
		refSegment = reader.readNextByte();
		reader.readNextByte();
		reader.readNextByte();
		addend = reader.readNextInt();
	}
}
