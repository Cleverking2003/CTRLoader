package ctr;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

enum SegId {
	TEXT,
	RODATA,
	DATA,
	BSS
}

public class SegEntry {
	
	public int getOffset() {
		return offset;
	}

	public int getSize() {
		return size;
	}

	public SegId getId() {
		return id;
	}

	private int offset;
	private int size;
	private SegId id;
	
	public SegEntry(BinaryReader reader) throws IOException {
		offset = reader.readNextInt();
		size = reader.readNextInt();
		int id = reader.readNextInt();
		switch(id) {
		case 0:
			this.id = SegId.TEXT;
			break;
		case 1:
			this.id = SegId.RODATA;
			break;
		case 2:
			this.id = SegId.DATA;
			break;
		case 3:
			this.id = SegId.BSS;
			break;
		}
	}
	
}
