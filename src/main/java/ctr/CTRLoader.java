/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ctr;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class CTRLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "3DS loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);
		
		if (reader.readAsciiString(0x80, 4).equals("CRO0")) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), true));
		}

		return loadSpecs;
	}
	
	protected int DecodeSegOffset(List<SegEntry> segs, int off) {
		return segs.get(off & 0xf).getOffset() + (off >> 4);
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		List<SegEntry> segTable = new ArrayList<>();
		int segTableOffset = reader.readInt(0xc8);
		int segTableSize = reader.readInt(0xcc);
		
		reader.setPointerIndex(segTableOffset);
		for (int i = 0; i < segTableSize; i++) {
			segTable.add(new SegEntry(reader));
		}
		
		for (SegEntry seg : segTable) {
			if (seg.getSize() != 0) {
				FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, seg.getOffset(), seg.getSize(), monitor);
				try {
					if (seg.getId() == SegId.BSS) {
						MemoryBlockUtils.createInitializedBlock(program, false, seg.getId().name(), program.getAddressFactory().getDefaultAddressSpace().getAddress(0x80000000), seg.getSize(), "", null, true, true, false, log);
					}
					else {
						MemoryBlockUtils.createInitializedBlock(program, false, seg.getId().name(), program.getAddressFactory().getDefaultAddressSpace().getAddress(seg.getOffset()), fileBytes, 0, seg.getSize(), "", null, true, true, true, log);
					}
				} catch (AddressOverflowException e) {
					e.printStackTrace();
				}
			}
		}
		
		int relocPatchOffset = reader.readInt(0x128);
		int relocPatchSize = reader.readInt(0x12c);
		List<PatchEntry> relocPatches = new ArrayList<>();
		
		reader.setPointerIndex(relocPatchOffset);
		for (int i = 0; i < relocPatchSize; i++) {
			relocPatches.add(new PatchEntry(reader));
		}
		
		for (PatchEntry patch : relocPatches) {
			int targetInt = DecodeSegOffset(segTable, patch.getSegOffset());
			Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(targetInt);
			int base = segTable.get(patch.getRefSegment()).getOffset() + patch.getAddend();
			switch(patch.getType()) {
			case 2:
				try {
					program.getMemory().setInt(target, base);
				} catch (MemoryAccessException e) {
					e.printStackTrace();
				}
				break;
			case 3:
				try {
					base -= targetInt;
					if (base < 0) base += 0x10000000;
					program.getMemory().setInt(target, base);
				} catch (MemoryAccessException e) {
					e.printStackTrace();
				};
			}
		}
		
		int namedExportOffset = reader.readInt(0xd0);
		int namedExportSize = reader.readInt(0xd4);
		List<NamedExportEntry> namedExportTable = new ArrayList<>();
		
		reader.setPointerIndex(namedExportOffset);
		for (int i = 0; i < namedExportSize; i++) {
			namedExportTable.add(new NamedExportEntry(reader));
		}
		
		for (NamedExportEntry entry : namedExportTable) {
			int realOffset = entry.getSegOffset() >> 4;
			int base = segTable.get(entry.getSegOffset() & 0xf).getOffset();
			String name = reader.readTerminatedString(entry.getNameOffset(), '\0');
			try {
				Address func = program.getAddressFactory().getDefaultAddressSpace().getAddress(base + realOffset);
				program.getFunctionManager().createFunction(name, func, new AddressSet(func), SourceType.ANALYSIS);
			} catch (InvalidInputException | AddressOutOfBoundsException | OverlappingFunctionException e) {
				e.printStackTrace();
			}
		}
		
		String funcs[] = {"OnLoad", "OnExit", "OnUnresolved"};
		reader.setPointerIndex(0xa4);
		for (int i = 0; i < 2; i++) {
			int func = reader.readNextInt();
			if (func != 0xffffffff) {
				Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(func);
				try {
					program.getFunctionManager().createFunction(funcs[i], funcAddr, new AddressSet(funcAddr), SourceType.ANALYSIS);
				} catch (InvalidInputException | OverlappingFunctionException e) {
					e.printStackTrace();
				}
			}
		}
		
		int importPatchesOffset = reader.readInt(0xf8);
		int importPatchesSize = reader.readInt(0xfc);
		List<PatchEntry> importPatches = new ArrayList<PatchEntry>();
		
		reader.setPointerIndex(importPatchesOffset);
		for (int i = 0; i < importPatchesSize; i++) {
			importPatches.add(new PatchEntry(reader));
		}
		
		for (PatchEntry patch : importPatches) {
			int targetInt = DecodeSegOffset(segTable, patch.getSegOffset());
			Address target = program.getAddressFactory().getDefaultAddressSpace().getAddress(targetInt);
			int base = segTable.get(patch.getRefSegment()).getOffset() + patch.getAddend();
			switch(patch.getType()) {
			case 2:
				try {
					program.getMemory().setInt(target, base);
				} catch (MemoryAccessException e) {
					e.printStackTrace();
				}
				break;
			case 3:
				try {
					base = Math.abs(base - targetInt);
					program.getMemory().setInt(target, base);
				} catch (MemoryAccessException e) {
					e.printStackTrace();
				};
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
