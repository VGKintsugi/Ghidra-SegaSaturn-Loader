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
package segasaturnloader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
//import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.util.bin.BinaryReader;

/**
* TODO: Provide class-level documentation that describes what this loader does.
*/

// TODO: Add Javadoc
public class SegaSaturnLoader extends AbstractLibrarySupportLoader {

	public static final int SATURN_INVALID = -1;
	public static final int SATURN_ISO = 0;
	public static final int SATURN_YSS = 1;

	public static int m_loadType = SATURN_INVALID;

	public static final int IP_SIZE_OFFSET = 0xE0;
	public static final int FIRST_READ_OFFSET = 0xF0;
	public static final int SECURITY_CODE_OFFSET = 0x100;
	public static final int AREA_CODE_OFFSETS = 0xE00;
	public static final int SATURN_HEADER_WRITE_ADDR = 0x06002000;
	public static final int MAX_SATURN_HEADER_SIZE = 0xF00;
	public static final int AREA_CODE_OFFSET = 0xE00;
	public static final int AREA_CODE_SIZE = 0x20;
	public static final int AREA_CODE_MAGIC = 0xA00E0009;

	//
	// Ghidra loader required functions
	//

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion
		// files.
		return "Sega Saturn (ISO/YSS)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		//
		// Check if this is a Sega Saturn ISO or Yabause Save State
		//

		if(isSegaSaturnIso(provider)) {
			m_loadType = SATURN_ISO;
		}
		else if(isYabauseSaveState(provider)) {
			m_loadType = SATURN_YSS;
		}

		if(m_loadType != SATURN_INVALID) {
			// TODO: This should use the Opinion service but I have no clue how that works
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH:BE:32:SH-2", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log)

	/*protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)*/
			throws CancelledException, IOException {

		try {

			createSegaSaturnMemoryMap(program, monitor, log);

			if(m_loadType == SATURN_ISO) {

				loadSegaSaturnHeader(provider, program, monitor, log);

				loadFirstExecutable(provider, program, monitor, log);
			}
			else if(m_loadType == SATURN_YSS) {

				loadYabauseSaveState(provider, program, monitor, log);

			} else {

				throw new IOException("Invalid Saturn loader type!!");
			}

		}catch(Exception e) {
			log.appendException(e);
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

		//return super.validateoptions(provider, loadSpec, options);
		return null;
	}

	//
	// Memory region creation functions
	// TODO: move to separate script so they can be called by raw binary files
	//

	public void createMemoryRegion(String regionName, long startAddress, long endAddress, boolean read, boolean write, boolean execute, Program program, TaskMonitor monitor, MessageLog log){

		try {
			Address addr;
			MemoryBlock block;

			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(startAddress);
			block = program.getMemory().createInitializedBlock(regionName, addr, endAddress-startAddress, (byte)0x00, monitor, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}

	// TODO: split this into separate script file so raw binaries can use this same code
	// TODO: add missing memory sections
	public void createSegaSaturnMemoryMap(Program program, TaskMonitor monitor, MessageLog log) {

		//
		// The Sega Saturn SH-2 Memory Map (https://wiki.yabause.org/index.php5?title=SH-2CPU)
		//
		// 0x00000000 	0x000FFFFF 	Boot ROM
		// 0x00100000 	0x0017FFFF 	SMPC Registers
		// 0x00180000 	0x001FFFFF 	Backup RAM
		// 0x00200000 	0x002FFFFF 	Work RAM Low
		// 0x00300000 	0x003FFFFF 	Random Data On Every Read (mostly $00)
		// 0x00400000 	0x007FFFFF 	Always Returns $0000.
		// 0x00800000 	0x00FFFFFF 	Always Returns $00000001000200030004000500060007.
		// 0x01000000 	0x01FFFFFF 	Always Returns $FFFF.
		// 0x02000000 	0x03FFFFFF 	A-Bus CS0
		// 0x04000000 	0x04FFFFFF 	A-Bus CS1
		// 0x05000000 	0x057FFFFF 	A-Bus Dummy
		// 0x05800000 	0x058FFFFF 	A-Bus CS2
		// 0x05900000 	0x059FFFFF 	Lockup When Read
		// 0x05A00000 	0x05AFFFFF 	68000 Work RAM
		// 0x05B00000 	0x05BFFFFF 	SCSP registers
		// 0x05C00000 	0x05C7FFFF 	VDP1 VRAM
		// 0x05C80000 	0x05CFFFFF 	VDP1 Framebuffer
		// 0x05D00000 	0x05D7FFFF 	VDP1 Registers
		// 0x05D80000 	0x05DFFFFF 	Lockup When Read2
		// 0x05E00000 	0x05EFFFFF 	VDP2 VRAM
		// 0x05F00000 	0x05F7FFFF 	VDP2 CRAM
		// 0x05F80000 	0x05FBFFFF 	VDP2 Registers
		// 0x05FC0000 	0x05FDFFFF 	Always Returns $000E0000
		// 0x05FE0000 	0x05FEFFFF 	SCU Registers
		// 0x05FF0000 	0x05FFFFFF 	Unknown Registers
		// 0x06000000 	0x07FFFFFF 	Work RAM High
		//

		try {
			// 0x00000000 - 0x000FFFFF: Boot ROM
			createMemoryRegion("Boot ROM", 0x00000000, 0x000FFFFF, true, false, true, program, monitor, log);

			// 0x00100000 	0x0017FFFF 	SMPC Registers
			createMemoryRegion("SMPC Registers", 0x00100000, 0x0017FFFF, true, true, true, program, monitor, log);

			// 0x00180000 	0x001FFFFF 	Backup RAM
			createMemoryRegion("Backup RAM", 0x00180000, 0x001FFFFF, true, true, true, program, monitor, log);

			// 0x00200000 - 0x002FFFFF: Work RAM Low
			createMemoryRegion("Work RAM Low", 0x00200000, 0x002FFFFF + 1, true, true, true, program, monitor, log);

			// 0x00300000 	0x003FFFFF 	Random Data On Every Read (mostly $00)
			createMemoryRegion("Random Data On Every Read", 0x00300000, 0x003FFFFF, true, true, true, program, monitor, log);

			// 0x00400000 	0x007FFFFF 	Always Returns $0000
			createMemoryRegion("Always Returns $0000", 0x00400000, 0x007FFFFF, true, true, true, program, monitor, log);

			// 0x00800000 	0x00FFFFFF 	Always Returns $00000001000200030004000500060007
			createMemoryRegion("Always Returns $1234567", 0x00800000, 0x00FFFFFF, true, true, true, program, monitor, log);

			// 0x01000000 	0x01FFFFFF 	Always Returns $FFFF.
			createMemoryRegion("Always Returns $FFFF", 0x01000000, 0x01FFFFFF, true, true, true, program, monitor, log);

			// 0x02000000 	0x03FFFFFF 	A-Bus CS0
			createMemoryRegion("A-Bus CS0", 0x02000000, 0x03FFFFFF, true, true, true, program, monitor, log);

			// 0x04000000 	0x04FFFFFF 	A-Bus CS1
			createMemoryRegion("A-Bus CS1", 0x04000000, 0x04FFFFFF, true, true, true, program, monitor, log);

			// 0x05000000 	0x057FFFFF 	A-Bus Dummy
			createMemoryRegion("A-Bus Dummy", 0x05000000, 0x057FFFFF, true, true, true, program, monitor, log);

			// 0x05800000 	0x058FFFFF 	A-Bus CS2
			createMemoryRegion("A-Bus CS2", 0x05800000, 0x058FFFFF, true, true, true, program, monitor, log);

			// 0x05900000 	0x059FFFFF 	Lockup When Read
			createMemoryRegion("Lockup When Read", 0x05900000, 0x059FFFFF, true, true, true, program, monitor, log);

			// 0x05A00000 	0x05AFFFFF 	68000 Work RAM
			createMemoryRegion("68000 Work RAM", 0x05A00000, 0x05AFFFFF, true, true, true, program, monitor, log);

			// 0x05B00000 	0x05BFFFFF 	SCSP Registers
			createMemoryRegion("SCSP registers", 0x05B00000, 0x05BFFFFF, true, true, true, program, monitor, log);

			// 0x05C00000 	0x05C7FFFF 	VDP1 VRAM
			createMemoryRegion("VDP1 VRAM", 0x05C00000, 0x05C7FFFF, true, true, true, program, monitor, log);

			// 0x05C80000 	0x05CFFFFF 	VDP1 Framebuffer
			createMemoryRegion("Work RAM Low", 0x05C80000, 0x05CFFFFF, true, true, true, program, monitor, log);

			// 0x05D00000 	0x05D7FFFF 	VDP1 Registers
			createMemoryRegion("VDP1 Registers", 0x05D00000, 0x05D7FFFF, true, true, true, program, monitor, log);

			// 0x05D80000 	0x05DFFFFF 	Lockup When Read2
			createMemoryRegion("Lockup When Read2", 0x05D80000, 0x05DFFFFF, true, true, true, program, monitor, log);

			// 0x05E00000 	0x05EFFFFF 	VDP2 VRAM
			createMemoryRegion("VDP2 VRAM", 0x05E00000, 0x05EFFFFF, true, true, true, program, monitor, log);

			// 0x05F00000 	0x05F7FFFF 	VDP2 CRAM
			createMemoryRegion("VDP2 CRAM", 0x05F00000, 0x05F7FFFF, true, true, true, program, monitor, log);

			// 0x05F80000 	0x05FBFFFF 	VDP2 Registers
			createMemoryRegion("VDP2 Registers", 0x05F80000, 0x05FBFFFF, true, true, true, program, monitor, log);

			// 0x05FC0000 	0x05FDFFFF 	Always Returns $000E0000
			createMemoryRegion("Always Returns $E0000", 0x05FC0000, 0x05FDFFFF, true, true, true, program, monitor, log);

			// 0x05FE0000 	0x05FEFFFF 	SCU Registers
			createMemoryRegion("SCU Registers", 0x05FE0000, 0x05FEFFFF, true, true, true, program, monitor, log);

			// 0x05FF0000 	0x05FFFFFF 	Unknown Registers
			createMemoryRegion("Unknown Registers", 0x05FF0000, 0x05FFFFFF, true, true, true, program, monitor, log);

			// 0x06000000 - 0x07FFFFFF: Work RAM High
			createMemoryRegion("Work RAM High", 0x06000000, 0x07FFFFFF, true, true, true, program, monitor, log);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}

	// helper function to swap the endianess of a 32-bit value
	public long swapLongEndianess(long val) {

		long result = Long.reverseBytes(val);
		result = result >> 32;
		return result;
	}

	//
	// Sega Saturn ISO loading functions
	//

	public boolean isSegaSaturnIso(ByteProvider provider) throws IOException{

		// All Sega Saturn discs begin with this string
		String signature = "SEGA SEGASATURN";

		if(provider.length() >= signature.length()) {

			byte sig[] = provider.readBytes(0, signature.length());
			if(Arrays.equals(sig, signature.getBytes())) {
				return true;
			}
		}

		return false;
	}

	// Copies the Sega Saturn header and initial program to 0x06002000
	public void loadSegaSaturnHeader(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// The Sega Saturn header is the first ~0xF00 bytes of the disc
		//
		// - At IP_SIZE_OFFSET is a DWORD that is the size of the initial program
		// - At SECURITY_CODE_OFFSET is 0xD00 bytes of the security check code
		// - Next is a variable length array of 0x20 byte area codes
		// - Finally there is the initial program code (runs during Sega logo) which is IP_SIZE bytes long
		//

		try {
			Address addr;
			AddressSet addrSet;

			BinaryReader reader = new BinaryReader(provider, true);

			// obtain the length of the initial program
			long ip_size = swapLongEndianess(reader.readUnsignedInt(IP_SIZE_OFFSET));

			// The ISO's Sega Saturn header (variable length, begins at offset 0) are copied to 0x06002000.
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SATURN_HEADER_WRITE_ADDR);
			byte romBytes[] = provider.readBytes(0, ip_size + MAX_SATURN_HEADER_SIZE);
			program.getMemory().setBytes(addr, romBytes);

			// create a function for the security check code
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SATURN_HEADER_WRITE_ADDR + SECURITY_CODE_OFFSET);
			addrSet = new AddressSet(addr); // TODO: no clue how AddressSet works
			program.getFunctionManager().createFunction("security_check", addr, addrSet, SourceType.IMPORTED);

			long area_code_offset = 0;
			long area_code_magic = 0;

			// count the number of area codes so we can skip them
			for(int i = 0; i < 10; i++)	{

				area_code_offset = AREA_CODE_OFFSET + (i*AREA_CODE_SIZE);
				area_code_magic = swapLongEndianess(reader.readUnsignedInt(area_code_offset));

				if(area_code_magic != AREA_CODE_MAGIC) {
					// done with area code section
					break;
				}
			}

			if(area_code_offset > MAX_SATURN_HEADER_SIZE) {
				throw new IOException("Malformed area code offsets!!");
			}

			// create a function for the initial program (runs during Sega logo)
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SATURN_HEADER_WRITE_ADDR + area_code_offset);
			addrSet = new AddressSet(addr); // TODO: no clue how AddressSet works
			program.getFunctionManager().createFunction("initial_program", addr, addrSet, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}

	public static final int ISO_SECTOR_SIZE = 0x800;
	public static final int ISO_PVD_OFF = 0x8000;
	public static final int ISO_PVD_SIGNATURE = 0x01434430; // "\x01CD0"
	public static final int ISO_PVD_DIRECTORY_ENTRY_OFF = 0x9C;
	public static final int ISO_DIR_SIZE = 0x22;
	public static final int ISO_FAD_OFF = 0x02;
	public static final int ISO_FILE_SIZE_OFF = 0x08;

	// Loads the first executable on the disc to the address specified by the header
	public void loadFirstExecutable(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// To load the first file on the ISO 996 disc we have to:
		// - find the PVD at ISO_PVD_OFF
		// - look at the root directory entry at ISO_PVD_DIRECTORY_ENTRY_OFF from there
		// - find the FAD to the root directory
		// - skip the "." and ".." files
		// - after those files the first actual file is present
		//
		// Reference: https://wiki.osdev.org/ISO_9660
		//

		try {
			Address addr;
			AddressSet addrSet;
			long curr;

			BinaryReader reader = new BinaryReader(provider, true);

			//
			// Parse ISO 9660 just enough to find the first actual file on the disc
			// TODO: use an ISO parsing library??
			//

			// validate the PVD
			curr = ISO_PVD_OFF;
			long pvdSignature = swapLongEndianess(reader.readUnsignedInt(curr));
			if(pvdSignature != ISO_PVD_SIGNATURE) {
				throw new IOException("Invalid PVD signature!!");
			}

			// read the directory entry
			curr += ISO_PVD_DIRECTORY_ENTRY_OFF;
			long dirSize = reader.readByte(curr);
			if(dirSize != ISO_DIR_SIZE)	{
				throw new IOException("Invalid directory size!!");
			}

			// Get the FAD to the root directory
			curr += ISO_FAD_OFF;
			long dirFAD = reader.readUnsignedInt(curr);

			// The first file is "."
			curr = dirFAD * ISO_SECTOR_SIZE;
			dirSize = reader.readByte(curr);
			if(dirSize != ISO_DIR_SIZE) {
				throw new IOException("Invalid directory size!!");
			}

			// The second file is ".."
			curr += ISO_DIR_SIZE;
			dirSize = reader.readByte(curr);
			if(dirSize != ISO_DIR_SIZE)	{
				throw new IOException("Invalid directory size!!");
			}

			// The third file is the actual code to run
			curr += ISO_DIR_SIZE;
			dirSize = reader.readByte(curr);
			if(dirSize == ISO_DIR_SIZE)	{
				throw new IOException("Invalid directory size!!");
			}

			// read the code file's FAD
			curr += ISO_FAD_OFF;
			long fileFAD = reader.readUnsignedInt(curr);

			// get the size of the first file
			curr += ISO_FILE_SIZE_OFF;
			long fileSize = reader.readUnsignedInt(curr);

			// The Sega Saturn header contains the address of where to write the first file on the disc
			long readAddress = swapLongEndianess(reader.readUnsignedInt(FIRST_READ_OFFSET));

			// copy the executable file to first readAddress
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(readAddress);
			byte romBytes[] = provider.readBytes(fileFAD * ISO_SECTOR_SIZE, fileSize);
			program.getMemory().setBytes(addr, romBytes);

			// create a function at readAddress
			addrSet = new AddressSet(addr); // TODO: no clue how AddressSet works
			program.getFunctionManager().createFunction("main", addr, addrSet, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}

	//
	// Yabause Save State (YSS) loading functions
	//

	public boolean isYabauseSaveState(ByteProvider provider) throws IOException{

		// Yabause Save States start with this signature
		String signature = "YSS";

		if(provider.length() >= signature.length()) {

			byte sig[] = provider.readBytes(0, signature.length());
			if(Arrays.equals(sig, signature.getBytes())) {

				return true;
			}
		}

		return false;
	}

	public long yssGetRegionSize(String regionName, long regionAddress, ByteProvider provider, long startPos, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// Each Yabause Save State (YSS) memory region starts with:
		//
		// - 4 byte tag
		// - 4 byte version
		// - 4 byte size
		// - size bytes of memory
		//

		final int YSS_SIZE_OF_TAG = 4;
		final int YSS_SIZE_OF_VER = 4;
		final int YSS_SIZE_OF_SIZE = 4;

		long currPos = startPos;
		long regionSize = 0;

		try {
			BinaryReader reader = new BinaryReader(provider, true);

			// 4-byte tag
			byte tag[] = provider.readBytes(currPos, YSS_SIZE_OF_TAG);
			currPos += YSS_SIZE_OF_TAG;

			String tagString = new String(tag);

			if(!tagString.equals(regionName)){
				throw new IOException("Invalid YSS tag name!!");
			}

			// 4-byte version, unused
			currPos += YSS_SIZE_OF_VER;

			regionSize = reader.readInt(currPos);
			currPos += YSS_SIZE_OF_SIZE;
		}
		catch(Exception e) {
			log.appendException(e);
			return -1;
		}

		return regionSize;
	}

		// create labels for the PC and PR registers
	public long yssLabelSH2Regs(String regionName, long regionAddress, ByteProvider provider, long startPos, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// Each Yabause Save State (YSS) memory region starts with:
		//
		// - 4 byte tag
		// - 4 byte version
		// - 4 byte size
		// - size bytes of memory
		//
		// The MSH2 and SSH2 regions are then followed by a struct of 4 byte registers
		// see https://github.com/Yabause/yabause/blob/f2ebf5ab6161babe66836f94b3fa71453133f128/yabause/src/sh2core.h
		// for reference.
		//

		final int YSS_SIZE_OF_TAG = 4;
		final int YSS_REG_SIZE = 4;
		final int YSS_REGION_HEADER_SIZE = 12;

		long currPos = startPos;
		long R15 = 0;
		long PC = 0;
		long PR = 0;
		Address addr;

		try {

			BinaryReader reader = new BinaryReader(provider, true);

			// 4-byte tag
			byte tag[] = provider.readBytes(currPos, YSS_SIZE_OF_TAG);
			String tagString = new String(tag);

			if(!tagString.equals(regionName)){
				throw new IOException("Invalid YSS tag name!!");
			}

			// 4-byte version, unused
			currPos += YSS_REGION_HEADER_SIZE;

			if(regionName == "SSH2")
			{
				// Slave SSH2 has an extra byte field "IsSSH2Running" which we skip
				currPos += 1;
			}

			// skip the first 15 registers to get to R15
			currPos += 15 * YSS_REG_SIZE;

			R15 = reader.readInt(currPos);
			currPos += YSS_REG_SIZE;
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(R15);
			program.getSymbolTable().createLabel(addr, regionName + "_R15", null, SourceType.IMPORTED);

			// skip the next 5 registers to get to PR and PC
			currPos += 5 * YSS_REG_SIZE;

			PR = reader.readInt(currPos);
			currPos += YSS_REG_SIZE;
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(PR);
			program.getSymbolTable().createLabel(addr, regionName + "_PR", null, SourceType.IMPORTED);

			PC = reader.readInt(currPos);
			currPos += YSS_REG_SIZE;
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(PC);
			program.getSymbolTable().createLabel(addr, regionName + "_PC", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
			return -1;
		}

		return 0;
	}

	public long swapWordOrder(byte byteArray[])	{

		for(int i = 0; i < byteArray.length; i += 2){

			byte temp = byteArray[i];
			byteArray[i] = byteArray[i+1];
			byteArray[i+1] = temp;
		}

		return 0;
	}

	public long readYSSRegion(long regionAddress, int regionSize, boolean swapWordOrder, ByteProvider provider, long startPos, Program program, TaskMonitor monitor, MessageLog log) {

		try {
			// load the region into memory
			BinaryReader reader = new BinaryReader(provider, false);

			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(regionAddress);
			byte romBytes[] = reader.readByteArray(startPos, regionSize);

			// TODO: not sure why, but Yabause Save States are formatted weirdly
			if(swapWordOrder) {
				swapWordOrder(romBytes);
			}

			program.getMemory().setBytes(addr, romBytes);
		}
		catch(Exception e) {
			log.appendException(e);
			return -1;
		}

		return regionSize;
	}

	public void loadYabauseSaveState(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// The Yabause Save State (YSS) is documented in YabLoadStateStream in https://github.com/Yabause/yabause/blob/master/yabause/src/memory.c
		//

		final int HEADER_VERSION_OFF = 4;
		final int HEADER_SIZE_VERSION_1 = 0xC;
		final int HEADER_SIZE_VERSION_2 = 0x14;
		final int REGION_HEADER_SIZE = 0xC;

		long regionSize = 0;

		try {

			BinaryReader reader = new BinaryReader(provider, true);

			long currPos = 0;
			long version = 0;
			int headerSize = 0;

			// we already checked the signature earlier, no need to check it again
			currPos += HEADER_VERSION_OFF;

			version = reader.readUnsignedInt(currPos);
			if(version == 1) {
				headerSize = HEADER_SIZE_VERSION_1;
			}
			else if(version == 2) {
				headerSize = HEADER_SIZE_VERSION_2;
			}
			else{
				throw new IOException("Invalid YSS version!!");
			}

			currPos = headerSize;

			// Cart doesn't actually appear to be saved??
			regionSize = yssGetRegionSize("CART", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS CART memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// CS2
			regionSize = yssGetRegionSize("CS2 ", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS CS2 memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// MSH2
			regionSize = yssGetRegionSize("MSH2", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS MSH2 memory");
			}
			yssLabelSH2Regs("MSH2", 0, provider, currPos, program, monitor, log);
			currPos += REGION_HEADER_SIZE + regionSize;

			// SSH2
			regionSize = yssGetRegionSize("SSH2", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS SSH2 memory");
			}
			yssLabelSH2Regs("SSH2", 0, provider, currPos, program, monitor, log);
			currPos += REGION_HEADER_SIZE + regionSize;

			// SCSP
			regionSize = yssGetRegionSize("SCSP", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS SCSP memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// SCU
			regionSize = yssGetRegionSize("SCU ", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS SCU memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// SMPC
			regionSize = yssGetRegionSize("SMPC", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS SMPC memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// VDP1
			regionSize = yssGetRegionSize("VDP1", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS VDP1 memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// VDP2
			regionSize = yssGetRegionSize("VDP2", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS VDP2 memory");
			}
			currPos += REGION_HEADER_SIZE + regionSize;

			// OTHR
			regionSize = yssGetRegionSize("OTHR", 0, provider, currPos, program, monitor, log);
			if(regionSize < 0)	{
				throw new IOException("Failed to load YSS OTHR memory");
			}
			currPos += REGION_HEADER_SIZE;

			// Backup RAM
			readYSSRegion(0x00180000, 0x10000, false, provider, currPos, program, monitor, log);
			currPos += 0x10000;

			// high work ram
			readYSSRegion(0x06000000, 0x100000, true, provider, currPos, program, monitor, log);
			currPos += 0x100000;

			// low work ram
			readYSSRegion(0x00200000, 0x100000, true, provider, currPos, program, monitor, log);
			currPos += 0x100000;
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}
}
