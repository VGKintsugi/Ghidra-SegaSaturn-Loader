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
import generic.jar.ResourceFile;

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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.framework.Application;


import ghidra.program.model.listing.Function;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.listing.Function.FunctionUpdateType;


/**
* TODO: Provide class-level documentation that describes what this loader does.
*/

// TODO: Add Javadoc
public class SegaSaturnLoader extends AbstractLibrarySupportLoader {

	public static final int SATURN_INVALID = -1;
	public static final int SATURN_ISO = 0;
	public static final int SATURN_MSS = 1;
	public static final int SATURN_YSS = 2;

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

	// master and slave registers parsed from the save states
	long MSH2_PC;
	long MSH2_PR;
	long MSH2_R15;

	long SSH2_PC;
	long SSH2_PR;
	long SSH2_R15;

	// hashmap of all sections in the Mednafen Save State
	HashMap<String, Long> mssSectionMap;

	// types from /Data/bios.gdt
	DataTypeManager biosDataTypeManager;

	//
	// Ghidra loader required functions
	//

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion
		// files.
		return "Sega Saturn (ISO/MC/YSS)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		//
		// Check if this is a Sega Saturn ISO, Mednafen Save State, or Yabause Save State
		//

		if(isSegaSaturnIso(provider)) {
			m_loadType = SATURN_ISO;
		}
		else if(isMednafenSaveState(provider)) {
			m_loadType = SATURN_MSS;
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
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		try {

			// load bios data types
			biosDataTypeManager = loadBiosDataTypeManager();

			createSegaSaturnMemoryMap(program, monitor, log);

			if(m_loadType == SATURN_ISO) {

				loadSegaSaturnHeader(provider, program, monitor, log);

				loadFirstExecutable(provider, program, monitor, log);
			}
			else if(m_loadType == SATURN_MSS) {

				loadMednafenSaveState(provider, program, monitor, log);

			}
			else if(m_loadType == SATURN_YSS) {

				loadYabauseSaveState(provider, program, monitor, log);

			} else {

				throw new IOException("Invalid Saturn loader type!!");
			}

			// needs to after bytes are loaded to the program
			labelBackupFunctions(program, log);

			// success
			log.appendMsg("This\n  is\n  COOL");

		}catch(Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram, mirrorFsLayout);

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

	public DataTypeManager loadBiosDataTypeManager() throws IOException {

		ResourceFile biosArchiveFile = Application.getModuleDataFile("Ghidra-SegaSaturn-Loader", "bios.gdt");
		FileDataTypeManager fileDtm = FileDataTypeManager.openFileArchive(biosArchiveFile, false);

		return fileDtm;
	}

	//
	// Memory region creation functions
	// TODO: move to separate script so they can be called by raw binary files
	//

	public void createMemoryRegion(String regionName, long startAddress, long endAddress, boolean read, boolean write, boolean execute, Program program, TaskMonitor monitor, MessageLog log){

		try {
			Address addr;
			MemoryBlock block;

			// Ghidra 9.2 no longer allows spaces in region names
			regionName = regionName.replaceAll("\\s+","_");

			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(startAddress);
			block = program.getMemory().createInitializedBlock(regionName, addr, endAddress-startAddress, (byte)0x00, monitor, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);

			// create a cached region
			if((startAddress & 0x20000000) == 0)
			{
				Address cacheAddr;

				cacheAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(startAddress | 0x20000000);

				block = program.getMemory().createByteMappedBlock​(regionName + "_Cache", cacheAddr, addr, endAddress-startAddress, false);
				block.setRead(read);
				block.setWrite(write);
				block.setExecute(execute);
			}
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
		// 0xFFFFFE00 	0xFFFFFFFF	On Chip Registers

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
			createMemoryRegion("VDP1 Framebuffer", 0x05C80000, 0x05CFFFFF, true, true, true, program, monitor, log);

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

			// 0x06000000 - 0x07FFFFFF Work RAM High
			createMemoryRegion("Work RAM High", 0x06000000, 0x07FFFFFF, true, true, true, program, monitor, log);

			// 0xFFFFFE00 	0xFFFFFFFF	On Chip Registers
			// TODO: this worsens decompilation significantly. Error codes are replaced with data references to this region of memory
			createMemoryRegion("On Chip Registers", 0xFFFFFE00, 0xFFFFFFFF, true, true, true, program, monitor, log);

			labelCDRegisters(program, log);
			labelOnchipRegisters(program, log);
			labelSCURegisters(program, log);
			labelSMPCRegisters(program, log);
			labelVDP1Registers(program, log);
			labelVDP2Registers(program, log);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}

	//
	// Memory-Mapped Registers
	//

	// label the SMPC registers
	public long labelCDRegisters(Program program, MessageLog log) {

		//
		// CD registers taken from: https://wiki.yabause.org/index.php5?title=CDBlock
		//

		final int CD_BASE = 0x25890000;

		String name = "CD_";
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(CD_BASE);

		try {
			program.getSymbolTable().createLabel(addr.add(0x08), name + "HIRQ", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0C), name + "HIRQ_MASK", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x18), name + "CR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x1C), name + "CR2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x20), name + "CR3", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x24), name + "CR4", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x28), name + "MPEGRGB", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		return 0;
	}

	// label the onchip registers 0xFFFFFE00 - 0xFFFFFFFF
	public long labelOnchipRegisters(Program program, MessageLog log) {

		//
		// Onchip registers taken from: https://github.com/Yabause/yabause/blob/master/yabause/src/sh2core.c
		//

		String name = "Onchip_";
		Address onChipAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xFFFFFE00);
		Address addr;

		try {
			program.getSymbolTable().createLabel(onChipAddr.add(0x000), name + "SMR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x001), name + "BRR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x002), name + "SCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x003), name + "TDR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x004), name + "SSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x005), name + "RDR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x010), name + "TIER", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x011), name + "FTCSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x012), name + "FTCSR.part.h", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x013), name + "FTCSR.part.L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x014), name + "OCRA_OCRB_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x015), name + "OCRA_OCRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x016), name + "TCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x017), name + "TOCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x018), name + "FICR_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x019), name + "FICR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x060), name + "IPRB_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x062), name + "VCRA_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x063), name + "VCRA_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x064), name + "VCRB_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x065), name + "VCRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x066), name + "VCRC_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x067), name + "VCRC", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x068), name + "VCRD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x080), name + "WTCSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x081), name + "WTCNT", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x092), name + "CCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x0E0), name + "ICR_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x0E1), name + "ICR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x0E2), name + "IPRA_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x0E3), name + "IPRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x0E4), name + "VCRWDT_high", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x0E5), name + "WCRWDT", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x100), name + "DVSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x120), name + "DVSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x104), name + "DVDNTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x124), name + "DVDNTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x108), name + "DVCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x128), name + "DVCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x10C), name + "VCRDIV", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x12C), name + "VCRDIV", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0X110), name + "DVDNTH", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x130), name + "DVDNTH", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x114), name + "DVDNTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x134), name + "DVDNTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x118), name + "DVDNTUH", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x138), name + "DVDNTUH", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x11C), name + "DVDNTUL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x13C), name + "DVDNTUL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x180), name + "SAR0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x184), name + "DAR0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x188), name + "TCR0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x18C), name + "CHCR0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x190), name + "SAR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x194), name + "DAR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x198), name + "TCR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x19C), name + "CHCR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1A0), name + "VCRDMA0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1A8), name + "VCRDMA1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1B0), name + "DMA0R", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1E0), name + "BCR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1E4), name + "BCR2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1E8), name + "WCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1EC), name + "MCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1F0), name + "RTCSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1F4), name + "RTCNT", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(onChipAddr.add(0x1F8), name + "RTCOR", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		return 0;
	}

	// label the SCU registers
	public long labelSCURegisters(Program program, MessageLog log) {

		//
		// SCU registers taken from: https://github.com/ijacquez/libyaul/blob/develop/libyaul/scu/scu/map.h
		//

		final int SCU_BASE = 0x25FE0000;

		String name = "SCU_";
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SCU_BASE);

		try {
			program.getSymbolTable().createLabel(addr.add(0x0000), name + "D0R", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0004), name + "D0W", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0008), name + "D0C", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x000C), name + "D0AD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0010), name + "D0EN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0014), name + "D0MD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0020), name + "D1R", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0024), name + "D1W", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0028), name + "D1C", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x002C), name + "D1AD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0030), name + "D1EN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0034), name + "D1MD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0040), name + "D2R", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0044), name + "D2W", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0048), name + "D2C", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x004C), name + "D2AD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0050), name + "D2EN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0054), name + "D2MD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0060), name + "DSTP", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x007C), name + "DSTA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0080), name + "PPAF", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0084), name + "PPD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0088), name + "PDA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x008C), name + "PDD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0090), name + "T0C", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0094), name + "T1S", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0098), name + "T1MD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A0), name + "IMS", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A4), name + "IST", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A8), name + "AIACK", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B0), name + "ASR0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B4), name + "ASR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B8), name + "AREF", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C4), name + "RSEL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C8), name + "VER", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		return 0;
	}

	// label the SMPC registers
	public long labelSMPCRegisters(Program program, MessageLog log) {

		//
		// SMPC registers taken from: https://github.com/ijacquez/libyaul/scu/bus/cpu/smpc/smpc/map.h
		//

		final int SMPC_BASE = 0x20100000;

		String name = "SMPC_";
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(SMPC_BASE);

		try {
			program.getSymbolTable().createLabel(addr.add(0x01F), name + "COMREG", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x061), name + "SR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x063), name + "SF", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x075), name + "PDR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x077), name + "PDR2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x079), name + "DDR1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x07B), name + "DDR2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x07D), name + "IOSEL1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x07D), name + "IOSEL2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x07F), name + "EXLE1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x07F), name + "EXLE2", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		return 0;
	}

	// label the backup functions
	public long labelBackupFunctions(Program program, MessageLog log) {

		//
		// Definitions taken from: https://segaxtreme.net/threads/decompilation-of-backup-library.25353/
		//

		final Address DIVIDE_BY_ZERO_STATUS_ADDR = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x06000350);
		final Address FUNCTION_POINTERS_ADDR = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x06000354);
		final Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		AddressSet addrSet;
		Function func;
		ReturnParameterImpl returnParam;
		ParameterImpl param1;
		ParameterImpl param2;
		ParameterImpl param3;
		ParameterImpl param4;

		// enums
		DataType BUP_ERROR = biosDataTypeManager.getDataType​(new CategoryPath("/backup/enums"), "BUP_ERROR");
		DataType BACKUP_DEVICE = biosDataTypeManager.getDataType​(new CategoryPath("/backup/enums"), "BACKUP_DEVICE");
		DataType BACKUP_OVERWRITE_MODE = biosDataTypeManager.getDataType​(new CategoryPath("/backup/enums"), "BACKUP_OVERWRITE_MODE");
		DataType SEARCH_MODE = biosDataTypeManager.getDataType​(new CategoryPath("/backup/enums"), "SEARCH_MODE");

		// structs
		DataType backup_config = biosDataTypeManager.getDataType​(new CategoryPath("/backup/structs"), "backup_config");
		DataType backup_file = biosDataTypeManager.getDataType​(new CategoryPath("/backup/structs"), "backup_file");
		DataType backup_stat = biosDataTypeManager.getDataType​(new CategoryPath("/backup/structs"), "backup_stat");
		DataType backup_date = biosDataTypeManager.getDataType​(new CategoryPath("/backup/structs"), "backup_date");


		String name = "BUP_";

		try {

			// this address has the status of divide by zero errors
			program.getSymbolTable().createLabel(DIVIDE_BY_ZERO_STATUS_ADDR, name + "DIVIDE_BY_ZERO_STATUS", null, SourceType.IMPORTED);
			program.getListing().createData(DIVIDE_BY_ZERO_STATUS_ADDR, DWordDataType.dataType, 4);

			// 0x0600354 has a pointer to the backup functions if they are loaded and inited
			program.getListing().createData(FUNCTION_POINTERS_ADDR, PointerDataType.dataType, 4);

			Address backup_functions = addr.add(program.getMemory().getInt(FUNCTION_POINTERS_ADDR));
			if(backup_functions.getOffset() == 0)
			{
				log.appendMsg("Backup library not loaded." + backup_functions.toString());
				return 0;
			}

			// now create functions for each of the backup routines
			program.getSymbolTable().createLabel(backup_functions, name + "FUNCTION_POINTERS", null, SourceType.IMPORTED);
			for (int i = 0; i < 11; i++)
			{
				program.getListing().createData(backup_functions.add(i*4), PointerDataType.dataType, 4);
			}

			//function prototypes
			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(0))));
			func = program.getFunctionManager().createFunction("Init", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(VoidDataType.dataType, program);
			param1 = new ParameterImpl("metadata", new PointerDataType(VoidDataType.dataType), program);
			param2 = new ParameterImpl("conifg", new PointerDataType(backup_config), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(4))));
			func = program.getFunctionManager().createFunction(name + "SelPart", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("partition_number", UnsignedShortDataType.dataType, program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(8))));
			func = program.getFunctionManager().createFunction(name + "Format", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(12))));
			func = program.getFunctionManager().createFunction(name + "Stat", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("data_size", DWordDataType.dataType, program);
			param3 = new ParameterImpl("output_stat", new PointerDataType(backup_stat), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2, param3);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(16))));
			func = program.getFunctionManager().createFunction(name + "Write", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("file", new PointerDataType(backup_file), program);
			param3 = new ParameterImpl("data", new PointerDataType(UnsignedCharDataType.dataType), program);
			param4 = new ParameterImpl("overwrite_mode", BACKUP_OVERWRITE_MODE, program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2, param3, param4);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(20))));
			func = program.getFunctionManager().createFunction(name + "Read", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("filename", new PointerDataType(UnsignedCharDataType.dataType), program);
			param3 = new ParameterImpl("output_data", new PointerDataType(UnsignedCharDataType.dataType), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2, param3);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(24))));
			func = program.getFunctionManager().createFunction(name + "Delete", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("filename", new PointerDataType(UnsignedCharDataType.dataType), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(28))));
			func = program.getFunctionManager().createFunction(name + "Dir", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("filename", new PointerDataType(UnsignedCharDataType.dataType), program);
			param3 = new ParameterImpl("data_size", DWordDataType.dataType, program);
			param4 = new ParameterImpl("file_metadata", new PointerDataType(backup_file), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2, param3, param4);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(32))));
			func = program.getFunctionManager().createFunction(name + "Verify", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(BUP_ERROR, program);
			param1 = new ParameterImpl("device", BACKUP_DEVICE, program);
			param2 = new ParameterImpl("filename", new PointerDataType(UnsignedCharDataType.dataType), program);
			param3 = new ParameterImpl("data", new PointerDataType(UnsignedCharDataType.dataType), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2, param3);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(36))));
			func = program.getFunctionManager().createFunction(name + "GetDate", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(VoidDataType.dataType, program);
			param1 = new ParameterImpl("minutes_since_1980", DWordDataType.dataType, program);
			param2 = new ParameterImpl("date", new PointerDataType(backup_date), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1, param2);

			addrSet = new AddressSet(addr.add(program.getMemory().getInt(backup_functions.add(40))));
			func = program.getFunctionManager().createFunction(name + "SetDate", addrSet.getMinAddress(), addrSet, SourceType.IMPORTED);
			returnParam = new ReturnParameterImpl(DWordDataType.dataType, program);
			param1 = new ParameterImpl("date", new PointerDataType(backup_date), program);
			func.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), returnParam,	FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.IMPORTED, param1);
		}
		catch(Exception e) {
			log.appendException(e);
			log.appendMsg("Error labelling backup functions!!!");
		}

		return 0;
	}

	// label the VDP2 registers
	public long labelVDP2Registers(Program program, MessageLog log) {

		//
		// VDP2 registers taken from: https://github.com/ijacquez/libyaul/scu/bus/b/vdp/vdp2/map.h
		//

		final int VDP2_BASE = 0x25F80000;

		String name = "VDP2_";
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(VDP2_BASE);

		try {
			program.getSymbolTable().createLabel(addr.add(0x0000), name + "TVMD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0002), name + "EXTEN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0004), name + "TVSTAT", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0006), name + "VRSIZE", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0008), name + "HCNT", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x000A), name + "VCNT", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x000E), name + "RAMCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0010), name + "CYCA0L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0012), name + "CYCA0U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0014), name + "CYCA1L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0016), name + "CYCA1U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0018), name + "CYCB0L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x001A), name + "CYCB0U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x001C), name + "CYCB1L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x001E), name + "CYCB1U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0020), name + "BGON", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0022), name + "MZCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0024), name + "SFSEL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0026), name + "SFCODE", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0028), name + "CHCTLA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x002A), name + "CHCTLB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x002C), name + "BMPNA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x002E), name + "BMPNB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0030), name + "PNCN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0032), name + "PNCN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0034), name + "PNCN2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0036), name + "PNCN3", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0038), name + "PNCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x003A), name + "PLSZ", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x003C), name + "MPOFN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x003E), name + "MPOFR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0040), name + "MPABN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0042), name + "MPCDN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0044), name + "MPABN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0046), name + "MPCDN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0048), name + "MPABN2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x004A), name + "MPCDN2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x004C), name + "MPABN3", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x004E), name + "MPCDN3", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0050), name + "MPABRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0052), name + "MPCDRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0054), name + "MPEFRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0056), name + "MPGHRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0058), name + "MPIJRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x005A), name + "MPKLRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x005C), name + "MPMNRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x005E), name + "MPOPRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0060), name + "MPABRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0062), name + "MPCDRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0064), name + "MPEFRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0066), name + "MPGHRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0068), name + "MPIJRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x006A), name + "MPKLRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x006C), name + "MPMNRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x006E), name + "MPOPRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0070), name + "SCXIN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0072), name + "SCXDN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0074), name + "SCYIN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0076), name + "SCYDN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0078), name + "ZMXIN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x007A), name + "ZMXDN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x007C), name + "ZMYIN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x007E), name + "ZMYDN0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0080), name + "SCXIN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0082), name + "SCXDN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0084), name + "SCYIN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0086), name + "SCYDN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0088), name + "ZMXIN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x008A), name + "ZMXDN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x008C), name + "ZMYIN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x008E), name + "ZMYDN1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0090), name + "SCXN2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0092), name + "SCYN2", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0094), name + "SCXN3", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0096), name + "SCYN3", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0098), name + "ZMCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x009A), name + "SCRCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x009C), name + "VCSTAU", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x009E), name + "VCSTAL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A0), name + "LSTA0U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A2), name + "LSTA0L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A4), name + "LSTA1U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A6), name + "LSTA1L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00A8), name + "LCTAU", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00AA), name + "LCTAL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00AC), name + "BKTAU", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00AE), name + "BKTAL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B0), name + "RPMD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B2), name + "RPRCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B4), name + "KTCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B6), name + "KTAOF", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00B8), name + "OVPNRA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00BA), name + "OVPNRB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00BC), name + "RPTAU", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00BE), name + "RPTAL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C0), name + "WPSX0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C2), name + "WPSY0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C4), name + "WPEX0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C6), name + "WPEY0", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00C8), name + "WPSX1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00CA), name + "WPSY1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00CC), name + "WPEX1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00CE), name + "WPEY1", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00D0), name + "WCTLA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00D2), name + "WCTLB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00D4), name + "WCTLC", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00D6), name + "WCTLD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00D8), name + "LWTA0U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00DA), name + "LWTA0L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00DC), name + "LWTA1U", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00DE), name + "LWTA1L", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00E0), name + "SPCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00E2), name + "SDCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00E4), name + "CRAOFA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00E6), name + "CRAOFB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00E8), name + "LNCLEN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00EA), name + "SFPRMD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00EC), name + "CCCTL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00EE), name + "SFCCMD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00F0), name + "PRISA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00F2), name + "PRISB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00F4), name + "PRISC", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00F6), name + "PRISD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00F8), name + "PRINA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00FA), name + "PRINB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x00FC), name + "PRIR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0100), name + "CCRSA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0102), name + "CCRSB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0104), name + "CCRSC", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0106), name + "CCRSD", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0108), name + "CCRNA", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x010A), name + "CCRNB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x010C), name + "CCRR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x010E), name + "CCRLB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0110), name + "CLOFEN", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0112), name + "CLOFSL", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0114), name + "COAR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0116), name + "COAG", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0118), name + "COAB", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x011A), name + "COBR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x011C), name + "COBG", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x011E), name + "COBB", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		return 0;
	}

	// label the VDP1 registers
	public long labelVDP1Registers(Program program, MessageLog log) {

		//
		// VDP1 registers taken from: https://github.com/ijacquez/libyaulscu/bus/b/vdp/vdp1/map.h
		//

		final int VDP1_BASE = 0x25D00000;

		String name = "VDP1_";
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(VDP1_BASE);

		try {
			program.getSymbolTable().createLabel(addr.add(0x0000), name + "TVMR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0002), name + "FBCR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0004), name + "PTMR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0006), name + "EWDR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0008), name + "EWLR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x000A), name + "EWRR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x000C), name + "ENDR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0010), name + "EDSR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0012), name + "LOPR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0014), name + "COPR", null, SourceType.IMPORTED);
			program.getSymbolTable().createLabel(addr.add(0x0016), name + "MODR", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
		}

		return 0;
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

			// save off the master and slave SH2 registers
			if(regionName == "MSH2")
			{
				MSH2_PC = PC;
				MSH2_PR = PR;
				MSH2_R15 = R15;
			}
			else
			{
				SSH2_PC = PC;
				SSH2_PR = PR;
				SSH2_R15 = R15;
			}
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

	//
	// Mednafen Save State (MSS) loading functions
	//

	public boolean isMednafenSaveState(ByteProvider provider) throws IOException{

		// Mednafen Save States start with this signature
		String signature = "MDFNSVST";

		if(provider.length() >= signature.length()) {

			byte sig[] = provider.readBytes(0, signature.length());
			if(Arrays.equals(sig, signature.getBytes())) {

				return true;
			}
		}

		return false;
	}

	// find all sections in the save state file and add them to mssSectionMap
	public int mssMakeSectionMap(ByteProvider provider, long currPos, long totalLen, Program program, TaskMonitor monitor, MessageLog log) {

		// TODO: the list of sections has increased
		/* The Mednafen save state has the following sections:
			MDFNDRIVE_00000000
			MDFNRINP
			BIOS_HASH
			SH2-M
			SH2-S
			SCU
			SMPC
			SMPC_P0_Gamepad
			SMPC_P1_Gamepad
			CDB
			VDP1
			VDP2
			VDP2REND
			SOUND
			M68K
			SCSP
			CART_BACKUP
			MAIN
		*/

		final int MSS_SIZE_OF_SECTION_TAG = 0x20;
		final int MSS_SIZE_OF_SECTION_SIZE = 0x4;
		final int MSS_MAX_SECTIONS = 0x14;

		int regionSize = 0;
		int i = 0;

		try {

			mssSectionMap = new HashMap<String, Long>();

			BinaryReader reader = new BinaryReader(provider, true);

			while(true)
			{
				// 32-byte tag
				byte tag[] = provider.readBytes(currPos, MSS_SIZE_OF_SECTION_TAG);
				String tagString = new String(tag);
				tagString = tagString.replaceAll("\u0000.*", ""); // remove trailing NULLs

				// record the postion of the section
				mssSectionMap.put(tagString, currPos);

				currPos += MSS_SIZE_OF_SECTION_TAG;

				regionSize = reader.readInt(currPos);
				currPos += MSS_SIZE_OF_SECTION_SIZE;

				currPos += regionSize;

				if(currPos == 0 || currPos >= totalLen)
				{
					break;
				}

				i++;

				if(i > MSS_MAX_SECTIONS)
				{
					//throw new IOException("Too many sections!!");
				}
			}
		}
		catch(Exception e) {
			log.appendException(e);
			return -1;
		}

		return 0;
	}

	// create labels for the PC, PR, and R15 registers
	public long mssLabelSH2Regs(String regionName, ByteProvider provider, long startPos, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// Each Mednafen Save State (MSS) section starts with:
		//
		// - 32 section tag
		// - 4 byte length
		// - variable number of data fields that consist of:
		// -- one byte data name length
		// -- varible length data name
		// -- 4 byte data length field
		// -- variable length data
		//

		final int MSS_SIZE_OF_SECTION_TAG = 32;
		final int MSS_SIZE_OF_SECTION_SIZE = 4;
		final int MSS_MAX_VARIABLES = 100;

		long currPos = startPos;
		long sectionSize = 0;
		long endPos = 0;
		int i = 0;

		long PC = 0;
		long PR = 0;
		long R15 = 0;
		Address addr;

		boolean foundPC = false;
		boolean foundPR = false;
		boolean foundR15 = false;

		String labelRegionName;

		try {

			BinaryReader reader = new BinaryReader(provider, true);

			byte tag[] = provider.readBytes(currPos, MSS_SIZE_OF_SECTION_TAG);
			String tagString = new String(tag);
			tagString = tagString.replaceAll("\u0000.*", ""); // remove trailing NULLs

			if(!tagString.equals(regionName)){
				throw new IOException("Invalid MSS tag name!!");
			}

			// skip pass the tag
			currPos += MSS_SIZE_OF_SECTION_TAG;

			// read the section size
			sectionSize = reader.readInt(currPos);
			currPos += MSS_SIZE_OF_SECTION_SIZE;

			// compute the end size
			endPos = currPos + sectionSize;

			// parse the variables in the section
			// -- one byte data name length
			// -- varible length data name
			// -- 4 byte data length field
			// -- variable length data
			while(true)
			{
				long varNameLen;
				long dataLen;

				// variable name length
				varNameLen = reader.readByte(currPos);
				currPos += 1;

				// variable name
				byte varName[] = provider.readBytes(currPos, varNameLen);

				String varString = new String(varName);
				varString = varString.replaceAll("\u0000.*", ""); // remove trailing NULLs
				currPos += varNameLen;

				// data length
				dataLen = reader.readInt(currPos);
				currPos += 4;

				// look for the PC, PR, and R15 registers
				// currPos points to the data section of the variable
				if(varString.equals("PC"))
				{
					// PC variable only contains 4 bytes of data that is the PC reg
					PC = reader.readInt(currPos);
					foundPC = true;
				}
				else if(varString.equals("R"))
				{
					// R variable contains 64 bytes of data that is r0-r15
					// we only want r15
					R15 = reader.readInt(currPos + 60);
					foundR15 = true;
				}
				else if(varString.equals("CtrlRegs"))
				{
					// CtrlRegs variable contains three regs
					// we only want PR, the 3rd register
					PR = reader.readInt(currPos + 8);
					foundPR = true;
				}

				// data
				currPos += dataLen;

				if(foundPC == true && foundPR == true && foundR15 == true)
				{
					// found all the registers, fast exit
					break;
				}

				if(currPos == 0 || currPos >= endPos)
				{
					break;
				}

				i++;

				if(i > MSS_MAX_VARIABLES)
				{
					throw new IOException("Too many MSS sections!");
				}
			}

			// save off the master and slave SH2 registers
			if(regionName == "SH2-M")
			{
				labelRegionName = "MSH2";
				MSH2_PC = PC;
				MSH2_PR = PR;
				MSH2_R15 = R15;
			}
			else
			{
				labelRegionName = "SSH2";
				SSH2_PC = PC;
				SSH2_PR = PR;
				SSH2_R15 = R15;
			}

			// create the labels
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(R15);
			program.getSymbolTable().createLabel(addr, labelRegionName + "_R15", null, SourceType.IMPORTED);

			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(PR);
			program.getSymbolTable().createLabel(addr, labelRegionName + "_PR", null, SourceType.IMPORTED);

			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(PC);
			program.getSymbolTable().createLabel(addr, labelRegionName + "_PC", null, SourceType.IMPORTED);
		}
		catch(Exception e) {
			log.appendException(e);
			return -1;
		}

		return 0;
	}

	// reads a region of memory from the MSS save state and appends it to the Ghidra DB
	public long readMSSRegions(String regionName, ByteProvider provider, long startPos, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// Each Mednafen Save State (MSS) section starts with:
		//
		// - 32 section tag
		// - 4 byte length
		// - variable number of data fields that consist of:
		// -- one byte data name length
		// -- varible length data name
		// -- 4 byte data length field
		// -- variable length data
		//

		final int MSS_SIZE_OF_SECTION_TAG = 32;
		final int MSS_SIZE_OF_SECTION_SIZE = 4;
		final int MSS_MAX_VARIABLES = 100;

		long currPos = startPos;
		long sectionSize = 0;
		long endPos = 0;
		int i = 0;

		boolean foundRamH = false;
		boolean foundRamL = false;
		boolean foundBackupRam = false;

		String labelRegionName;

		try {

			BinaryReader reader = new BinaryReader(provider, true);

			byte tag[] = provider.readBytes(currPos, MSS_SIZE_OF_SECTION_TAG);
			String tagString = new String(tag);
			tagString = tagString.replaceAll("\u0000.*", ""); // remove trailing NULLs

			if(!tagString.equals(regionName)){
				throw new IOException("Invalid MSS tag name!!");
			}

			// skip pass the tag
			currPos += MSS_SIZE_OF_SECTION_TAG;

			// read the section size
			sectionSize = reader.readInt(currPos);
			currPos += MSS_SIZE_OF_SECTION_SIZE;

			// compute the end size
			endPos = currPos + sectionSize;

			// parse the variables in the section
			// -- one byte data name length
			// -- varible length data name
			// -- 4 byte data length field
			// -- variable length data
			while(true)
			{
				long varNameLen;
				long dataLen;

				// variable name length
				varNameLen = reader.readByte(currPos);
				currPos += 1;

				// variable name
				byte varName[] = provider.readBytes(currPos, varNameLen);

				String varString = new String(varName);
				varString = varString.replaceAll("\u0000.*", ""); // remove trailing NULLs
				currPos += varNameLen;

				// data length
				dataLen = reader.readInt(currPos);
				currPos += 4;

				// look for the PC, PR, and R15 registers
				// currPos points to the data section of the variable
				if(varString.equals("WorkRAML"))
				{
					// low work ram
					readYSSRegion(0x00200000, 0x100000, true, provider, currPos, program, monitor, log);
					foundRamL = true;
				}
				else if(varString.equals("WorkRAMH"))
				{
					// high work ram
					readYSSRegion(0x06000000, 0x100000, true, provider, currPos, program, monitor, log);
					foundRamH = true;
				}
				else if(varString.equals("BackupRAM"))
				{
					// TODO: this isn't quite correct. Why is Yabause reading twice as much as Mednafen??
					readYSSRegion(0x00180000, 0x8000, false, provider, currPos, program, monitor, log);
					foundBackupRam = true;
				}

				// data
				currPos += dataLen;

				if(foundRamL == true && foundRamH == true && foundBackupRam == true)
				{
					// found all the registers, fast exit
					break;
				}

				if(currPos == 0 || currPos >= endPos)
				{
					break;
				}

				i++;

				if(i > MSS_MAX_VARIABLES)
				{
					throw new IOException("Too many MSS sections!");
				}
			}
		}
		catch(Exception e) {
			log.appendException(e);
			return -1;
		}

		return 0;
	}

	// loads an ungzipped Mednafen save state
	public void loadMednafenSaveState(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {

		//
		// The Mednafen Save State (MSS) is documented in MDFNSS_LoadSM in src/state.cpp
		//
		// The file format starts with:
		// - 16 byte magic
		// - 16 bytes of fields
		// - variable length preview data
		// - variable length array of sections
		//

		final int MAGIC_SIZE = 16;

		long stateVersion = 0;
		long totalLen = 0;
		long svbe = 0;
		long width = 0;
		long height = 0;
		long previewLen = 0;
		long regionSize = 0;

		int result = 0;

		try {

			BinaryReader reader = new BinaryReader(provider, true);

			long currPos = 0;
			long version = 0;
			int headerSize = 0;

			//
			// parse the MSS file header
			//

			// we already checked the signature earlier, no need to check it again
			currPos += MAGIC_SIZE;

			stateVersion = reader.readInt(currPos);
			currPos += 4;

			totalLen = reader.readInt(currPos);
			svbe = totalLen & 0x80000000;
			totalLen = totalLen & 0x7FFFFFFF;
			currPos += 4;

			width = reader.readInt(currPos);
			currPos += 4;

			height = reader.readInt(currPos);
			currPos += 4;

			// skip past the previewLen
			previewLen = height * width * 3;
			currPos += previewLen;

			//
			// currPos should now point to a variable array of sections
			//

			// get the position of all sections
			result = mssMakeSectionMap(provider, currPos, totalLen, program, monitor, log);
			if(result != 0)
			{
				throw new IOException("Failed to parse MSS sections!");
			}

			// parse out the Master SH-2 registers
			if(mssSectionMap.containsKey("SH2-M") == false)
			{
				throw new IOException("MSS missing SH2-M section!");
			}
			mssLabelSH2Regs("SH2-M", provider, mssSectionMap.get("SH2-M"), program, monitor, log);

			// parse out the Slave SH-2 registers
			if(mssSectionMap.containsKey("SH2-S") == false)
			{
				throw new IOException("MSS missing SH2-S section!");
			}
			mssLabelSH2Regs("SH2-S", provider, mssSectionMap.get("SH2-S"), program, monitor, log);

			// load the memory regions
			readMSSRegions("MAIN", provider, mssSectionMap.get("MAIN"), program, monitor, log);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}
}
