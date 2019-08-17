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
import ghidra.app.util.importer.MemoryConflictHandler;
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
public class SegaSaturnLoader extends AbstractLibrarySupportLoader {
		
	public static final int IP_SIZE_OFFSET = 0xE0;
	public static final int FIRST_READ_OFFSET = 0xF0;
	public static final int SECURITY_CODE_OFFSET = 0x100;
	public static final int AREA_CODE_OFFSETS = 0xE00;
	public static final int SATURN_HEADER_WRITE_ADDR = 0x06002000;
	public static final int MAX_SATURN_HEADER_SIZE = 0xF00;
	public static final int AREA_CODE_OFFSET = 0xE00;
	public static final int AREA_CODE_SIZE = 0x20;
	public static final int AREA_CODE_MAGIC = 0xA00E0009;	

	// TODO: split this into separate script file so raw binaries can use this same code
	// TODO: add missing memory sections
	public void CreateSegaSaturnMemoryMap(Program program, TaskMonitor monitor, MessageLog log) {
		
		//
		// The Sega Saturn SH-2 Memory Map (https://wiki.yabause.org/index.php5?title=SH-2CPU)
		//
		// 0x00000000 - 0x000FFFFF: Boot ROM
		// 0x00200000 - 0x002FFFFF: Work RAM low
		// 0x06000000 - 0x07FFFFFF: Work RAM high
		//
		
		try {
			Address addr;
			MemoryBlock block;
			
			// 0x00000000 - 0x000FFFFF: Boot ROM
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
			block = program.getMemory().createInitializedBlock("Boot ROM", addr, 0x00100000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);			
	
			// 0x00200000 - 0x002FFFFF: Work RAM low
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00200000);
			block = program.getMemory().createInitializedBlock("Work RAM Low", addr, 0x00100000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
	
			// 0x06000000 - 0x07FFFFFF: Work RAM high
			addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x06000000);
			block = program.getMemory().createInitializedBlock("Work RAM High", addr, 0x01000000, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(true);
		}
		catch(Exception e) {
			log.appendException(e);
		}
	}
	
	public long swapLongEndianess(long val) {
		
		long result = Long.reverseBytes(val);
		result = result >> 32;
		return result;
	}

	
	// Copies the Sega Saturn header and initial program to 0x06002000
	public void LoadSegaSaturnHeader(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {
		
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
	public void LoadFirstExecutable(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {
		
		//
		// To load the first file on the ISO 996 disc we have to:
		// - find the PVD at ISO_PVD_OFF
		// - look at the root directory entry at ISO_PVD_DIRECTORY_ENTRY_OFF from there
		// - find the FAD to the root directory
		// - skip the "." and ".." files
		// - after those files the first actual file is present
		// Reference: https://wiki.osdev.org/ISO_9660
		
		try {
			Address addr;
			AddressSet addrSet;
			long curr; 

			BinaryReader reader = new BinaryReader(provider, true);
			
			//
			// Parse ISO 9660 just enought to find the first actual file on the disc
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
	
	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion 
		// files.
		return "Sega Saturn (ISO)";
	}
	
	public boolean isSegaSaturnIso(ByteProvider provider) throws IOException{
		
		// All Sega Saturn discs begin with this string
		String signature = "SEGA SEGASATURN";		
			
		if(provider.length() >= signature.length()) {	

			byte sig[] = provider.readBytes(0, signature.length());
			if(Arrays.equals(sig, signature.getBytes())) {
				
				// found the Saturn disc header
				return true;			
			}
		}
		
		return false;		
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		// Check if this is a Sega Saturn ISO or Yabause Save State
	
		if(isSegaSaturnIso(provider)) {
			
			// TODO: This should use the Opinion service but I have no clue how that works
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH:BE:32:SH-2", "default"), true));
		}			
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		try {
			
			CreateSegaSaturnMemoryMap(program, monitor, log);	
			
			LoadSegaSaturnHeader(provider, program, monitor, log);
			
			LoadFirstExecutable(provider, program, monitor, log);

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
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}
