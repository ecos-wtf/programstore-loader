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
package programstoreloader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import docking.widgets.OkDialog;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Broadcom's ProgramStore loader. Specifically designed to load ProgramStore images
 * of cable modems.
 */
public class ProgramStoreLoaderLoader extends AbstractLibrarySupportLoader {

	public static final String OPTION_NAME_BASE_ADDR = "Base Address";
	
	@Override
	public String getName() {
		return "Broadcom ProgramStore Loader";
	}
	
	private void promptShowHeaderInfo(final ProgramStore programStore) {

		String message = "<html>You have loaded what looks like a Broadcom ProgramStore firmware.<br/><br/>";
		message += programStore.bcmHeader.toString().replace("\n", "<br/>") + "</html>";
		OkDialog.showInfo("ProgramStore Info", message);
	}
	
	private void promptShowErrorInfo(final Exception e) {
		OkDialog.showError("Loading error", e.getMessage());
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {

		ProgramStore programStore = new ProgramStore(provider);
		
		if(programStore.bcmHeader.isValidHeader()) {
			System.out.println(programStore.bcmHeader);
			promptShowHeaderInfo(programStore);
			return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:32:default", "default"), true));
		}
		return new ArrayList<>();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		
		Memory mem = program.getMemory();
		
		monitor.setMessage("Loading ProgramStore firmware...");	
		
		//Handles the NDS format in detail
		ProgramStore programStore = new ProgramStore(provider);
		
		//Get decompressed blob
		try {
			programStore.decompress();
		}
		catch (Exception e) {
			promptShowErrorInfo(e);
		}
		
		// we create the .text segment
		// we create the .data segment
		// TODO: create the stack overlay
		// TODO: create the heap overlay
		// TODO: create the bss overlay
		
		System.out.println(String.format(".text start: 0x%08X\n", programStore.getTextOffset()));
		System.out.println(String.format("data start: 0x%08X\n", programStore.getDataOffset()));
		
		try {
			Address textAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(programStore.getTextOffset());
			Address dataAddr =program.getAddressFactory().getDefaultAddressSpace().getAddress(programStore.getDataOffset());
			
			MemoryBlock text_block = mem.createInitializedBlock(".text", textAddr, programStore.getTextLength(), (byte)0x00, monitor, false);
			MemoryBlock data_block = mem.createInitializedBlock(".data", dataAddr, programStore.getDataLength(), (byte)0x00, monitor, false);
			
			//Set properties
			text_block.setRead(true);
			text_block.setWrite(true);
			text_block.setExecute(true);
			
			data_block.setRead(true);
			data_block.setWrite(true);
			data_block.setExecute(false);
			
			//Fill the main memory segment with the decompressed data/code.
			mem.setBytes(textAddr, programStore.getText());
			mem.setBytes(dataAddr, programStore.getData());
	
		} catch (LockException | DuplicateNameException | MemoryConflictException | AddressOverflowException
				| CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		return list;
	}
}
