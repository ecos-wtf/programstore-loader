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
import java.util.Collection;
import java.util.List;

import docking.widgets.OkDialog;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Broadcom's ProgramStore loader. Specifically designed to load ProgramStore images
 * of cable modems.
 */
public class ProgramStoreLoaderLoader extends AbstractLibrarySupportLoader {
	
	@Override
	public String getName() {
		return "Broadcom ProgramStore Loader";
	}
	
	private void promptShowHeaderInfo(final ProgramStore programStore) {

		String message = "<html>You have loaded what looks like a Broadcom ProgramStore firmware.<br/><br/>";
		message += programStore.bcmHeader.toString().replace("\n", "<br/>") + "</html>";
		OkDialog.showInfo("ProgramStore Info", message);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (provider.length() < ProgramStore.HEADER_LENGTH) {
			return List.of();
		}

		ProgramStore programStore = new ProgramStore(provider);
		
		if (programStore.bcmHeader.isValidHeader()) {
			LanguageCompilerSpecPair language =
				new LanguageCompilerSpecPair("MIPS:BE:32:default", "default");
			return List.of(new LoadSpec(this, 0, language, true));
		}
		return List.of();
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		TaskMonitor monitor = settings.monitor();
		
		Memory mem = program.getMemory();
		
		monitor.setMessage("Loading ProgramStore firmware...");	
		
		ProgramStore programStore = new ProgramStore(provider);
		settings.log().appendMsg(programStore.bcmHeader.toString());
		if (!SystemUtilities.isInHeadlessMode()) {
			promptShowHeaderInfo(programStore);
		}
		
		try {
			programStore.decompress();
		}
		catch (IOException e) {
			settings.log().appendException(e);
			throw e;
		}
		if (programStore.getDataIndex() <= 0) {
			throw new IOException("Decompressed ProgramStore image has no .data separator");
		}
		
		// we create the .text segment
		// we create the .data segment
		// TODO: create the stack overlay
		// TODO: create the heap overlay
		// TODO: create the bss overlay
		
		settings.log().appendMsg(String.format(".text start: 0x%08X", programStore.getTextOffset()));
		settings.log().appendMsg(String.format(".data start: 0x%08X", programStore.getDataOffset()));
		
		try {
			Address textAddr = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(programStore.getTextOffset());
			Address dataAddr = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(programStore.getDataOffset());
			
			MemoryBlock textBlock = mem.createInitializedBlock(".text", textAddr,
				programStore.getTextLength(), (byte) 0, monitor, false);
			MemoryBlock dataBlock = mem.createInitializedBlock(".data", dataAddr,
				programStore.getDataLength(), (byte) 0, monitor, false);
			
			//Set properties
			textBlock.setRead(true);
			textBlock.setWrite(true);
			textBlock.setExecute(true);
			
			dataBlock.setRead(true);
			dataBlock.setWrite(true);
			dataBlock.setExecute(false);
			
			//Fill the main memory segment with the decompressed data/code.
			mem.setBytes(textAddr, programStore.getText());
			mem.setBytes(dataAddr, programStore.getData());
	
		} catch (LockException | MemoryConflictException | AddressOverflowException |
				MemoryAccessException | IllegalArgumentException e) {
			throw new IOException("Unable to map the decompressed ProgramStore image", e);
		}
	}
}
