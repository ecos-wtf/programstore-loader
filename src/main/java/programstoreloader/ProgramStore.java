package programstoreloader;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Date;
import java.util.Arrays;

import ghidra.GhidraApplicationLayout;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;


public class ProgramStore {
	
	public BcmProgramHeader bcmHeader;
	
	public byte[] compressed;
	
	public byte[] decompressed;

	public class BcmProgramHeader {
		
		// the unique signature may be specified as a command
		// line option: The default is: 0x3350
		public  int usSignature; 
		  
		// Control flags: currently defined lsb=1 for compression
		// remaining bits are currently reserved
		public  int usControl;
		
		// Major SW Program Revision
		public  int usMajorRevision;
		
		// Minor SW Program Revision
		// From a command line option this is specified as xxx.xxx
		// for the Major.Minor revision (note: Minor Revision is 3 digits)
		public  int usMinorRevision;
		
		// calendar time of this build (expressed as seconds since Jan 1 1970)
		public  long ulcalendarTime;
		
		// length of Program portion of file
		public  long ulTotalCompressedLength;
		
		// Address where program should be loaded (virtual, uncached)
		public  long ulProgramLoadAddress; 
		  
		// NULL terminated filename only (not pathname)
		public  String cFilename;
		
		// For future use
		public  String pad;
		  
		// When doing a dual-compression for Linux,
		// it's necessary to save both lengths.
		public  long ulCompressedLength1;
		public  long ulCompressedLength2; 
		
		// 16-bit crc Header checksum (CRC_CCITT) over the header [usSignature through cFilename]
		public  short usHcs;
		
		// reserved
		public  short reserved;
		
		// CRC-32 of Program portion of file (following the header)
		public  long ulcrc;
		
		@SuppressWarnings("unused")
		public BcmProgramHeader() {}
		
		@SuppressWarnings("unused")
		public BcmProgramHeader(final BinaryReader reader) throws IOException {
			this.usSignature = reader.readUnsignedShort(0x00);
			this.usControl = reader.readUnsignedShort(0x02);
			this.usMajorRevision = reader.readUnsignedShort(0x04);
			this.usMinorRevision = reader.readUnsignedShort(0x06);
			this.ulcalendarTime = reader.readUnsignedInt(0x08);
			this.ulTotalCompressedLength = reader.readUnsignedInt(0x0c);
			this.ulProgramLoadAddress = reader.readUnsignedInt(0x10);
			this.cFilename = reader.readAsciiString(0x14, 48);
			this.pad = reader.readAsciiString(0x44, 8);
			this.ulCompressedLength1 = reader.readUnsignedInt(0x4c);
			this.ulCompressedLength2 = reader.readUnsignedInt(0x50);
			this.usHcs = reader.readShort(0x54);
			this.ulcrc = reader.readUnsignedInt(0x58);
		}
		
		public boolean isValidHeader() {
			/**
			 * the following assumptions are made:
			 * - compression flag (control) is always set to 0x0005 (UseLZMACompression)
			 * - the build date is after the initial release of eCos
			 * - the build date is before April 2021
			 */
			if(this.usControl == 0x05 && this.ulcalendarTime > 904608000 && this.ulcalendarTime < 1617356513) {
				return true;
			}
			
			// TODO: check header CRC
			
			// TODO: check compressed data CRC
			
			return false;
		}
		
		public  String getManufacturer() {
			/**
			 * Map to known signatures taken from bcm2-utils
			 */
			switch(this.usSignature) {
			case 0x3350:
				return "default";
			case 0xc200:
				return "Netgear";
			case 0xa0eb:
				return "Netgear";
			case 0x3390:
				return "Sagemcom";
			case 0xa825:
				return "Technicolor";
			case 0xa81b:
				return "TWG";
			case 0xa815:
				return "TWG";
			case 0xa03a:
				return "Cisco";
			case 0x8364:
				return "CBW";
			case 0xd22f:
				return "ASKEY/Siligence";
			}
			return "unkown";
		}
		
		@Override
		public String toString() {
			String representation = "";
			representation += String.format("Signature: 0x%02X\n", this.usSignature);
			representation += String.format("Control: 0x%02X\n", this.usControl);
			representation += String.format("Major: 0x%02X\n", this.usMajorRevision);
			representation += String.format("Minor: 0x%02X\n", this.usMinorRevision);
			//representation += String.format("Build: 0x%04X\n", this.ulcalendarTime);
            Date date = new Date(this.ulcalendarTime * 1000);                  
			representation += "Build: " + date + "\n";
			representation += String.format("Length: 0x%04X\n", this.ulTotalCompressedLength);
			representation += String.format("Load: 0x%04X\n", this.ulProgramLoadAddress);
			representation += "Name: " + this.cFilename + "\n";
			representation += "Manufacturer: " + this.getManufacturer() + "\n";
			//representation += String.format("Compressed length 1: 0x%04X\n", this.ulCompressedLength1);
			//representation += String.format("Compressed length 2: 0x%04X\n", this.ulCompressedLength2);
			representation += String.format("HCS: 0x%02X\n", this.usHcs);
			representation += String.format("Reserved: 0x%02X\n", this.reserved);
			representation += String.format("CRC: 0x%04X\n", this.ulcrc);			
			return representation;
		}
	}
	
	public ProgramStore() { }
	
	/**
	 * Constructor. Initialize ProgramStore header and compressed data
	 * by reading it from Ghidra's ByteProvider.
	 * @param provider
	 * @throws IOException
	 */
	public ProgramStore(ByteProvider provider) throws IOException
	{
		// big-endian reader
		BinaryReader er = new BinaryReader(provider, false); 
		bcmHeader = new BcmProgramHeader(er);
		
		InputStream inputStream = provider.getInputStream(0);
		compressed = inputStream.readAllBytes();
		inputStream.close();
	
	}
	
	private int computeCRC(byte[] data, int polynomial, int initial, int xor, boolean reverse) {
		int bits = 8; 

    	int crc = initial;	// initial contents of LFBSR

        for (byte b : data) {
            int temp = (crc ^ b) & 0xff;

            // read 8 bits one at a time
            for (int i = 0; i < bits; i++) {
                if ((temp & 1) == 1) temp = (temp >>> 1) ^ polynomial;
                else                 temp = (temp >>> 1);
            }
            crc = (crc >>> bits) ^ temp;
        }

        if(reverse) {
        	Integer.reverse(crc);
        }
        // flip bits
        crc = crc ^ xor;
        return crc; 
	}
	
	private int getHeaderCRC() {
		byte[] data = Arrays.copyOfRange(compressed, 0, 82);
    	return computeCRC(data, 0x00001021, 0x00000000, 0xffffffff, false);
	}
	
	private int getDataCRC() {
		byte[] data = Arrays.copyOfRange(compressed, 92, (int)bcmHeader.ulTotalCompressedLength + 92);
    	return computeCRC(data, 0x04c11db7, 0x00000000, 0xffffffff, false);
    }
	
	@SuppressWarnings("unused")
	private boolean isHeaderCRCValid() {
		return (getHeaderCRC() == bcmHeader.usHcs);
	}
	
	@SuppressWarnings("unused")
	private boolean isDataCRCValid() {
		return (getDataCRC() == bcmHeader.ulcrc);
	}
	
	/**
	 * Runs Broadcom's ProgramStore binary to extract 'infile' into
	 * 'outfile'.
	 * 
	 * ProgramStore binary is a statically linked x86 ELF compiled
	 * from https://github.com/Broadcom/aeolus.git
	 * @param infile
	 * @param outfile
	 * @throws Exception 
	 * @throws InterruptedException 
	 */
	private void extract(String infile, String outfile) throws Exception {
				
		try {
			String path;
			File f = new File("./lib/ProgramStore");
			// testing mode (run from Eclipse)
			if(f.exists()) {
				path = f.getCanonicalPath();
			}
			// extension installed mode
			else {
				GhidraApplicationLayout appLayout = new GhidraApplicationLayout();
				path = appLayout.getExtensionInstallationDir() + "/ProgramStoreLoader/lib/ProgramStore";
			}
			String[] command = {path, "-x", "-f", infile, "-o", outfile};
			Process process = Runtime.getRuntime().exec(command);
		    process.waitFor();
		    if(process.exitValue() == 0) {
		    	BufferedReader reader = new BufferedReader(
			            new InputStreamReader(process.getInputStream()));
			    String line;
			    while ((line = reader.readLine()) != null) {
			        System.out.println(line);
			    }
			    reader.close();
		    } else {
		    	BufferedReader reader = new BufferedReader(
			            new InputStreamReader(process.getErrorStream()));
			    StringBuilder output = new StringBuilder();
			    String line;
			    while ((line = reader.readLine()) != null) {
			        output.append(line);
			    }
			    reader.close();
			    throw new Exception(output.toString());
		    }
		} catch (IOException | InterruptedException e) {
		    throw e;
		}
		
	}

	/**
	 * Writes compressed firmware to a temporary file, decompress it using ProgramStore
	 * executable into another temporary file.
	 * 
	 * Reads the decompressed content into 'decompressed' byte array and delete both
	 * temporary files.
	 * @throws Exception 
	 */
	public void decompress() throws Exception
	{
		File programStoreTempFile = File.createTempFile(bcmHeader.cFilename, ".programstore");
        FileOutputStream fOutputStream = new FileOutputStream(programStoreTempFile);
        fOutputStream.write(compressed);
        fOutputStream.close();
        
        System.out.println("ProgramStore firmware written to: " + programStoreTempFile.getAbsolutePath());
        
        File rawFirmware = File.createTempFile(bcmHeader.cFilename, ".raw");
        System.out.println("Temp file On Default Location: " + rawFirmware.getAbsolutePath());
        
        System.out.println("Launching ProgramStore extraction");
        extract(programStoreTempFile.getAbsolutePath(), rawFirmware.getAbsolutePath());

        System.out.println("Reading decompressed content.");
        FileInputStream fInputStream = new FileInputStream(rawFirmware);
        
        byte[] tmp = fInputStream.readAllBytes();
        fInputStream.close();
        programStoreTempFile.delete();
        rawFirmware.delete();
        
        // we remove trailing null bytes that have been padded by 
        // ProgramStore executable
        
        if(tmp.length > 0) {
        	var i = tmp.length - 1;
            while (tmp[i] == 0) {
                i--;
            }
            decompressed = Arrays.copyOf(tmp, i);
        }else {
        	decompressed = tmp;
        }
	}
	
	/**
	 * Returns the .data section offset.
	 * @return
	 */
	public long getDataOffset() {
		return bcmHeader.ulProgramLoadAddress + getDataIndex();
	}
	
	/**
	 * Returns the .text section offset, which corresponds
	 * to the firmware load address.
	 * @return
	 */
	public long getTextOffset() {
		return bcmHeader.ulProgramLoadAddress;
	}
	
	public long getDataLength() {
		return decompressed.length - getDataIndex();
	}
	
	public long getTextLength() {
		return getDataIndex();
	}
	
	/**
	 * Identify the start of .data section by looking for a known
	 * separator. In this case, the 'bcm0' string.
	 * @return
	 */
	public int getDataIndex() {
		// data section starts with \x00\x00\x00\x00bcm0\x00\x00\x00\x00
		byte[] pattern = {0, 0, 0, 0, 'b', 'c', 'm', '0', 0, 0, 0, 0};
		int dataStartIndex = KMP.indexOf(decompressed, pattern);
		return dataStartIndex;
	}
	
	/**
	 * Returns the .data section bytes.
	 * @return
	 */
	public byte[] getData() {
		return Arrays.copyOfRange(decompressed, getDataIndex(), decompressed.length);
	}

	/**
	 * Returns the .text section bytes.
	 * @return
	 */
	public byte[] getText() {
		return Arrays.copyOfRange(decompressed, 0, getDataIndex());
	}
	
	public long getHeapOffset() {
		throw new UnsupportedOperationException();
	}
	
	public long getBssOffset() {
		throw new UnsupportedOperationException();
		/**
		 * 
		 * HAL_ZERO_BSS_OFFSET     = 0x80004854
 
		 flirt = re.compile(b"\x3c\x04([\x00-\xFF][\x00-\xFF])\$\x84([\x00-\xFF][\x00-\xFF])\x3c\x05([\x00-\xFF][\x00-\xFF])\$\xa5([\x00-\xFF][\x00-\xFF])\x30\x86\x00\x03\x14\xc0\x00\x12")
		 
		 fp =  open(sys.argv[1], 'rb')
		 fp.seek(HAL_ZERO_BSS_OFFSET - DEFAULT_LOAD_ADDRESS)
		 instruction = fp.read(24)
		 match = flirt.findall(instruction)
		 if match:
		     a0_upper = struct.unpack(">H", match[0][0])[0]
		     a0_lower = struct.unpack(">H", match[0][1])[0]
		     a1_upper = struct.unpack(">H", match[0][2])[0]
		     a1_lower = struct.unpack(">H", match[0][3])[0]
		     bss_start = (a0_upper << 16) + a0_lower
		     bss_end = (a1_upper << 16) + a1_lower
		 fp.close()
		 */
	}
	
	public long getStackOffset() {
		throw new UnsupportedOperationException();
		/**
		 * # we identify the string 'tStartup' in the data section
 tstartup_index = s.find(b"tStartup\x00\x00\x00\x00")
 
 # if we have a match, we search for an assembly pattern
 if tstartup_index > -1:
     tstartup_addr = DEFAULT_LOAD_ADDRESS + tstartup_index
 
     # 807dd4b8 3c 07 80 fc     lui        a3,0x80fc
     # 807dd4bc 24 e7 03 34     addiu      a3,a3,0x334                 = "tStartup"
     pattern = b''.join([
         b"\x3c\x07",
         struct.pack(">H", tstartup_addr >> 16),
         b"\x24\xe7",
         struct.pack(">H", tstartup_addr - (tstartup_addr >> 16) * 0x10000)
         ]
     )
     instruction_index = s.find(pattern)
     instruction_addr = DEFAULT_LOAD_ADDRESS + instruction_index
 
     # we're looking for a call to cyg_thread_create(0x12,FUN_807dd4f8,0,"tStartup", stack_base, stack_size, handle, thread);
     # they use a custom calling convention
     # cyg_thread_create(a0, a1, a2, a3, t3, t1, t2, t0)
     # we're interested in register $t3 value which holds the stack_base address
     # given that tStartup is the first thread to run, stack_base is the actual start address of eCOS stack.
 
     '''
     3c 07 80 fc     lui        a3,0x80fc
     24 e7 03 34     addiu      a3=>s_tStartup_80fc0334,a3,0x334                 = "tStartup"
     3c 08 81 74     lui        t0,0x8174
     25 08 7c 48     addiu      t0,t0,0x7c48
     24 09 30 00     li         t1,0x3000
     3c 10 81 75     lui        s0,0x8175
     26 0a 3d 70     addiu      t2,s0,0x3d70
     3c 0b 81 75     lui        t3,0x8175
     0c 34 d1 0a     jal        cyg_thread_create                                undefined cyg_thread_create()
     25 6b 3c 48     _addiu     t3,t3,0x3c48
     '''
 
 
     lui_t3 = s[instruction_index+28:instruction_index+32]
     addui_t3 = s[instruction_index+36:instruction_index+40]
     if lui_t3[0:2] == b"\x3c\x0b" and addui_t3[0:2] == b"\x25\x6b":
         t3_upper = struct.unpack(">H", lui_t3[2:])[0]
         t3_lower = struct.unpack(">H", addui_t3[2:])[0]
         stack_start = (t3_upper << 16) + t3_lower
         stack_end = stack_start + 0x4000
		 */
	}
}
