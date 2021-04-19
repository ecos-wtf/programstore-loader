# ProgramStore Ghidra Loader

A Broadcom ProgramStore firmware image loader for Ghidra (9.1.2 and 9.2).
 
This loader will auto-detect ProgramStore firmware images from their header and display header information in a dialog box. On load, it takes care of decompressing the raw binary and loads both .text and .data sections.
 
## Known Limitations
 
### Decompression
 
The loader rely on a statically linked x86 binary compiled from Broadcom's [aeolus](https://github.com/Broadcom/aeolus/tree/master/ProgramStore) project to perform the decompression. I tried to implement the LZMA decompression in pure Java but the ProgramStore format does not exactly follow the LZMA header structure which tends to mess with the only LZMA library available for Java. If you want to give it a try, and succeed, feel free to submit a [pull request](https://github.com/ecos-wtf/programstore-loader) and I'll happily merge it.

### CRC validation
 
The loader does not validate the header CRC or the data CRC at the moment. Two methods are implemented ( `getHeaderCRC` and `getDataCRC`) that set the right values for polynomials, initial value, and xor filter but they return the wrong results due to Java handling of signedness. I'll probably get back to it in the future but given that CRC validation is performed by the external binary we call, this should not lead to loading corrupted images.
 
### Overlays
 
Overlays for BSS, stack, and heap region are in the works but are not ready yet. This will be added in the next release.

## Installation
 
If you just want to install the loader into a existing Ghidra installation:

1. Download the .zip from [releases](https://github.com/ecos-wtf/programstore-loader/releases) OR build the project.
2. Put the .zip into the GHIDRA_INSTALL_DIR/Extensions/Ghidra folder
3. In the initial window (not the Code Browser), open the File menu, and select Install Extensions. Click the small 'plus' icon in the top right of the window, and select the extension zip file downloaded. This should add an entry into the extensions list. Make sure it is checked and click OK.
4. Restart Ghidra.

## Build from Source

Provided is an Eclipse project to debug and build the loader. You must have a Ghidra installation as well as the GhidraDev Eclipse extension.

To export a build of the project in Eclipse select File > Export and then choose Ghidra > Ghidra Module Extension. You can then use a local Gradle installation or an online build.

## Contributing & Support

- Fork, modify and pull request to contribute, don't hesitate to open issues suggesting features, reporting bugs, asking for documentation or changes, etc

## References

- ProgramStore format handling - [https://github.com/Broadcom/aeolus/](https://github.com/Broadcom/aeolus/tree/master/ProgramStore)
- ProgramStore firmware dumps from different manufacturers - [https://github.com/jclehner/bcm2-utils](https://github.com/jclehner/bcm2-utils)
- Nintendo DS Ghidra Loader - [https://github.com/pedro-javierf/NTRGhidra/](https://github.com/pedro-javierf/NTRGhidra/)
