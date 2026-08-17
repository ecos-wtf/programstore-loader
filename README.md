# ProgramStore Ghidra Loader

A Broadcom ProgramStore firmware image loader for Ghidra 12.x (verified with Ghidra 12.1.2).
 
This loader will auto-detect ProgramStore firmware images from their header and display header information in a dialog box. On load, it takes care of decompressing the raw binary and loads both .text and .data sections.
 
## Known Limitations
 
### Decompression
 
The loader relies on a statically linked Linux x86 binary compiled from Broadcom's [aeolus](https://github.com/Broadcom/aeolus/tree/master/ProgramStore) project to perform the decompression. This limits the extension to Linux hosts on which that executable can run. The ProgramStore format does not exactly follow the standard LZMA header structure, so a pure Java LZMA decoder cannot be used directly.

### CRC validation
 
The loader does not validate the header CRC or the data CRC at the moment. Two methods are implemented ( `getHeaderCRC` and `getDataCRC`) that set the right values for polynomials, initial value, and xor filter but they return the wrong results due to Java handling of signedness. I'll probably get back to it in the future but given that CRC validation is performed by the external binary we call, this should not lead to loading corrupted images.
 
### Overlays
 
Overlays for BSS, stack, and heap region are in the works but are not ready yet. This will be added in the next release.

## Installation
 
If you just want to install the loader into an existing Ghidra installation:

1. Download the .zip from [releases](https://github.com/ecos-wtf/programstore-loader/releases) OR build the project.
2. Put the `.zip` into the `GHIDRA_INSTALL_DIR/Extensions/Ghidra` folder.
3. In the initial window (not the Code Browser), open **File > Install Extensions**. Click the plus icon, select the extension zip, enable the new extension, and click **OK**.
4. Restart Ghidra.

## Build from Source

Ghidra 12.x requires JDK 21 and Gradle 8.5 or newer. Use the Gradle version accepted by the `application.gradle.min` and `application.gradle.max` values in your Ghidra installation's `Ghidra/application.properties` file.

```sh
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra_12.x_PUBLIC
gradle buildExtension
```

The installable extension archive is written to `dist/`. You can also import the project into Eclipse with the matching GhidraDev extension for debugging.

## Contributing & Support

- Fork, modify and pull request to contribute, don't hesitate to open issues suggesting features, reporting bugs, asking for documentation or changes, etc

## References

- ProgramStore format handling - [https://github.com/Broadcom/aeolus/](https://github.com/Broadcom/aeolus/tree/master/ProgramStore)
- ProgramStore firmware dumps from different manufacturers - [https://github.com/jclehner/bcm2-utils](https://github.com/jclehner/bcm2-utils)
- Nintendo DS Ghidra Loader - [https://github.com/pedro-javierf/NTRGhidra/](https://github.com/pedro-javierf/NTRGhidra/)
