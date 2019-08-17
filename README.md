## Ghidra Sega Saturn Loader

A (WIP) Ghidra loader for the Sega Saturn. Currently supports:
- ISO format

To use select any Sega Saturn ISO file. At the "Container file detected" prompt, select "Single file". The loader will create functions for main, initial_program (the code that runs during the Sega logo), and security_check. 

## Screenshots

Loader screenshot  
![Loader](screenshot_loader.png)

Disassembly View w/Decompiler  
![Disassembly View](screenshot_loaded.png)

## Issues/Future Work
- memory map is incomplete
- memory map doesn't handle mirrored regions
- support for Yabause Save States
- it would be useful to label some globals to assist reversing
- library signatures

## Building
- ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``.
- ``gradle``
- The output zip file will be created within `/dist`

## Installation
- As SH-2 support is currently being merged into Ghidra you must first install the SuperH processor module from [VGKintsugi/ghidra](https://github.com/VGKintsugi/ghidra/tree/master/Ghidra/Processors/SuperH). 
-- Copy the SuperH directory to your ghidra/Ghidra/Processors/ directory
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (``File -> Install Extensions...``).

## Credits/References
- [Sega Saturn SH-2 Memory Map](https://wiki.yabause.org/index.php5?title=SH-2CPU)
- [ISO 9660 documented](https://wiki.osdev.org/ISO_9660)
- Thank you to @mumbel, @loudinthecloud, and the Ghidra team for helping get the SuperH plugin merged to Ghidra


