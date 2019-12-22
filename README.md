## Ghidra Sega Saturn Loader

A (WIP) Ghidra loader for the Sega Saturn. Currently supports:
- ISO disc images
- Yabause Save States (YSS)
Grab from [Releases](https://github.com/VGKintsugi/Ghidra-SegaSaturn-Loader/releases/) or build from source. 

## Screenshots

Loader screenshot  
![Loader](screenshot_loader.png)

Disassembly View w/Decompiler  
![Disassembly View](screenshot_loaded.png)

## How to Use
### Sega Saturn ISOs
- Select any Sega Saturn ISO file
- At the "Container file detected" prompt, select "Single file"
- The loader will create functions for main, initial program (the code that runs during the Sega logo), and security_check
- Pros: Easy to use, useful for debugging game initialization, works great on Saturn homewbrew
- Cons: Doesn't load any file after the first file on disc

### Yabause Save States (YSS)
- Select any Yabause Save State (YSS) 
- The loader will load backup cart memory, high work RAM, and low work RAM to the correct places

### Applying Sega Saturn Library Signatures
- After loading in Ghidra, open "Script Manager" and execute ApplySig.py
- Select the signature file to apply

## Issues
- Code quality needs serious improvement and refactoring
- Memory map doesn't handle mirrored regions
- It would be useful to label some globals to assist reversing

## Building
- ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
- ``gradle``
- The output zip file will be created within `/dist`

## Installation
- Ghidra 9.1 added SH-1/SH-2 support.     
- Copy the zip file to ``<Ghidra install directory>/Extensions/Ghidra``.
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (``File -> Install Extensions...``).
- (Optional but recommended) Install the [ApplySig](https://github.com/NWMonster/ApplySig) script so you can use Sega Saturn library signatures. Copy to a ``ghidra_scripts`` directory.
- (Optional but recommended) Download CyberWarriorX's [Sega Saturn library signatures](http://cyberwarriorx.com/saturn-utilities) 

## Credits/References
- [Yabause](https://github.com/Yabause/yabause) - Sega Saturn emulator used to sanity check loader
- [cyberwarriorx/yssloader](https://github.com/cyberwarriorx/yssloader) - YSS loader for IDA Pro
- [Sega Saturn SH-2 Memory Map](https://wiki.yabause.org/index.php5?title=SH-2CPU)
- [ISO 9660 Documentation](https://wiki.osdev.org/ISO_9660)
- [ApplySig](https://github.com/NWMonster/ApplySig) - python script to load IDA Pro library signatures into Ghidra. 
- [Sega Saturn Library Signatures](http://cyberwarriorx.com/saturn-utilities) -  CyberWarriorX's Sega Saturn library signatures
- Thank you to @mumbel, @loudinthecloud, and the Ghidra team for helping get the SuperH plugin merged to Ghidra
- Thank you to @TrekkiesUnite118 for Java help and code review advice
- Thank you to @CyberWarriorX for just tons of amazing open source Saturn utilities. 


