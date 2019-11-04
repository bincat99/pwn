g++ -O2 -static -fPIE -nostdlib -nostartfiles shell.cc -o shell.elf -mrtm
objcopy -O binary -R .note.* -R .eh_frame -R .comment shell.elf shell.bin

