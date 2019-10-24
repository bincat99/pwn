In this challenge, `know_your_mem.c` is the meat.

However, remember that timeouts are strict -- it's suggested to first try locally in C.

Basically:

  # First solve it in 'standard' C without triggering alarm()
  sudo apt install libseccomp-dev libseccomp2
  edit simplified_shellcode.so.c
  make check

  # Switch syscalls to Google's linux_syscall_support
  edit shellcode.c
  make check

  # If all goes well, shellcode.bin.pkt will be ready to submit as-is!
