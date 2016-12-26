# asm2
-----------------------------
from Christmas CTF 2016
pwn 250

Features  
1. sysenter, int 0x80, vdso are filtered.
2. code area and stack area are seperated.

Daehee, problem owner, said that there is no need to brute force, but I have no idea about it. 
I just tried with one random address.

```bash
  christmas2@ubuntu:~$ ldd ./asm2
  linux-gate.so.1 =>  (0xf77b3000)
  libc.so.6 => /lib32/libc.so.6 (0xf75ee000)
  /lib/ld-linux.so.2 (0x5655e000)
  christmas2@ubuntu:~$
```

In problem server gdb, `system ("/bin/sh");` seemes to not work well so that I use `system ("/bin/cat flag");`

` while true; do ./sol_asm2.py; done; ` will be give you flag





