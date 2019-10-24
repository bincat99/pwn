from pwn import *
from base64 import b64encode

r = remote ("dfa.eatpwnnosleep.com", 9999)



r.sendline ("auto.c")

f = open ("auto.c", "r")
code = f.read()
f.close()

b64code = b64encode(code)

r.sendline (b64code)

r.interactive()
