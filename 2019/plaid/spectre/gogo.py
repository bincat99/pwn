from pwn import *

context.os='linux'
context.arch = 'amd64'


def print_cdq():
  for i in xrange (100):
    print disasm ("\x4d\x63" + chr((8*(i&7) | (i>>3)&7| 0xc0)))

def print_add ():
  for i in xrange (100):
    print disasm ("\x4d\x01" + chr(i | 0xc0))

def print_sub ():
  for i in xrange (100):
    print disasm ("\x4d\x29" + chr(i | 0xc0))

def print_and ():
  for i in xrange (100):
    print disasm ("\x4d\x21" + chr(i | 0xc0))

def print_shl ():

  for reg in xrange (100):
    gadget = "\x44\x88"+chr(0xc1|reg&0x38) +"\x49\xd3" + chr (reg&7 | 0xe0) 
    print (disasm (gadget))

def print_shr ():
  
  for reg in xrange (100):
    gadget = "\x44\x88"+chr(0xc1|reg&0x38) +"\x49\xd3" + chr (reg&7 | 0xe8) 
    print (disasm (gadget))

def print_mov ():
  for reg in xrange (100):
    gadget = "\x4d\x89"+chr(0xc0|reg) 
    print (disasm (gadget))

def print_movc ():
  c = 0x41414141

  for reg in xrange (100):
    rr = reg&7
    if rr >0xf :
      rr -= 0x10
      gadget = "\x48\xc7" + chr(rr|0xc0) + p32(c)
    else :
      gadget = "\x49\xc7" + chr(rr|0xc0) + p32(c)

    print disasm (gadget)

def print_load ():
  for reg in xrange (100):
    rr = (reg>>3) & 7
    if (rr > 8):
      sys.exit ("load reg error")
    gadget = "\x44\x89" +  chr ((rr * 8) | 0xc0)
    gadget += "\x4c\x8b" + chr(8*(reg&7)+4) + "\x07"

    print disasm (gadget)
print_cdq ()
