from pwn import *
from base64 import b64encode, b64decode
r = remote ("bad.eatpwnnosleep.com", 8888)

r.recvuntil ("STAGE : 1\n")

i = 1
while True:
  prob = b64decode(r.recvuntil ("Send your file encode as base64.(Allow only 2 byte to change)").split ("Send")[0])

  print 'Stage_1_{}'.format(i)
  f = open ("prob_01", "wb")
  f.write (prob)
  f.close ()

  fuck_boy = 0
  elf = ELF ("./prob_01")
  getint_addr = elf.functions["get_int"].address & 0x0fff
  target = prob[getint_addr:].find("\x8d") - 4 

  if target == 7:
    target = 10 
    fuck_boy = 1
  patch_addr = getint_addr + target
  if fuck_boy == 1:
    prob_patch = prob[:patch_addr] + "\x08" + prob[patch_addr+1:]
  else:
    prob_patch = prob[:patch_addr] + "\x08\x00" + prob[patch_addr+2:]

  #debugging purpose 
  """
  f = open ("prob_01_patch", "wb")
  f.write (prob_patch)
  f.close ()
  """
  r.sendline (b64encode(prob_patch))
  
  ret1 = r.recvline ()
  ret2 = r.recvline ()
  del elf 

  if "Success" not in ret1 and "Success" not in ret2:
    break
  if i == 30:
    break
  i += 1

print ret1
print ret2

r.recvuntil ("STAGE : 2\n")

i = 1
while True:
  prob = b64decode(r.recvuntil ("Send your file encode as base64.(Allow only 4 byte to change)").split ("Send")[0])

  print 'Stage_2_{}'.format(i)
  f = open ("prob_02", "wb")
  f.write (prob)
  f.close ()

  fuck_boy = 0
  elf = ELF ("./prob_02")
  getint_addr = elf.functions["get_int"].address & 0x0fff
  target = prob[getint_addr:].find("\x8d") - 4 

  if target == 7:
    target = 10 
    fuck_boy = 1
  patch_addr = getint_addr + target
  if fuck_boy == 1:
    prob_patch_one = prob[:patch_addr] + "\x0c" + prob[patch_addr+1:]
  else:
    prob_patch_one = prob[:patch_addr] + "\x04\x00" + prob[patch_addr+2:]


  getfile_addr = elf.functions["get_file"].address & 0x0fff
  target = prob_patch_one[getfile_addr:].find("\x8d") - 4
  size = prob_patch_one[getfile_addr+5:getfile_addr+9]
  if size[3] == "\x00":
    new_size = u32 (size.ljust(4, "\x00")) - 12
    new_size = p32 (new_size)[:2]
    patch_addr = getfile_addr + target
    prob_patch = prob_patch_one[:patch_addr] + new_size + prob_patch_one[patch_addr+2:]

  else:
    new_size = u32 (size[:1].ljust(4, "\x00")) - 12 
    new_size = p32 (new_size)[:2]
    patch_addr = getfile_addr + target
    prob_patch = prob_patch_one[:patch_addr] + new_size + prob_patch_one[patch_addr+2:]
  
  #debugging purpose
  """
  f = open ("prob_02_patch", "wb")
  f.write (prob_patch)
  f.close ()
  """

  r.sendline (b64encode(prob_patch))
  
  ret1 = r.recvline ()
  ret2 = r.recvline ()

  del elf
  if "Success" not in ret1 and "Success" not in ret2:
    break
  if i == 30:
    break
  i += 1

print ret1
print ret2

r.recvuntil ("STAGE : 3\n")

i = 1
while True:
  prob = b64decode(r.recvuntil ("Send your file encode as base64.(Allow only 6 byte to change)").split ("Send")[0])

  print 'Stage_3_{}'.format(i)
  f = open ("prob_03", "wb")
  f.write (prob)
  f.close ()

  fuck_boy = 0
  elf = ELF ("./prob_03")
  getint_addr = elf.functions["get_int"].address & 0x0fff
  target = prob[getint_addr:].find("\x8d") - 4 

  if target == 7:
    target = 10 
    fuck_boy = 1
  patch_addr = getint_addr + target
  if fuck_boy == 1:
    prob_patch_one = prob[:patch_addr] + "\x0c" + prob[patch_addr+1:]
  else:
    prob_patch_one = prob[:patch_addr] + "\x04\x00" + prob[patch_addr+2:]


  getfile_addr = elf.functions["get_file"].address & 0x0fff
  target = prob_patch_one[getfile_addr:].find("\x8d") - 4
  size = prob_patch_one[getfile_addr+5:getfile_addr+9]
  if size[3] == "\x00":
    new_size = u32 (size.ljust(4, "\x00")) - 12
    #print "new_size = {}".format (hex(new_size))
    new_size = p32 (new_size)[:2]
    patch_addr = getfile_addr + target
    prob_patch_two = prob_patch_one[:patch_addr] + new_size + prob_patch_one[patch_addr+2:]

  else:
    new_size = u32 (size[:1].ljust(4, "\x00")) - 12 
    #print "new_size!! = {}".format (hex(new_size))
    new_size = p32 (new_size)[:2]
    patch_addr = getfile_addr + target
    prob_patch_two = prob_patch_one[:patch_addr] + new_size + prob_patch_one[patch_addr+2:]


  create_addr = elf.functions["create_file"].address & 0x0fff
  modify_addr = elf.functions["modify_file"].address & 0x0fff 

  target = prob_patch_two[modify_addr:].find("\x8d") - 4

  offset_size = prob_patch_two[create_addr:].find("\x50\xe8") - 4

  size = prob_patch_two[create_addr + offset_size:create_addr + offset_size+4]
  if size[3] == "\x00":
    new_size = u32 (size.ljust(4, "\x00")) 
    #print "new_size = {}".format (hex(new_size))
    new_size = p32 (new_size)[:2]
    patch_addr = modify_addr + target
    prob_patch = prob_patch_two[:patch_addr] + new_size + prob_patch_two[patch_addr+2:]

  else:
    offset_size = prob_patch_two[create_addr:].find("\x50\xe8") - 1
    size = prob_patch_two[create_addr + offset_size:create_addr + offset_size+1]
    new_size = u32 (size[:1].ljust(4, "\x00")) 
    #print "new_size!! = {}".format (hex(new_size))
    new_size = p32 (new_size)[:2]
    patch_addr = modify_addr + target
    prob_patch = prob_patch_two[:patch_addr] + new_size + prob_patch_two[patch_addr+2:]




  f = open ("prob_03_patch", "wb")
  f.write (prob_patch)
  f.close ()

  r.sendline (b64encode(prob_patch))
  
  ret1 = r.recvline ()
  ret2 = r.recvline ()

  del elf
  if "Success" not in ret1 and "Success" not in ret2:
    break
  if i == 30:
    break
  i += 1

print ret1
print ret2
r.interactive()


