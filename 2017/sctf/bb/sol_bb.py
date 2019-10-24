from pwn import *
from hashlib import sha256
from base64 import b64decode

r = remote ("buildingblocks.eatpwnnosleep.com", 46115)

context.arch = 'amd64'
context.os = 'linux'


stage = 1
while True:
  print "stage {}".format (stage)
  r.recvuntil ("stage ({}/10)\n".format(stage))
  r.recvuntil ("[")
  asm_set = r.recvuntil ("]")[:-1].split (", ")

  asm_list = []
  cmp_dict = {}

  for i in (asm_set):
    asm_list.append (b64decode (eval(i)))

  def keep_cmp ():
    for i in xrange(len(asm_list)):
      if asm_list[i][0] == "\x3d":
        key = u32 (asm_list[i][1:5])
        cmp_dict[key] = i



  def calculate (asm_v, _eax = 0):
    eax = _eax
    edx = 0
    end = 0
    cal_asm = ""
    chk = asm_v.find ("\x74\x08")
    
    if asm_v.find ("\x0f\x05") != -1:
      return (eax, edx, 1)

    if chk == -1:
      cal_asm = asm_v

    else:
      cal_asm = asm_v[:chk] + asm_v[chk+10:]

    i = 0
    while True:
      if cal_asm[i] == "\xb8":
        eax = u32 (cal_asm[i+1:i+5])
        i += 5

      elif cal_asm[i] == "\x05":
        eax += u32 (cal_asm[i+1:i+5])
        eax &= 0xffffffff
        i += 5

      elif cal_asm[i] == "\x2d":
        sub = u32 (cal_asm[i+1:i+5])
        if eax < sub:
          eax = (eax | 0x100000000) - sub
        else:
          eax -= sub
        eax &= 0xffffffff
        i += 5

      elif cal_asm[i] == "\xba":
        edx = u32 (cal_asm[i+1:i+5])
        i += 5
        
      elif cal_asm[i] == "\xf7":
        mul = edx * eax
        edx = mul >> 32
        eax = mul & 0xffffffff
        i += 2

      elif cal_asm[i] == "\x3d":
        i += 5

      if i >= len(cal_asm):
        break
    return (eax, edx, end)

  #for i in asm_list:
  #  print disasm (i)
  #  print ""
  ban_list = ["\xb8\x00\x00\x00\x00\x67\x8b"]
  later_list = [ "\x48\xc7\xc7\x00\x00\x00\x00\x0f\x05"]

  answer = ""

  for i in xrange (len(asm_list)):
    asm_v = asm_list[i]
    if later_list[0] not in asm_v and ban_list[0] not in asm_v:
      start_num = i
      answer += asm_v

  for i in xrange (len(asm_list)):
    asm_v = asm_list[i]
    if later_list[0] in asm_v: #and ban_list[0] not in i:
      end_num = i

  cmp_dict = {}
  keep_cmp ()

  (eax, edx, end) = calculate (asm_list[start_num])

  while True:

    if end == 1:
      #answer += asm_list[end_num]
      break

    if eax in cmp_dict.keys():
      n = cmp_dict[eax]
      answer += asm_list[n]

    else:
      print "FUCKING"
      break

    (eax, edx, end) = calculate (asm_list[n], eax)

  sha_answer = sha256(answer).hexdigest()

  r.sendline (sha_answer)
  stage +=1 

  if stage == 11:
    break

r.interactive ()
  
