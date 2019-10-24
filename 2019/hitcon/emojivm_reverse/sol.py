with open ("chal.evm", "rb") as f:
  data = f.read ()

el = data.decode('utf-8')

inst = [
0x0,
0x1F233,                               
0x2795,                                 
0x2796,                                 
0x274C,                                 
0x2753,                                 
0x274E,                                 
0x1F46B,                                
0x1F480,                                
0x1F4AF,                                
0x1F680,                                
0x1F236,                                
0x1F21A,                                
0x23EC,                                 
0x1F51D,                                
0x1F4E4,                                
0x1F4E5,                                
0x1F195,                                
0x1F193,                                
0x1F4C4,                                
0x1F4DD,                                
0x1F521,                                
0x1F522,                                
0x1F6D1]

num_list = [
0x1F600,
0x1F601,
0x1F602,
0x1F923,
0x1F61C,
0x1F604,
0x1F605,
0x1F606,
0x1F609,
0x1F60A,
0x1F60D,
]

inst = [unichr(c) for c in inst]
num_list = [unichr(c) for c in num_list]

print inst[0] == el[0]
pc = 0
sp = -1
stack = [0] * 1024
Memo = [None] * 10
def get_switch (e):
  for i in xrange(len(inst)):
    if inst[i] == e:
      return i

  raise "Illegal Instruction"

def get_num (e):
  for i in xrange(len(num_list)):
    if num_list[i] == e:
      return i

  raise "Illegal Datacode"

def Memo_new ():
  for i in xrange(len(Memo)):
    if Memo[i] == None:
      return i
  print "Memo Max"

#for i in range (0, len(data), 3):
#  x = data[i:i+3]
INST_NOP         = 1
INST_ADD         = 2
INST_SUB         = 3
INST_MUL         = 4
INST_MOD         = 5
INST_XOR         = 6
INST_AND         = 7
INST_SETG        = 8
INST_SETEQ       = 9
INST_JMP         = 0xA
INST_JZ         = 0xB
INST_JNZ          = 0xC
INST_PUSH_IMM    = 0xD
INST_POP         = 0xE
INST_GET_Memo_BYTE  = 0xf
INST_SET_Memo_BYTE  = 0x10
INST_MAKE_Memo   = 0x11
INST_DELETE_Memo  = 0x12
INST_WRITE_Memo  = 0x13
INST_PRINT_Memo  = 0x14
INST_PRINT_STACK_STR  = 0x15
INST_PRINT_STACK_VAL  = 0x16
INST_HLT         = 0x17

while True:
  ci = get_switch (el[pc])
  
  if ci == INST_NOP:
    pc += 1

  elif ci == INST_ADD : # add
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp += 1
    if isinstance(a1, long) and isinstance(a2, str):
      a1 = int (a1)
      a2 = ord (a2)
    stack[sp] = ((a1)+(a2)) % (2**64)
    pc +=1
    print "add {}, {}".format (a1,a2)

  elif ci == INST_SUB:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    if isinstance(a1, str) and isinstance(a2, int):
      a1 = ord (a1)
    stack[sp] = a1-a2
    pc +=1
    print "sub {}, {}".format (a1,a2)

  elif ci == INST_MUL:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    stack[sp] = (a1*a2) % (2**64)
    pc +=1
    print "mul {}, {}".format (a1,a2)

  elif ci == INST_MOD:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    stack[sp] = a1%a2
    pc +=1
    print "mod {}, {}".format (a1,a2)

  elif ci == INST_XOR:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    if isinstance(a2, str):
      a1 = int (a1)
      a2 = ord (a2)
    stack[sp] = a1^a2
    pc +=1
    print "xor {}, {}".format (a1,a2)

  elif ci == INST_AND:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    stack[sp] = a1 & a2
    pc +=1
    print "and {}, {}".format (a1,a2)

  elif ci == INST_SETG:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    stack[sp] = (a1 < a2)
    pc +=1
    #print "greater {}, {}".format (a1,a2)

  elif ci == INST_SETEQ:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    sp+=1
    if isinstance(a2, long) and isinstance(a1, str):
      a2 = chr (a2)
    stack[sp] = (a1 == a2)
    pc +=1
    print "compare ",a1, a2

  elif ci == INST_JMP:
    a1 = stack[sp]
    sp -= 1
    pc = a1
    #print "JMP!", a1

  elif ci == INST_JZ:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    if a2 == True:
      pc = a1
    else:
      pc += 1

    #print "JZ!", a1, a2

  elif ci == INST_JNZ:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    if a2 == False:# and a1 != 8550:
      pc = a1
    else:
      pc += 1
    #print "JNZ!" , a1, a2

  elif ci == INST_PUSH_IMM:
    assert (sp < 1024)
    a1 = get_num (el[pc+1])
    sp += 1
    stack[sp] = a1
    pc += 2
    #print "push {}".format (a1)

  elif ci == INST_POP:
    assert (sp != -1)
    sp -= 1
    pc += 1
    print "POP"

  elif ci == INST_GET_Memo_BYTE:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    tm = Memo[a1]['memo']
    if a2 == len(tm):
      tm.append (0)
    sp +=1
    stack[sp] = tm[a2]
    print "GET BYTE: ", (tm[a2])
    pc += 1
    
  elif ci == INST_SET_Memo_BYTE:
    a1 = stack[sp]
    sp -= 1
    a2 = stack[sp]
    sp -= 1
    a3 = stack[sp]
    sp -= 1
    print a1, a2, hex(a3)
    tm = Memo[a1]['memo']
    tm[a2] = a3 
    Memo[a1]['memo'] = tm
    pc += 1

  elif ci == INST_MAKE_Memo:
    a1 = stack[sp]
    sp -= 1
    tm = Memo_new ()
    print "New Memo:", tm
    Memo[tm] = {}
    Memo[tm]['size'] = a1
    Memo[tm]['memo'] = [0] * (a1 + 1)
    pc += 1
    
  elif ci == INST_DELETE_Memo:
    a1 = stack[sp]
    sp -= 1
    Memo[a1] = None
    pc += 1
    print "DELETE MEMO", a1
    
  elif ci == INST_WRITE_Memo:
    a1 = stack[sp]
    sp -= 1
    assert (a1 >= 0 and a1 < 10)
    Memo[a1]['memo'] = list ("plis-g1v3-me33-th3e-f14g")#list(raw_input ("your memo(size={}): ".format(Memo[a1]['size'])).strip ("\n"))
    pc += 1
    print "DELETE MEMO", a1
    
  elif ci == INST_PRINT_Memo:
    a1 = stack[sp]
    sp -= 1
    assert (a1 >= 0 and a1 < 10)
    ss = ""
    for c in (Memo[a1]['memo']):
      if c == 0:
        break
      try:
        ss += chr(c)
      except:
        break
    print "READMEMO: " + ss
    pc += 1

  elif ci == INST_HLT:
    print "END!"
    break

  else:
    "FUCK"
    pause()

