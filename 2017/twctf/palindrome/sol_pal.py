from pwn import *


r = remote ("ppc1.chal.ctf.westerns.tokyo", 8765)


def is_palindrome (s):
  
  for i in xrange (len(s)/2):
    
    if s[i] != s[-(i+1)]:
      return False

  return True 



def count_pal (l):

  count = 0

  #for i in xrange (len (l)):
  for i in l:
    for j in l:
      if is_palindrome (i + j) == True:
        count += 1
  return count
r.recvuntil ("----- START -----")

for _ in xrange (50):
  r.recvuntil ("Input"), 
  r.recvline ()
  n = int (r.recvline ())
  data = r.recvline ()[:-1]
  data = data.split (" ")
  
  assert (n == len (data))
  ans = (str (count_pal (data)))
  r.sendline (ans)
  print r.recv ()


print r.recv ()


  
