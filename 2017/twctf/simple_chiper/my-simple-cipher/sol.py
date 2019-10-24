import sys
import random

txt = "153a474b6a2d3f7d3f7328703e6c2d243a083e2e773c45547748667c1511333f4f745e".decode ('hex')

txt_len = len (txt)
flag_len = txt_len - 14
R = '\x7c'
flag = "" + R
key = {}

KEY_LEN = 13

key[flag_len % KEY_LEN] = chr ((ord (txt[flag_len]) - ord (txt[flag_len - 1]) - ord ('|') ) % 128)

while len (key) != 13:

  for k in key.keys():
    for i in range ((flag_len) + 1, len (txt)):
      if (i) % 13 == k:
        key[(i - flag_len - 1 ) % 13] = chr ((ord (txt[i]) - ord(txt[i-1]) - ord (key[k])) % 128)

print key

txt = "\x7c" + txt

flag = ""

for i in range (1, flag_len + 1):
  a = ((ord (txt[i]) - ord (txt[i-1]) - ord (key[(i-1) % 13] )) % 128)
  flag += chr (a)
print flag
