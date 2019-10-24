// This is an example of turning simple C into raw shellcode.

// make shellcode.bin will compile to assembly
// make shellcode.bin.pkt will prepend the length so you can
//    ./know_your_mem < shellcode.bin.pkt

// Note: Right now the 'build' does not support .(ro)data
//       If you want them you'll have to adjust the Makefile.
//       They're not really necessary to solve this challenge though.


// From https://chromium.googlesource.com/linux-syscall-support/
static int my_errno = 0;
#define SYS_ERRNO my_errno
#include "linux-syscall-support/linux_syscall_support.h"


#define ADDR_MIN   0x0000100000000000UL
#define ADDR_MASK  0x00000ffffffff000UL


void _start()
{
  //sys_write(1, __builtin_frame_address(0), 5);  // Prints something (note: best avoid literals)
  asm(".intel_syntax noprefix");
  asm("xor r8, r8");
  asm("mov r9, rsp");
  asm("sub r9, 0x100");

  asm("loop:");
  asm("inc r8");
  //asm("mov rbx, r8");
  //asm("shl rbx, 3");
  //asm("add rsi, rbx");
  asm("add r9, 8");
  asm("mov rsi, [r9]");
  asm("mov rdi, 1");
  asm("mov rax, 1");
  asm("mov rdx, 100");
  asm("mov rcx, 100");
  asm("syscall");
  asm("cmp r8, 0x30");
  asm("jl loop");

  sys_exit_group(2);                            // Exit
}
