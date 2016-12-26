// gcc -o asm2 asm2.c -m32 -pie
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#define LEN 27
char stub[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xff\x31\xf6\x31\xed";

// block x86 system call gadgets
int sandbox(char* shellcode){
	// block syscall via "int 0x80"
	if(strstr(shellcode, "\xcd\x80")) return 1;

	// block syscall via "sysenter"
	if(strstr(shellcode, "\x0f\x34")) return 1;

	// block syscall via "gs:0x10 (vdso trampoline)"
	if(strstr(shellcode, "\x65")) return 1;

	return 0;
}

int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Your christmas present is 'arbitrary-code-execution ticket'\n");
	printf("have fun with arbitrary code execution!\n");
	printf("but, for your safty, you cannot use system calls..\n");
	printf("play only with registers and memory.\n");
	printf("**this challenge does not require any brute-force**\n");
	sleep(5);

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd<0){
		printf("can't open /dev/urandom\n");
		exit(0);
	}
	int seed;
	read(fd, &seed, 4);
	srand(seed);

	unsigned int addr = rand()*0xdeadbeef;
	unsigned int addr2 = rand()*0xdeadbeef;
	addr &= 0xfffff000;
	addr2 &= 0xfffff000;
	char* sh = (char*)mmap(addr, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, 0, 0);
	char* stack = (char*)mmap(addr2, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, 0, 0);
	memcpy(sh, stub, strlen(stub));
	printf("give me your shellcode: ", sh, stack);
	read(0, sh+strlen(stub), LEN);

	int i;
	for(i=0; i<LEN; i++){
		if(sh[strlen(stub)+i] == 0){
			printf("remove null bytes in your input\n");
			exit(0);
		}
	}

	if( sandbox(sh+strlen(stub)) ){
		printf("caught by filter!\n");
		exit(0);
	}

	mprotect(addr, 0x1000, 5);
	alarm(30);
	printf("buena suerte!\n");
	asm("mov %0, %%esp" :: "r"(addr2 + 0x800));
	asm("jmp *%0" :: "r"(sh));
	return 0;
}



