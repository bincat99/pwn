
# House of Daehee
-----------------------------
from Christmas CTF 2016
pwn 100

code seems like unlink problem of [pwnable.kr](http://pwnable.kr) 
There are two differences.
1. given libc leak instead of stack address leak
2. nullified argv and envp

To solve this, I followed  [House of Orange](http://4ngelboy.blogspot.kr/2016/10/hitcon-ctf-qual-2016-house-of-orange.html)


_IO_list_all pointer를 잘 덮고 abort 루트안에서 
조건을 적당히 통과해서 _IO_OVERFLOW 로 뛰게될 때 내가 덮은 function pointer로 뛰게 할 수 있다. 

After overwrite _IO_list_all pointer, in abort routine, I got the rip control by overwritten function pointer (_IO_OVERFLOW)

  ```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)

#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
      || (_IO_vtable_offset (fp) == 0
        && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
          > fp->_wide_data->_IO_write_base))
#endif
    )
    && _IO_OVERFLOW (fp, EOF) == EOF)
  result = EOF;
```



```bash
christmas1@ubuntu:/tmp/heheunlink2$ ./sol_unlink2.py
[+] Starting local process '/home/christmas1/unlink2': Done
70774af855

*** Error in `': double free or corruption (!prev): 0x000055f84a770030 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x77725)[0x7f4831539725]
/lib/x86_64-linux-gnu/libc.so.6(+0x7ff4a)[0x7f4831541f4a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7f4831545abc]
[0x55f848810a52]
[0x55f848810d6f]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f48314e2830]
[0x55f848810899]
======= Memory map: ========
55f848810000-55f848812000 r-xp 00000000 08:01 1049659                    /home/christmas1/unlink2
55f848a11000-55f848a12000 r--p 00001000 08:01 1049659                    /home/christmas1/unlink2
55f848a12000-55f848a13000 rw-p 00002000 08:01 1049659                    /home/christmas1/unlink2
55f84a770000-55f84a791000 rw-p 00000000 00:00 0                          [heap]
7f482c000000-7f482c021000 rw-p 00000000 00:00 0
7f482c021000-7f4830000000 ---p 00000000 00:00 0
7f48312ac000-7f48312c2000 r-xp 00000000 08:01 3539479                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f48312c2000-7f48314c1000 ---p 00016000 08:01 3539479                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f48314c1000-7f48314c2000 rw-p 00015000 08:01 3539479                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f48314c2000-7f4831682000 r-xp 00000000 08:01 3539453                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4831682000-7f4831881000 ---p 001c0000 08:01 3539453                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4831881000-7f4831885000 r--p 001bf000 08:01 3539453                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4831885000-7f4831887000 rw-p 001c3000 08:01 3539453                    /lib/x86_64-linux-gnu/libc-2.23.so
7f4831887000-7f483188b000 rw-p 00000000 00:00 0
7f483188b000-7f48318b1000 r-xp 00000000 08:01 3539429                    /lib/x86_64-linux-gnu/ld-2.23.so
7f4831aa1000-7f4831aa4000 rw-p 00000000 00:00 0
7f4831aad000-7f4831ab0000 rw-p 00000000 00:00 0
7f4831ab0000-7f4831ab1000 r--p 00025000 08:01 3539429                    /lib/x86_64-linux-gnu/ld-2.23.so
7f4831ab1000-7f4831ab2000 rw-p 00026000 08:01 3539429                    /lib/x86_64-linux-gnu/ld-2.23.so
7f4831ab2000-7f4831ab3000 rw-p 00000000 00:00 0
7ffd0ad85000-7ffd0ada6000 rw-p 00000000 00:00 0                          [stack]
7ffd0ade1000-7ffd0ade3000 r--p 00000000 00:00 0                          [vvar]
7ffd0ade3000-7ffd0ade5000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
$ id
uid=1098(christmas1) gid=1098(christmas1) egid=1101(christmas1_pwn) groups=1101(christmas1_pwn),1098(christmas1)
$
```




