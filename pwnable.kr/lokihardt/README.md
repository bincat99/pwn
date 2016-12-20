#lokihardt

From [pwnable.kr][http://pwnable.kr] :)

First, this solver is quite different from the intended solution. (you can read the intended_sol.py after getting shell)

```bash
[*] 
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

The easily we can find that reference count check doesn't work well.

```c
void Delete(unsigned int idx){
    ArrayBuffer[idx] = NULL;
    refCount--;
}
```

```c
void gc(){
    if(refCount == 0 && theOBJ != NULL){
        free(theOBJ);
        free(randomPadding);
        theOBJ = NULL;
    }
}
```

Delete does not check whether ArrayBuffer index was already nullified and refCount is already zero. So we can call gc() whenever we want.  
However, gc checks whether theObj is null or not, so that we cannot use the technic of general UAF. Also the size of theObj is fixed.

The key idea is that random padding will help us. Due to the random padding, we can make address leak and writing of 16bytes to anywhere (of course it's not easy work)

Cheer up!

