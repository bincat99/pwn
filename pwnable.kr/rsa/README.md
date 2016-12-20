#RSA_calculator

In the RSA_decrypt function, FSB bug exists.

```c
puts("- decrypted result -");
printf(&g_pbuf, v3);
putchar(10);
```

By FSB bug, we can easily overwrite got of _exit_ and execute shellcodes in the g_ebuf.



