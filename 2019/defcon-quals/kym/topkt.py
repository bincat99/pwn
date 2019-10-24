#!/usr/bin/env python3

"""Turn a raw shellcode binary into the format expected by know_your_mem."""

import os, sys, struct

with open(sys.argv[1], "rb") as inf, open(sys.argv[1]+'.pkt', "wb") as outf:
    l = os.fstat(inf.fileno()).st_size
    outf.write(struct.pack("<H", l))        # uint16 length
    outf.write(inf.read(l))                 # payload

assert os.stat(sys.argv[1]+".pkt").st_size == 2+l
