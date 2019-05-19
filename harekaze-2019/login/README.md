# login system

## vuln

some stack var is a pointer to main return address.
It is found in 18.04, not in 16.04 


## expoit
using `%3c`, we can overwrite lower 3 bytes of return address.
It is a 1.5 byte (1/4096) brute forcing, which is not very hard.

`while true; do python sol.py problem.harekaze.com 20002; done;` gave me a flag :) 

