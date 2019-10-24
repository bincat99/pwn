# begin: upper left point 
# 1 if point has dot otherwise 0
s = """10001100
01100011
11100100
01000110
10000101
00111101
01000010
10011000
11100000
11110100
10000000
00101101
01110010
00011100
00001000
10100101
11010111
01101110
10100110
10010001
10111100
10000100
10000001
10111001
11010100
00111011
11001110
11110010
00011110
10011101
11001001
11000111
01100101
00011110
10011111"""

bit_array = s.replace("\n", "")

flag = ''
base = '+-=ABCDEFGHIJKLMNOPQRSTUVWXYZ_{}'
for i in range(0, len(bit_array), 5):
  subs = bit_array[i:i+5]
  flag += base[ int(subs, 2)]

print flag