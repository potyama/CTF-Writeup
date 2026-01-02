from pwn import *

HOST = "34.170.146.252"
PORT = 35506

io = remote(HOST, PORT)

io.recvuntil(b": ")
p = io.recvline().strip().decode()
print(p)
io.sendline(str(int(p)-1).encode())

io.interactive()