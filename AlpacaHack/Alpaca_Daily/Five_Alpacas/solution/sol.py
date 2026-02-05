import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *
 
HOST = "34.170.146.252"
PORT = 58209

io = remote(HOST, PORT)

io.recvuntil("[DEBUG] key: ")

key = io.recvline().strip().decode()
key = bytes.fromhex(key)
print(f"Leaked key: {key}")
iv = os.urandom(16)
data = chr(129433) * 5
pt = pad(data.encode("utf-8"), 16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pt)


io.sendlineafter("Enter your ciphertext (hex): ", ct.hex().encode())
io.sendlineafter("Enter your IV (hex):", iv.hex().encode())

io.interactive()
