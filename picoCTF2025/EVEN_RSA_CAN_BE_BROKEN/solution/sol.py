from pwn import *
from Crypto.Util.number import isPrime, long_to_bytes
HOST = "verbal-sleep.picoctf.net"
PORT = 50440

io = remote(HOST, PORT)

io.recvuntil(b"N:")
N = int(io.recvline().strip().decode())

io.recvuntil(b"e:")
e = int(io.recvline().strip().decode())

io.recvuntil(b"cyphertext:")
c = int(io.recvline().strip().decode())

p = N//2
q = 2
d = pow(e, -1, (p-1)*(q-1))
print(long_to_bytes(pow(c, d, N)).decode())