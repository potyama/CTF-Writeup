from pwn import *
from Crypto.Util.number import long_to_bytes

HOST = "localhost"
PORT = 12349

io = remote(HOST, PORT)

io.recvuntil(b"N: ")
N = int(io.recvline().strip())
io.recvuntil(b"encrypted flag: ")
enc_flag = int(io.recvline().strip())

print("N =", N)
print("enc_flag =", enc_flag)

l = 2 ** 1022
r = 2 ** 1024 - 2**513 + 1
while r-l != 1:
    m = (l + r) // 2
    io.sendlineafter(b"plaintext: ", str(m).encode())
    resp = io.recvline().strip()
    if resp == b"True":
        l = m 
    else:
        r = m


pq = r
print("pq =", pq)
p = N//pq
q = pq//p
print("p =", p)
print("q =", q)
e = 0x10001

assert p * p * q == N

d = pow(e, -1, p * (p - 1) * (q - 1))
m = pow(enc_flag, d, N)
flag = long_to_bytes(m)
prefix = b"ICC{"
start = flag.rfind(prefix)
end = flag.find(b"}", start)
print(flag[start:end + 1].decode())


