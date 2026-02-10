import math
import hashlib
from Crypto.Cipher import AES

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
LOW = 1500
MASK = (1 << LOW) - 1

d = {}
with open("../distfiles/output.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        d[k.strip()] = v.strip()

A = int(d["alice_public"])
B = int(d["bob_public"])
leak = int(d["leak"]) & MASK
enc = bytes.fromhex(d["encrypted_flag"])

H = pow(g, 1 << LOW, p)
T = (A * pow(pow(g, leak, p), p - 2, p)) % p

bound = 1 << (p.bit_length() - LOW)
m = math.isqrt(bound - 1) + 1

tbl = {}
e = 1
for j in range(m):
    if e not in tbl:
        tbl[e] = j
    e = (e * H) % p

factor = pow(pow(H, p - 2, p), m, p)
gamma = T
k = None
for i in range(m + 1):
    j = tbl.get(gamma)
    if j is not None:
        x = i * m + j
        if x < bound:
            k = x
            break
    gamma = (gamma * factor) % p

if k is None:
    raise SystemExit("k not found")

a = leak + k * (1 << LOW)
if pow(g, a, p) != A:
    raise SystemExit("Not valid a")

s = pow(B, a, p)
key = hashlib.sha256(s.to_bytes(p.bit_length() // 8, "big")).digest()
nonce, ct = enc[:8], enc[8:]
flag = AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
print(flag.decode())