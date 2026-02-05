import hashlib
from sympy import factorint
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import inverse

x1=4052328936969804578
x2=8676271689691567645
x3=2647032430467963079
x4=6612596210231769351
enc=bytes.fromhex("0c5355c5bb76b2a86aa7cf53279fb2350883865f2ca7423ff47512278a59a8db1ed85e82e0d84c2fec52e29d0b3aefd97d791f11edf18efdf1febc07ae860b8b")

t1 = x2 - x1
t2 = x3 - x2
t3 = x4 - x3
k = abs(t2 * t2 - t1 * t3)

p = max(q for q in factorint(k).keys() if q.bit_length() == 64)
a = (t2 % p) * inverse(t1 % p, p) % p
b = (x2 - a * x1) % p
s0 = ((x1 - b) * inverse(a, p)) % p

key = hashlib.sha256(str((p, a, b, s0)).encode()).digest()
pt = unpad(AES.new(key, AES.MODE_CBC, iv=enc[:16]).decrypt(enc[16:]), 16)
print(pt.decode())
