import os
from Crypto.Util.number import *
from math import gcd

flag = os.environ.get("FLAG", "Alpaca{dummy}")
assert len(flag) <= 40

e1 = 65517
e2 = 65577
while True:
    p = getPrime(512)
    q = getPrime(512)
    if gcd((p-1)*(q-1), e1) == gcd((p-1)*(q-1), e2) == 1:
        break
n = p * q

padded_flag = long_to_bytes(n)[:-len(flag)] + flag.encode()
m = bytes_to_long(padded_flag)
assert m < n
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)

print(f"{n = }")
print(f"{c1 = }")
print(f"{c2 = }")
