import os
from Crypto.Util.number import getPrime, bytes_to_long

flag = os.environ.get("FLAG", "Alpaca{****** REDACTED ******}").encode()
assert len(flag) == 30

p = getPrime(128)
n = p * p  # !?

e = 65537
m = bytes_to_long(flag)
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")
