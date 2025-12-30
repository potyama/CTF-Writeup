
from Crypto.Util.number import *
import os

flag = os.getenv("FLAG", "flag{example}").encode()
m = bytes_to_long(flag)

p = getPrime(512)
e = 65537
ct = pow(m, e, p)

print(f"{p = }")
print(f"{e = }")
print(f"{ct = }")

