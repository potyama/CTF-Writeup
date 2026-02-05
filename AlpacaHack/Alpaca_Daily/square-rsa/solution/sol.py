from Crypto.Util.number import long_to_bytes
from math import isqrt

n = 66579369096057840799275275806551056825754855027296356876541315429102104919401
c = 23240514848563033397887056861198100244595942784363115352574337396646368790635
p = isqrt(n)

assert p*p == n

phi = p*(p - 1)
e = 65537

d = int(pow(e, -1, phi))
m = pow(c, d, n)
print(long_to_bytes(m).decode())


