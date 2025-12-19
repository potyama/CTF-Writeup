from Crypto.Util.number import getStrongPrime
from gmpy2 import next_prime


avg = 0
for _ in range(100):
    p = getStrongPrime(1024)
    q = next_prime(p ^ (1 << 1024)-1)
    t = q - (p ^ (1 << 1024)-1)
    avg += t

print(avg//100)
