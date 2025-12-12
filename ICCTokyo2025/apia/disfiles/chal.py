#!/usr/bin/env python3

from Crypto.Util.number import *
import os

with open("flag.txt", "rb") as f:
    FLAG = f.read()
FLAG += os.urandom(512 * 3 // 8 - 1 - len(FLAG))

p = getPrime(512)
q = getPrime(512)
N = p ** 2 * q
d = pow(N, -1, (p - 1) * (q - 1))

def encrypt(pt):
    return pow(pt, N, N)

def decrypt(ct):
    return pow(ct, d, p * q)

print("N:", N)
print("encrypted flag:", pow(bytes_to_long(FLAG), 0x10001, N))

# for test
while True:
    pt = int(input("plaintext: "))
    assert pt > 0
    print(decrypt(encrypt(pt)) == pt)