from Crypto.Util.number import *
import os

flag = os.getenv("FLAG", "flag{EXAMPLE_TOMATO}")

p = getPrime(2048)

print(f"I think 🍅 equals to prime.")
print(f"here is my 🍅: {p}")
print("I need ONE 🍅!!!")
choice = int(input("what is your 🍅> "))

if choice <= 0:
    print("I need a POSITIVE 🍅!!!")
    exit()

a = getPrime(1024)

if pow(a, choice, p) == 1:
    print(f"here is the flag: {flag}")
else:
    print("NO NO 🍅")
