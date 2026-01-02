# super-tomato
authored by kanon
> ぴんくいろ の ぼうしょく は とまと を もとめて いる...
```python
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
```
## Solution
In this problem, we can obtain the flag by choosing `choice` such that

$$
a^{choice} \equiv 1\pmod p.
$$\

Now, when the modulus $`p`$ is a prime number, Fermat's little theorem tells us that

$$
a^{p-1} \equiv 1 \pmod p .
$$

Therefore, by setting `choice` to be $`p-1`$, we can satisfy the congruence above and obtain the flag.

```python
from pwn import *

HOST = "34.170.146.252"
PORT = 35506

io = remote(HOST, PORT)

io.recvuntil(b": ")
p = io.recvline().strip().decode()
print(p)
io.sendline(str(int(p)-1).encode())

io.interactive()
```
Flag:`Alpaca{Fully_restores_HP!!}`