# HellCouple

> 脆弱なカップル！

```python
import secrets
import hashlib
from Crypto.Cipher import AES
import os

FLAG = os.getenv("FLAG", "Alpaca{dummy}").encode()

# https://datatracker.ietf.org/doc/html/rfc3526#section-2
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

alice_private = secrets.randbelow(p)
bob_private = secrets.randbelow(p)

alice_public = pow(g, alice_private, p)
bob_public = pow(g, bob_private, p)

print("alice_public:", alice_public)
print("bob_public:", bob_public)
print("leak:", alice_private & (2**1500 - 1))

shared_key = pow(alice_public, bob_private, p)
assert shared_key == pow(bob_public, alice_private, p)
session_key = hashlib.sha256(shared_key.to_bytes(p.bit_length() // 8, "big")).digest()

cipher = AES.new(session_key, AES.MODE_CTR)
encrypted_flag = cipher.nonce + cipher.encrypt(FLAG)
print("encrypted_flag:", encrypted_flag.hex())
```

## Solution
`alice_private` (hereafter $`a`$) and `alice_public` (hereafter $`A`$) are expressed as follows.

$$
\begin{align}
a &= leak + k \cdot 2^{1500} \\
A &\equiv g^a \pmod p
\end{align}
$$

Here, $`k`$ corresponds to the upper 36 bits (the bit length of $`p`$ is 1536 bits).
Substituting $`a`$ into $`A`$, we get:

$$
A = g^{leak + k \cdot 2^{1500}} \equiv g^{leak} \cdot (g^{2^{1500}})^k \pmod p
$$

After this transformation, the only unknown variable is $`k`$.
In this form, it is still inconvenient to solve, so let us rearrange the expression to isolate $`k`$.

First, move $`g^{leak}`$ to the left-hand side and define it as $`T`$.

$$
T = A \cdot (g^{leak})^{-1}
$$

Here, since $`A\equiv g^{leak + k \cdot 2^{1500}} \pmod p`$, we have:

$$
T \equiv g^{leak + k \cdot 2^{1500}} \cdot (g^{leak})^{-1}
$$

By the exponent law, because it becomes $`g^{leak} \cdot (g^{2^{1500}})^k`$, we can write:

$$
T \equiv g^{leak} \cdot (g^{2^{1500}})^k \cdot (g^{leak})^{-1}
$$

Since $`g^{leak}`$ and its inverse cancel out, we finally obtain:

$$
T \equiv (g^{2^{1500}})^k \pmod p
$$

Defining $`g^{2^{1500}}`$ as $`H`$, we get a clean form:

$$
T \equiv H^k \pmod p
$$

This neatly reduces the problem to a discrete logarithm problem of finding $`k`$.

Finally, let us consider how to solve this discrete logarithm problem.
In this challenge, the bit length of the unknown is 36 bits, so it seems we would need about $`2^{36}`$ trials.
However, since $`2^{36} = 68719476736`$, brute-forcing directly is impractical.

To solve the discrete logarithm problem efficiently, we use the Baby-step Giant-step (BSGS) algorithm.
BSGS can reduce the search range $`0 \le x < n`$ for $`x`$ in

$$
g^x \equiv h \pmod p
$$

to about $`\sqrt{n}`$ steps.

Let the step count be $`m \approx \sqrt{n}`$, and decompose the unknown $`x`$ as:

$$
x = im + j\space (0 \le i, j < m)
$$

Then,

$$
g^x = g^{im+j} = (g^m)^i \cdot g^j
$$

so we can express:

$$
(g^m)^i \cdot g^j \equiv h \pmod p
$$

Multiplying both sides by $`(g^m)^{-i}`$ gives:

$$
g^j \equiv h \cdot (g^m)^{-i} \pmod p
$$

Thus, we can view it as the problem of searching for $`i, j`$ such that these relations hold.

First, compute all values $`g^j \pmod p\space(j = 0, 1, \dotsm, m-1)`$ and store them in a hash table.
This operation is called the baby-step.
Then, compute $`h \cdot (g^m)^{-i}\space(i = 0, 1, \dotsc, m)`$ and check whether each value exists in the hash table created in the baby-step phase; this operation is called the giant-step.

If a match is found, the above equation holds, and since

$$
h \equiv (g^m)^i \cdot g^j \equiv g^{im+j} \equiv g^x
$$

the solution is $`im+j`$.
Letting $`N = 2^{36}`$, we have $`\sqrt{2^{36}} = 262144`$, so it is clearly feasible.

In this way, we can recover the secret key $`a`$, and then decrypt by following:
shared key $`\rightarrow`$ SHA256 $`\rightarrow`$ AES-CTR.

The code is as follows.
```python
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
```