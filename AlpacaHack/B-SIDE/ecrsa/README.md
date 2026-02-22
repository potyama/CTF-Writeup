# ECRSA
> Elliptic Curve x RSA = ECRSA

```python
import os

# secp521r1 patemeter
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
K = GF(p)
a = K(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc)
b = K(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00)
EC = EllipticCurve(K, (a, b))

while True:
    Q = EC.random_point()
    q = int(Q.xy()[0])
    R = 2*Q
    r = int(R.xy()[0])
    if is_prime(q) and is_prime(r):
        break

n = q*r
e = 65537
m = int.from_bytes(os.environ.get("FLAG", "Alpaca{dummy}").encode(), "big")
assert m < n
c = pow(m, e, n)

print("n = {}".format(n))
print("e = {}".format(e))
print("c = {}".format(c))
```
The elliptic-curve parameters used in this challenge are secp521r1 (also known as NIST P-521).
secp521r1 is a recommended curve over the prime field $`\mathbb{F}_p`$ defined in SECG’s SEC 2.
Here, “secp” stands for Standards for Efficient Cryptography (SEC) and prime field (p).
The number 521 indicates the bit-length of $`p`$; for this curve, $`p = 2^{\scriptstyle 521} - 1`$ is used.
The suffix “r1” means: “r” indicates verifiably at random (i.e., generated in a way that can be publicly verified), and “1” is the variant number within that family. Since the choice of curve parameters may allow arbitrariness, the seed is published and the procedure to derive the coefficient $`b`$ from that seed using SHA-1 is also published, so that any third party can reproduce and verify the same $`b`$ from the same seed.
As an aside, in secp256k1 the “k” stands for Koblitz.
https://www.secg.org/sec2-v2.pdf

## Solution

In this challenge, we define $`q = x(Q), r = x(2Q)`$ as integers, and choose them so that $`q, r \in \mathbb{P}`$.
The key point is that $`r`$ is the $`x`$-coordinate of the point obtained by doubling the point whose $`x`$-coordinate is $`q`$. Using the elliptic-curve point-doubling formulas, we can express the relationship between $`q`$ and $`r`$.

For a point $`(x_1, y_1)`$ on the curve $`y^2 \equiv x^3 + ax + b \pmod p`$, its doubled point $`(x_2, y_2)`$ is computed as follows:
$$
\begin{align}
x_2 &\equiv \lambda^2 - 2x_1 \pmod p\\
y_2 &\equiv \lambda(x_2 - x_1) + y_1 \pmod p
\end{align}
$$
where $`\lambda \equiv \frac{3x_1^2+a}{2y_1} \pmod p`$.

Let $`q = (q_x, q_y), r = (r_x, r_y)`$. Then,
$$
\begin{align}
r_x &\equiv \lambda^2 - 2q_x \pmod p\\
r_y &\equiv \lambda(r_x - q_x) + q_y \pmod p
\end{align}
$$

Expanding $`r_x`$:
$$
\begin{align}
r_x &\equiv \lambda^2 - 2q_x \\
&\equiv \left(\frac{3q_x^2+a}{2q_y} \right)^2 - 2q_x\\
&\equiv \frac{9q_x^4 + 6aq_x + a^2}{4q_y^2} - 2q_x \pmod p
\end{align}
$$

From $`y^2 \equiv x^3 + ax + b \pmod p`$, we have $`q_y^2 \equiv q_x^3 + aq_x + b \pmod p`$, hence:
$$
\begin{align}
r_x &\equiv \frac{9q_x^4 + 6aq_x + a^2}{4(q_x^3 + aq_x + b)} - 2q_x\\
&\equiv\frac{(9q_x^4 + 6aq_x^2 + a^2) - 8q_x(q_x^3 + aq_x + b)}{4(q_x^3 + aq_x + b)}\\
&\equiv \frac{q_x^4 - 2aq_x^2 - 8bq_x + a^2}{4(q_x^3 + aq_x + b)} \pmod p
\end{align}
$$

In this problem, we use only the $`x`$-coordinates of both $`q`$ and $`r`$.
Therefore, $`n = qr`$ can be written as:
$$
n \equiv qr \equiv q\cdot\frac{q_x^4 - 2aq_x^2 - 8bq_x + a^2}{4(q_x^3 + aq_x + b)}  \pmod p
$$
Thus, we expressed $`n`$ using only $`q`$.

Finally, we slightly rearrange it to form an equation to solve:
$$
4n(q_x^3 + aq_x + b) - q(q_x^4 - 2aq_x^2 - 8bq_x + a^2) \equiv 0 \pmod p
$$
Hence, by finding roots with respect to the unknown variable $`q_x`$, we can recover a valid $`q`$ satisfying $`n = qr`$, and then decrypt using it to obtain the flag.

```python
from Crypto.Util.number import long_to_bytes
from sage.all import *

n = 24489807923160829853331858278295353076882496748356437425136070159565438013983472411573830861255379509744527059864107405391335396070661875605498494586447825822788450364814932266675738776136998383491576779465083731669643596152181500936763824489148317369367655622357267302603914593581625372679508643581386912033877057
e = 65537
c = 2878521000528279319502304373550176174118970956553760958198895851295578685557304197481600194317208136193632870619822554981703968844914526643614371981441816886658546070361109613762488893788055957762778868012759138069722552457665235326670564609161988943959614368453819936924812599400584406309008222724731151234689436

p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
K = GF(p)
a = K(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc)
b = K(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00)
EC = EllipticCurve(K, (a, b))

R = PolynomialRing(K, "q")
q = R.gen()

poly = 4*K(n)*(q**3 + a * q + b) - q*(q**4 - 2*a*q**2 - 8*b*q + a**2)
poly = poly.monic()

roots = poly.roots(multiplicities=False)
if not roots:
    raise ValueError("No roots found")
for root in roots:
    r = n // int(root)
    if r * int(root) == n:
        q = int(root)
        break

phi = (q-1)*(r-1)
d = pow(e, -1, phi)
flag = pow(c, d, n)
print(long_to_bytes(flag).decode())
```
Flag: `Alpaca{easier_cracked_ruined_suboptimal_algorithm}`