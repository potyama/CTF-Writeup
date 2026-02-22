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
