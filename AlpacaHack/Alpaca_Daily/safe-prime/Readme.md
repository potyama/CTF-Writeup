# Safe Prime
authored by ptr-yudai
> Using a safe prime makes RSA secure, doesn't it?

```python
import os
from Crypto.Util.number import getPrime, isPrime

FLAG = os.getenv("FLAG", "ctf4b{*** REDACTED ***}").encode()
m = int.from_bytes(FLAG, 'big')

while True:
    p = getPrime(512)
    q = 2 * p + 1
    if isPrime(q):
        break

n = p * q
e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")
```

When $`2p+1`$, if $`q`$ is also prime, then $`p`$ is called a Sophie Germain prime, and $`q = 2p + 1`$ is called a safe prime.
In this challenge, we deal with safe primes.

## solution
From $`q = 2p + 1`$, we have

$$
N = pq = p(2p+1) = 2p^2 + p.
$$

In other words, $`p`$ is a solution to the quadratic equation

$$
2p^2+p-N = 0.
$$

Once We find $`p`$, we can compute $`q`$ as $`q = 2p + 1`$(equivalently, $`q=N/p`$).

```python
from Crypto.Util.number import isPrime, long_to_bytes
import sympy
n = 292927367433510948901751902057717800692038691293351366163009654796102787183601223853665784238601655926920628800436003079044921928983307813012149143680956641439800408783429996002829316421340550469318295239640149707659994033143360850517185860496309968947622345912323183329662031340775767654881876683235701491291
c = 40791470236110804733312817275921324892019927976655404478966109115157033048751614414177683787333122984170869148886461684367352872341935843163852393126653174874958667177632653833127408726094823976937236033974500273341920433616691535827765625224845089258529412235827313525710616060854484132337663369013424587861

p = sympy.Symbol('p')

p = sympy.solve(2*p**2 + p - n)
p = int(p[1])
q = n // p

e = 65537

d = pow(e, -1, (p-1)*(q-1))

m = pow(c, d, n)

print(long_to_bytes(m).decode())
```
Flag: `ctf4b{R3l4ted_pr1m3s_4re_vuLner4ble_n0_maTt3r_h0W_l4rGe_p_1s}`
