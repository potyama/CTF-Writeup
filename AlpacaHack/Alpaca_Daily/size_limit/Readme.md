authored by jp3bgy
> 復号鍵も渡したんだし、これで誰でもメッセージを読めるよね！

```python
#!/usr/bin/python3

from Crypto.Util.number import getPrime, bytes_to_long
import flag 

assert(len(flag.flag) == 131)

p = getPrime(512)
q = getPrime(512)
N = p * q
phi = (p - 1) * (q - 1)
e = 0x10001
d = pow(e, -1, phi)

flag = bytes_to_long(flag.flag)


c = pow(flag, e, N)

print(f'N = {N}')
print(f'e = {e}')
print(f'c = {c}')
print(f'd = {d}')
```

In this challenge is public private key(d), so we decrypt using 'pow(c, d, N)'.

However, decryption fails here because the flag is too long: 131 bytes = 1048 bits, which exceeds the 1024 bit modulus size.

## Solution
Let $` m = N + \alpha`$. Encrypting $` m `$ gives the following expression.

$$
c \equiv m^e \pmod N
$$

On the other hand,

$$
m \equiv N + \alpha \equiv \alpha \pmod N.
$$

Therefore, encrypting $` m = N + \alpha `$ and encrypting $`m = \alpha `$ lead to the same ciphertext $`c`$.

This time, let’s solve the problem using this idea.

Suppose the plaintext we want is $`m`$. We can write it as

$$
m = m' + \alpha N.
$$

Considering $`m`$, it must be an integer whose byte length is 131 bytes and whose prefix is `TSGCTF{`.

Let $`T`$ be the lower bound of this range. Then we have

$$
m \geq T. 
$$

So, we just need to find the smallest integer $\alpha$ that satisfies this inequality.

From

$$
m = m' + \alpha N \geq T\\
$$

we obtain

$$
\alpha N \geq T - m'\\
$$

Therefore,

$$
\alpha \geq \frac{T-m'}{N}
$$

In other words, we want to find an integer $` \alpha`$ that satisfies this inequality(in particular, the smallest such $` \alpha`$).

Therefore, we can recover the flag as follows:

1. Compute `m_prime = pow(c, d, N)`.
2. Construct the lower bound $`T`$ for a 131-byte plaintext that starts with the prefix `TSGLIVE{`
3. Compute $`\alpha`$ using the inequality above, and then recover $`m`$(e.g., $`m = m' + \alpha N`$).

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

N = 65667982563395257456152578363358687414628050739860770903063206052667362178166666380390723634587933595241827767873104710537142458025201334420236653463444534018710274020834864080096247524541536313609304410859158429347482458882414275205742819080566766561312731091051276328620677195262137013588957713118640118673
e = 65537
c = 58443816925218320329602359198394095572237417576497896076618137604965419783093911328796166409276903249508047338019341719597113848471431947372873538253571717690982768328452282012361099369599755904288363602972252305949989677897650696581947849811037791349546750246816657184156675665729104603485387966759433211643
d = 14647215605104168233120807948419630020096019740227424951721591560155202409637919482865428659999792686501442518131270040719470657054982576354654918600616933355973824403026082055356501271036719280033851192012142309772828216012662939598631302504166489383155079998940570839539052860822636744356963005556392864865

prefix = b"TSGLIVE{"
flag_length = 131
m_prime = pow(c, d, N)
T = bytes_to_long(prefix + b"\x00" * (flag_length - len(prefix)))

m = m_prime + ((T - m_prime)//N + 1) * N
print(long_to_bytes(m).decode())
```
flag: `TSGLIVE{Tttthhhhhiiiiiiisssss iiiiiiiiiisssss aaaaaaaaaaaaaa tooooooooooooooooooooo looooooooooooooooong fllllaaaaaaaaaaaaaaaaaag!}`

## Other solution
According to minaminao’s writeup, this challenge can also be solved by brute force.
https://github.com/minaminao/ctf-writeups/tree/main/daily-alpacahack/2025-12/07_size-limit

```python
from Crypto.Util.number import long_to_bytes

N = 65667982563395257456152578363358687414628050739860770903063206052667362178166666380390723634587933595241827767873104710537142458025201334420236653463444534018710274020834864080096247524541536313609304410859158429347482458882414275205742819080566766561312731091051276328620677195262137013588957713118640118673
e = 65537
c = 58443816925218320329602359198394095572237417576497896076618137604965419783093911328796166409276903249508047338019341719597113848471431947372873538253571717690982768328452282012361099369599755904288363602972252305949989677897650696581947849811037791349546750246816657184156675665729104603485387966759433211643
d = 14647215605104168233120807948419630020096019740227424951721591560155202409637919482865428659999792686501442518131270040719470657054982576354654918600616933355973824403026082055356501271036719280033851192012142309772828216012662939598631302504166489383155079998940570839539052860822636744356963005556392864865

m = pow(c, d, N)

for _ in range(1 << 25):
    m += N
    x = long_to_bytes(m)
    if b"TSGLIVE" in x:
        print(x)
        break
```
