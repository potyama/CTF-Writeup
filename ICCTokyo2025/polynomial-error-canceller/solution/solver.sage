import os
os.environ['TERM'] = 'xterm'  # または 'dumb'

from pwn import remote
import ast

p = 3228206032448054398184207628825085966554669493805463265167665696830701529540084099119723675691077452831691319854331761432219589497432288040050662747548570074130953014496607604870057675105380073309897164406646729785729201532578330096873186509309117234682633245809639249284338994655706620772820519329101507659669328377541606046361885302918096567393300090560857343615655518705495446324370687991104640239375645715605435984209673393517029405065426498328683604534684326809785017137637714528819932053242916724841181430019358197852284950025845988662748391857833018025095461388123876075748560746574557730010283229855373561220585909777842183062337103159850798250919860729181085143350005433642718633029244382037778172273552094510707390078028887706806805476918199306596091991215035473995987485308835696040679111814045192248605124668771654407959069562079856070936878829629944078913415081177173049316946587785537249387530562885913779240455487769258297814458813148406510674895734921176079208150269423916661159302685365311567728540305442742301215156832412167914717546193373727753268039860671265525137301259594544904172871511992658277371275025780536921034779910286762731526177025760027083445146912175260907784628136352261350954943600353480186149602328577
n = 16384
Zp = GF(p)
R = PolynomialRing(Zp, 'x')
x = R.gen()
w = Zp.multiplicative_generator() ^ ((p - 1) // n)
domain = [Zp(w)^i for i in range(n)]
periods = [2**i for i in range(1, 12)]

# --- FFT and IFFT ---
def fft(vals, domain):
    if len(vals) == 1: return vals
    L = fft(vals[::2], domain[::2])
    R_ = fft(vals[1::2], domain[::2])
    return [(L[i] + R_[i] * domain[i]) for i in range(len(L))] + \
           [(L[i] - R_[i] * domain[i]) for i in range(len(L))]

def generate_period_indices(n, Zp, w):
    domain = [w^i for i in range(n)]

    period_indices = {}

    for period in [2 ** i for i in range(1, n.bit_length()) if 2 ** i <= n]:
        vec = [Zp(1) if (i % period) < (period // 2) else -Zp(1) for i in range(n)]
        fft_vec = fft(vec, domain)
        indices = [i for i, val in enumerate(fft_vec) if val != 0]
        period_indices[period] = indices

    return period_indices

period_indices = generate_period_indices(n, Zp, w)
print(period_indices)

def inverse_fft(vals, domain):
    n = len(vals)
    inv_n = ~Zp(n)
    vals = fft(vals, domain)
    reordered = [vals[0]] + vals[1:][::-1]
    return [(v * inv_n) for v in reordered]

def recover_amplitudes(e_poly):
    e_hat = fft(e_poly.list(), domain)
    recovered = {}
    for period, indices in period_indices.items():
        selected_hat = [e_hat[i] if i in indices else Zp(0) for i in range(n)]
        partial = inverse_fft(selected_hat, domain)
        half = period // 2
        avg = sum(partial[:half]) / half
        recovered[period] = avg
    selected_hat = [e_hat[0]] + [Zp(0)] * (n - 1)
    const_poly = inverse_fft(selected_hat, domain)
    recovered['const'] = const_poly[0]
    return recovered

def generate_k(target_periods):
    indices = set()
    for period in target_periods:
        indices.update(period_indices.get(period, []))
    filtered_hat = [Zp(1) if i in indices else Zp(0) for i in range(n)]
    coeffs = inverse_fft(filtered_hat, domain)
    return R(coeffs)


io = remote('localhost', "2468")
# io = process(['sage', 'server.sage'])
print(io.recvuntil('>>>'))
io.sendline(str(p))
print(io.recvuntil('e(x):\n'))
e_full = R(ast.literal_eval(io.recvline().strip().decode()))

amps = recover_amplitudes(e_full)
for period in periods + ['const']:
    print(io.recvuntil('>>>'))
    io.sendline(str(amps[period]))

print("hello")

for i in range(10):
    print(io.recvuntil('Target periods: '))
    periods = ast.literal_eval(io.recvline().strip().decode())
    print(periods)
    k = generate_k(periods)
    io.recvuntil('>>>')
    io.sendline(' '.join(map(str, k.list())))

io.interactive()