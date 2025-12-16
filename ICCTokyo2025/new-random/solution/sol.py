from pwn import *
from Crypto.Util.number import inverse
import time
import bisect
import numpy as np

HOST = "localhost"
PORT = 12348

A = int(0x5deece66d)
B = int(0xb)
M = 2**48

seed_uniquifiers = []
nano_candiates = []
t_base = time.time()
tmp_io = None

leaks = []
times = []

def recv_leak(io):
    io.recvuntil(b"leak: ")
    leak = int(io.recvline().strip())
    if leak < 0:
        leak += 2**32

    return leak
def calc_lcg(seed):
    return (A*seed+B)%M

def calc_seed_uniquifier():
    seed_uniquifier = 8682522807148012
    seed_multiplier = 1181783497276652981
    for i in range(5):
        seed_uniquifier = (seed_uniquifier * seed_multiplier) % M
        seed_uniquifiers.append(seed_uniquifier ^ A)
        
def brute_force_restore_lcg(candidates):
    for j in range(2**16):
        x1 = (2**16)*leaks[i] + j
        x0 = ((x1 - B) * inverse(A, M)) % M
        seed = x0 ^ seed_uniquifiers[0]
        candidates.append(seed - times[i])
    return candidates

def restore_lcg(seed_i):
    best_t = None
    best_d = 2**63
    for j in range(2**16):
        x1 = (leak << 16) + j
        x0 = ((x1 - B) * inverse(A, M)) % M
        nano = x0 ^ seed_i

        d = abs((nano - td) - correct_seed)
        if d < best_d:
            best_d = d
            best_t = nano

    x0 = best_t ^ seed_i

    x1 = (A * x0 + B) % M
    x2 = (A * x1 + B) % M
    secret = x2 >> 16
    if secret >= 2**31:
        secret -= 2**32

    return secret

calc_seed_uniquifier()
for i in range(32):
    io = remote(HOST, PORT)
    leak = recv_leak(io)
    leaks.append(leak)
    t_now = time.time()
    times.append(int((t_now - t_base) * (10**9)))
    if i > 0:
        io.close()
    else:
        tmp_io = io

for i in range(32):
    candidates = []
    candidates = brute_force_restore_lcg(candidates)
    candidates.sort()
    nano_candiates.append(candidates)
    
correct_seed = None
min_d = 2**32
ans_t = []

for t in nano_candiates[0]:
    diff_t = []
    for i in range(1, 32):
        j = bisect.bisect_left(nano_candiates[i], t)
        d = 2**32
        if j >= 1:
            d = min(d, t-nano_candiates[i][j-1])
        if j < 2**16:
            d = min(d, nano_candiates[i][j]-t)
        diff_t.append(d)
    if min_d > np.std(np.array(diff_t)):
        min_d = np.std(np.array(diff_t))
        correct_seed = t
        ans = diff_t

seed = (correct_seed+times[0])^seed_uniquifiers[0]
x_n = calc_lcg(seed)
x_n1= calc_lcg(x_n)
secret = x_n1 >> 16
if secret>=2**31:
    secret -= 2**32

tmp_io.sendlineafter(b"guess: ", str(secret).encode())
io = tmp_io
for i in range(1, 5):
    io.recvuntil(b"leak: ")
    leak = int(io.recvline().strip())
    td = int((time.time() - t_base) * (10**9))

    seed_i = seed_uniquifiers[i]
    secret = restore_lcg(seed_i)
    io.sendlineafter(b"guess: ", str(secret).encode())

io.interactive()
