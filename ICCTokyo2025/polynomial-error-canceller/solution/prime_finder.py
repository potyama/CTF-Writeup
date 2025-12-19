import gmpy2
from gmpy2 import is_prime, powmod
from random import randint

def is_proth_prime(a, n=2000):
    """
    a * 2^n + 1 が Proth 素数かどうかチェックする
    """
    N = a * (1 << n) + 1
    if a >= (1 << n):
        return False

    # Proth's theorem による確率的素数判定
    for _ in range(5):  # 試行回数を増やせば精度向上
        base = randint(2, min(N - 2, 2**20))
        if powmod(base, (N - 1) // 2, N) == N - 1:
            return True
    return False

def find_proth_prime(start_a=1, n=2000, max_trials=1000000):
    for a in range(start_a, start_a + max_trials):
        if a % 2 == 1:  # 偶数 a はスキップ（奇数の方が素数候補になりやすい）
            if is_proth_prime(a, n):
                return a, a * (1 << n) + 1
    return None, None

a, p = find_proth_prime(n=4096)
if a:
    print(f"Found prime: p = {a} * 2^2048 + 1 = {p}")
else:
    print("Not found in given range.")
