import random
from flag import flag
import signal

n = 16384
periods = [2**i for i in range(1, 12)]

def generate_periodic_error(Zp, R, periods=[2, 4, 8, 16, 32]):
    e = [Zp(0)] * n
    amplitudes = {}
    for period in periods:
        a = Zp.random_element()
        amplitudes[period] = a
        for i in range(n):
            e[i] += a if (i % period) < (period // 2) else -a

    a_const = Zp.random_element()
    amplitudes['const'] = a_const
    for i in range(n):
        e[i] += a_const
    return R(e), amplitudes

def generate_partial_error(Zp, R, amps):
    e = [Zp(0)] * n
    for period, a in amps.items():
        for i in range(n):
            e[i] += a if (i % period) < (period // 2) else -a
    return R(e)


def main():
    signal.alarm(120)
    p = int(input("Enter a 512bit prime p >>>"))
    assert p.bit_length() >= 512
    assert is_prime(p)

    Zp = GF(p)
    R = PolynomialRing(Zp, 'x')
    x = R.gen()

    e_full, amps_full = generate_periodic_error(Zp, R, periods)
    print("=== Exam 1: Predict the amplitudes of e(x). ===")
    print("You are given the coefficients of e(x):")
    print(list(e_full))

    for period in periods + ['const']:
        user_input = input(f"period({period})>>> ").strip()
        user_amp = Zp(user_input)
        assert user_amp == amps_full[period], f"Wrong amplitude for period {period}."
    print("[+] Exam 1 passed.")

    print("Exam 2: Cancel specific frequency components.")
    for round in range(10):
        e_full, amps_full = generate_periodic_error(Zp, R, periods)
        num_periods = random.randint(1, 10)
        selected_periods = random.sample(periods, num_periods)
        amps = {i: amps_full[i] for i in selected_periods}
        e_partial = generate_partial_error(Zp, R, amps)
        print(f"Round {round+1}: Provide a polynomial k(x) such that e(x)*k(x) = e_partial(x)")
        print(f"Target periods: {selected_periods}")
        k_coeffs = list(map(Zp, input("Enter space-separated coefficients of k(x) >>>").split()))
        k_poly = R(k_coeffs)
        result = (e_full * k_poly - e_partial) % (x^n - 1)
        assert result.is_zero(), f"Wrong polynomial for round {round+1}."
        print("[+] Correct.")

    print(f"Congratulations! Here is your flag: {flag}")

main()