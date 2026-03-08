# Vulnerable DHKE — Writeup

## TL;DR

This is a Diffie–Hellman challenge where the modulus `p` is randomly chosen from a list of three candidates. Only one candidate is actually possible from the public outputs, and that candidate has a **very smooth** group order `p - 1`.

That makes the discrete logarithm easy via **Pohlig–Hellman**. Once we recover one party’s exponent, we compute the shared secret, hash it exactly like the challenge does, and decrypt the AES-CFB ciphertext.

---

## Source analysis

The challenge code is:

```python
from random import randint, randbytes, choice
from Crypto.Cipher import AES
from hashlib import sha256

ps = []
g = 2
p = choice(ps)
a, b = randint(g,p-1), randint(g,p-1)

alice = pow(g,a,p)
bob = pow(g,b,p)
key = sha256(str(pow(alice,b,p)).encode()).digest()

with open('flag.txt', 'rb') as f:
    flag = f.read()

iv = randbytes(16)
cipher = AES.new(key, AES.MODE_CFB, iv)
ct = cipher.encrypt(flag)
```

The output file gives:

- the full list `ps`,
- `alice = g^a mod p`,
- `bob = g^b mod p`,
- `iv`,
- `ct`.

So the problem is simply: find the real modulus, recover a private exponent, then derive the AES key.

---

## Step 1: Identify the actual modulus

The output provides three candidate primes:

```python
ps = [p0, p1, p2]
```

and also the public values `alice` and `bob`.

A valid Diffie–Hellman public value must satisfy:

\[
0 < g^x \bmod p < p
\]

So both `alice` and `bob` must be strictly smaller than the real modulus.

Checking the three candidates immediately eliminates `ps[1]`, because the published value of `bob` is larger than `ps[1]`. That cannot happen if `bob = 2^b mod p` under that modulus.

The usable modulus is:

```text
p = ps[2]
```

---

## Step 2: Why this modulus is weak

For the chosen modulus,

\[
|\mathbb{F}_p^*| = p - 1
\]

and `p - 1` factors completely into many small 32-bit primes:

```text
p - 1 = 2 · 2303131849 · 2387901083 · 2523341879 · 2524054229 · ... · 4140791209
```

In total, `p - 1` is a product of many distinct small primes. That is exactly the case where **Pohlig–Hellman** is efficient.

Instead of solving one huge discrete logarithm modulo a 1044-bit group order, we solve many tiny discrete logs modulo 32-bit prime factors, then combine the results with CRT.

That is why the challenge description jokes that the attack is “as easy as 1 + 1”.

---

## Step 3: Recover Alice’s exponent with Pohlig–Hellman

We know

\[
alice = 2^a \bmod p
\]

Let `n = ord_p(2)` be the order of the generator actually used. Since `2` may not generate all of `\mathbb{F}_p^*`, it is cleaner to compute the order of `2` first by removing factors `q` from `p - 1` whenever

\[
2^{(p-1)/q} \equiv 1 \pmod p
\]

For this instance, the order of `2` is still huge, but it also factors completely into the same kind of small primes.

For each prime factor `q` of `ord_p(2)`, reduce the discrete log into the subgroup of order `q`:

\[
g_q = 2^{n/q} \bmod p,
\qquad
h_q = alice^{n/q} \bmod p
\]

Then solve

\[
g_q^{x_q} = h_q \pmod p
\]

which gives `a mod q`.

Since each `q` is only about 32 bits, this can be done quickly with baby-step giant-step.
Finally, combine all congruences using CRT to recover `a mod ord_p(2)`.

---

## Step 4: Recompute the shared secret

Once we have `a`, the shared secret is

\[
K = bob^a \bmod p
\]

The challenge derives the AES key as

```python
key = sha256(str(K).encode()).digest()
```

So it is important to hash the **decimal string** of the integer, not the raw bytes.

---

## Step 5: Decrypt correctly

The encryption line is:

```python
cipher = AES.new(key, AES.MODE_CFB, iv)
```

In PyCryptodome, if `segment_size` is not specified, **CFB8** is used by default.
That detail matters: if you try full-block CFB, decryption will fail.

Using AES-CFB8 with the recovered key yields the flag.

---

## Recovered flag

```text
PUCTF26{M4st3ring_7he_P0hlig_Hel1man_4lgorithm_sh0uld_be_repeated_3_t1mes_a6ae23853267b9964675e266b280e347}
```

---

## Solver (Python)

```python
import ast
import math
import hashlib
from collections import Counter
from subprocess import check_output
from Crypto.Cipher import AES


def bsgs(g, h, p, order):
    """Solve g^x = h (mod p) with 0 <= x < order."""
    m = int(math.isqrt(order)) + 1

    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = (e * g) % p

    factor = pow(pow(g, -1, p), m, p)
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            x = i * m + table[gamma]
            if x < order:
                return x
        gamma = (gamma * factor) % p

    raise ValueError("log not found")


def crt(congruences):
    x = 0
    M = 1
    for _, m in congruences:
        M *= m

    for a, m in congruences:
        Mi = M // m
        inv = pow(Mi, -1, m)
        x = (x + a * Mi * inv) % M

    return x, M


def factor_with_coreutils(n):
    out = check_output(["factor", str(n)], text=True)
    parts = out.split(":", 1)[1].strip().split()
    return Counter(map(int, parts))


def order_of(g, p, factors):
    n = p - 1
    for q, e in factors.items():
        for _ in range(e):
            while n % q == 0 and pow(g, n // q, p) == 1:
                n //= q
    return n


def main():
    vals = {}
    with open("output.txt") as f:
        for line in f:
            k, v = line.strip().split("=", 1)
            vals[k] = ast.literal_eval(v)

    ps = vals["ps"]
    alice = vals["alice"]
    bob = vals["bob"]
    iv = bytes.fromhex(vals["iv"])
    ct = bytes.fromhex(vals["ct"])

    # ps[1] is impossible because bob >= ps[1].
    p = ps[2]
    g = 2

    factors = factor_with_coreutils(p - 1)
    ord_g = order_of(g, p, factors)

    ord_factors = {}
    tmp = ord_g
    for q, e in factors.items():
        cnt = 0
        while tmp % q == 0:
            cnt += 1
            tmp //= q
        if cnt:
            ord_factors[q] = cnt

    assert tmp == 1

    congruences = []
    for q, e in sorted(ord_factors.items()):
        assert e == 1  # true for this challenge instance
        n_i = ord_g // q
        g_i = pow(g, n_i, p)
        h_i = pow(alice, n_i, p)
        x_i = bsgs(g_i, h_i, p, q)
        congruences.append((x_i, q))

    a, mod = crt(congruences)
    assert mod == ord_g
    assert pow(g, a, p) == alice

    shared = pow(bob, a, p)
    key = hashlib.sha256(str(shared).encode()).digest()

    # PyCryptodome default for MODE_CFB is CFB8 when segment_size is omitted.
    cipher = AES.new(key, AES.MODE_CFB, iv)
    flag = cipher.decrypt(ct)
    print(flag.decode())


if __name__ == "__main__":
    main()
```

---

## Why the challenge is vulnerable

Diffie–Hellman is only hard when the discrete log problem is hard in the chosen group.
Here, the group order is deliberately smooth, so the problem collapses under Pohlig–Hellman.

In short, the challenge fails because:

1. the attacker is given the candidate moduli,
2. the real modulus can be identified from the public values,
3. `p - 1` factors completely into small primes,
4. the discrete log can be split into many tiny subproblems,
5. the shared secret is used directly to derive the AES key.

That makes the whole key exchange recoverable from public information alone.

---

## Flag

```text
PUCTF26{M4st3ring_7he_P0hlig_Hel1man_4lgorithm_sh0uld_be_repeated_3_t1mes_a6ae23853267b9964675e266b280e347}
```
