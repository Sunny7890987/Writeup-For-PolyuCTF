# Noisy — Writeup

## TL;DR

The challenge leaks several samples of the form

\[
x_i = p q_i + r_i
\]

where:

- `p` is a hidden ~512-bit integer,
- each `q_i` is large,
- each noise term `r_i` is only ~64 bits.

This is a classic **Approximate Common Divisor (AGCD)** setup. Because the noise is much smaller than `p`, a small lattice recovers one of the quotients, which immediately gives `p`. Once `p` is known, the AES key is just `SHA256(p_bytes)[:16]`, so decryption is trivial.

---

## Given files

The output file tells us the intended structure directly:

```text
M = 8
P_BITS ~= 512
R_BITS ~= 64
x0 = ...
x1 = ...
...
x7 = ...

iv = ...
ct = ...
```

The provided Sage helper also states the attack goal:

```python
print("[+] Recover p from xi = p*qi + ri (small ri), then decrypt ct.")
```

So the problem is not to guess the cryptosystem; it is to recover `p` from noisy multiples.

---

## Observation

Each sample satisfies

\[
x_i = p q_i + r_i, \quad |r_i| < 2^{64}
\]

with the same hidden `p`.

If the values were exact multiples, `gcd(x_0, x_1, ..., x_7)` would reveal `p`. But the small errors `r_i` destroy the exact gcd. Still, the errors are tiny compared with the 512-bit scale of `p`, so we can set up a lattice whose shortest vector encodes the hidden quotient information.

---

## Lattice idea

Take `x0` as the reference sample and let `B = 2^64`.
Construct the lattice basis

\[
L = \begin{pmatrix}
B & x_1 & x_2 & \cdots & x_7 \\
0 & -x_0 & 0 & \cdots & 0 \\
0 & 0 & -x_0 & \cdots & 0 \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
0 & 0 & 0 & \cdots & -x_0
\end{pmatrix}
\]

Now look at the integer combination using the quotients `q0, q1, ..., q7`:

\[
q_0 \cdot (B, x_1, x_2, \dots, x_7)
+ \sum_{i=1}^{7} q_i \cdot (0,0,\dots,-x_0,\dots,0)
\]

This gives the lattice vector

\[
(q_0 B,
q_0 x_1 - q_1 x_0,
q_0 x_2 - q_2 x_0,
\dots,
q_0 x_7 - q_7 x_0)
\]

Substitute `x_i = p q_i + r_i`:

\[
q_0 x_i - q_i x_0 = q_0(p q_i + r_i) - q_i(p q_0 + r_0) = q_0 r_i - q_i r_0
\]

The big `p q_i q_0` terms cancel out, so all non-first coordinates become small:

\[
q_0 r_i - q_i r_0
\]

Because the noise is only 64 bits, this vector is unusually short and LLL will recover it (or a close equivalent).

Once we get that vector, its first coordinate is `q0 * 2^64`, so we recover

\[
q_0 = \frac{|v_0|}{2^{64}}
\]

and then simply compute

\[
p \approx \frac{x_0}{q_0}
\]

using nearest-integer rounding.

---

## Recovering `p`

Running LLL on the basis above gives the hidden quotient information and recovers:

```text
p = 7458392365089045594309991234517420059044818537492607779936561176872243127966883595290812728363861264795751531842136361222998691480613527247629050300165103
```

A quick sanity check confirms the result. For each sample, compute the centered remainder

\[
\tilde r_i = \min(x_i \bmod p,\; p - (x_i \bmod p))
\]

and check its size:

```text
x0 -> 59 bits
x1 -> 63 bits
x2 -> 63 bits
x3 -> 62 bits
x4 -> 63 bits
x5 -> 63 bits
x6 -> 63 bits
x7 -> 62 bits
```

That is exactly what we expect from `R_BITS ~= 64`, so the recovered `p` is correct.

---

## Decrypting the flag

The helper script shows the key derivation:

```python
key = SHA256.new(int_to_bytes(p)).digest()[:16]
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
return unpad(pt, 16)
```

So after recovering `p`, we derive the AES-128 key and decrypt the ciphertext.

Recovered plaintext:

```text
PUCTF26{TH3_Agcd_1s_n0isY_arrrr_c7229ab626fd8c7234e906fadb4148ce}
```

---

## Solver (Sage)

```python
#!/usr/bin/env sage
from sage.all import *
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def int_to_bytes(n):
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, "big")


def parse_output(path="output.txt"):
    xs = []
    iv = None
    ct = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("x") and " = " in line:
                xs.append(Integer(line.split(" = ", 1)[1]))
            elif line.startswith("iv = "):
                iv = bytes.fromhex(line.split(" = ", 1)[1])
            elif line.startswith("ct = "):
                ct = bytes.fromhex(line.split(" = ", 1)[1])
    return xs, iv, ct


def recover_p(xs, rbits=64):
    x0 = xs[0]
    B = 1 << rbits
    n = len(xs)

    rows = []
    rows.append([B] + xs[1:])
    for i in range(1, n):
        row = [0] * n
        row[i] = -x0
        rows.append(row)

    M = Matrix(ZZ, rows)
    red = M.LLL()

    for v in red.rows():
        first = abs(int(v[0]))
        if first % B != 0:
            continue
        q0 = first // B
        if q0 == 0:
            continue

        p = Integer(round(xs[0] / q0))
        centered = [min(int(x % p), int(p - (x % p))) for x in xs]
        if max(centered).bit_length() <= rbits:
            return p

    raise ValueError("failed to recover p")


def main():
    xs, iv, ct = parse_output("output.txt")
    p = recover_p(xs, 64)
    print(f"[+] p = {p}")

    key = sha256(int_to_bytes(p)).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), 16)
    print(pt.decode())


if __name__ == "__main__":
    main()
```

---

## Why the challenge is vulnerable

The entire security rests on the noise hiding the common divisor. But the noise is only 64 bits, while the hidden divisor is ~512 bits and we get 8 samples. That gap is large enough for a standard AGCD lattice attack.

So the challenge is broken because:

1. all samples share the same hidden divisor `p`,
2. the error terms are very small,
3. enough samples are provided for LLL to isolate the short relation,
4. `p` is used directly as the AES key source.

In other words, the “noise” is nowhere near large enough to protect the hidden common divisor.

---

## Flag

```text
PUCTF26{TH3_Agcd_1s_n0isY_arrrr_c7229ab626fd8c7234e906fadb4148ce}
```
