# Noisy Lucky Number — Writeup

## Summary

The challenge gives us 50 ECDSA signatures over `secp256k1`, a compressed public key, and an encrypted flag.
The bug is in the custom nonce generator:

- in the **stable** case, the nonce is built as `30 random bytes || HW_ID`, so every good nonce shares the same **lower 16 bits**;
- in the **faulty** case, the fallback path returns a completely random 32-byte nonce.

So this is a **partial nonce leakage** problem with **noise**.
The intended solution is to recover the ECDSA private key with a lattice/HNP attack and then decrypt the flag using the post-processing step from the source.

---

## Challenge code review

Relevant part of the generator:

```python
class EntropyMixer:
    def __init__(self, hw_id):
        self.hw_id = hw_id & 0xFFFF
        self.mixer_stable = (os.urandom(1)[0] > 35)

    def generate_nonce(self):
        raw_entropy = os.urandom(30)

        if self.mixer_stable:
            mixed_buffer = struct.pack(">30sH", raw_entropy, self.hw_id)
            return int.from_bytes(mixed_buffer, "big")
        else:
            return int.from_bytes(os.urandom(32), "big")
```

Important observations:

1. `struct.pack(">30sH", raw_entropy, self.hw_id)` is **big-endian**.
2. Therefore, in the stable path, the nonce has the form

   ```text
   k = 2^16 * t + c
   ```

   where:

   - `c = HW_ID` is a fixed 16-bit constant,
   - `t` is a random 240-bit integer.

3. A fresh `EntropyMixer` is created for every signature, so the stable/faulty outcome is independent each time.
4. `os.urandom(1)[0] > 35` is true with probability `220/256 ≈ 85.94%`, so among 50 signatures we expect about **43 good** and **7 bad** signatures.

The flag is encrypted as:

```python
encrypted_flag = xor_stream(
    PLAINTEXT_FLAG,
    sha256(int(D_HEX, 16).to_bytes(32, "big"))
).hex()
```

So once the private key `d` is recovered, decryption is immediate.

---

## ECDSA relation

For each signature `(r_i, s_i)` on hash `h_i`, ECDSA gives:

```text
s_i = k_i^{-1}(h_i + d r_i) mod n
```

which can be rewritten as:

```text
k_i = s_i^{-1}(h_i + d r_i) mod n
```

For stable signatures we know that:

```text
k_i = 2^16 t_i + c
```

with the **same** `c` for every good signature.

---

## Removing the unknown lucky number

A very nice trick is that we do **not** need to brute-force `HW_ID`.

Take two stable signatures `i` and `j`:

```text
k_i - k_j = 2^16 (t_i - t_j)
```

Using the ECDSA formula,

```text
s_i^{-1}(h_i + d r_i) - s_j^{-1}(h_j + d r_j) ≡ 2^16 (t_i - t_j) mod n
```

Now choose one signature in a subset as the reference, say index `0`, and define

```text
A_i = s_i^{-1} h_i - s_0^{-1} h_0 mod n
B_i = s_i^{-1} r_i - s_0^{-1} r_0 mod n
```

Then for every other **stable** signature in that subset,

```text
A_i + B_i d ≡ 2^16 u_i mod n
```

for some small-ish integer `u_i = t_i - t_0`.
Multiplying by `2^{-16} mod n` gives a standard **Hidden Number Problem** instance:

```text
x_i = 2^{-16}(A_i + B_i d) mod n
```

where the centered representatives of `x_i` are bounded by about `n / 2^16`.
That is exactly the type of relation attacked by the classical ECDSA partial-nonce lattice attack.

So the challenge becomes:

- find a subset consisting only of stable signatures,
- build the HNP lattice from those equations,
- recover `d`.

---

## Why sub-sampling is necessary

The data is noisy: the faulty signatures do **not** satisfy the fixed-low-16-bit model.
If we feed all 50 signatures directly into the lattice, the noise breaks the assumptions.

Because about 86% of the signatures are good, a random subset has a reasonable chance of containing only stable signatures.
For example, with subset size 12 the probability that all 12 are good is:

```text
C(43, 12) / C(50, 12) ≈ 12.6%
```

So repeated random sub-sampling works well in practice.

The recovery loop is:

1. randomly choose a small subset of signatures;
2. build the reduced HNP instance using pairwise differences against one anchor signature;
3. run lattice reduction (LLL/BKZ + Babai / nearest plane) to get a candidate private key;
4. verify the candidate against **all 50 signatures**.

A wrong candidate might accidentally fit the sampled subset, but it will not explain the whole dataset.
The real private key will make the reconstructed nonces have a **single repeated 16-bit suffix** on almost all signatures.

---

## Candidate validation

Given a candidate private key `d`, reconstruct each nonce as:

```text
k_i = s_i^{-1}(h_i + d r_i) mod n
```

Then inspect the low 16 bits of every `k_i`.

For the correct private key:

- the good signatures all share the same `k_i mod 2^16`,
- the bad signatures look random.

This gives an extremely strong validation signal:

- wrong `d`: no dominant 16-bit suffix,
- correct `d`: one suffix appears on almost the entire dataset.

Once the key was recovered, I used it to regenerate the XOR stream key:

```python
key32 = sha256(d.to_bytes(32, "big"))
flag = xor_stream(bytes.fromhex(encrypted_flag), key32)
```

---

## Solve outline

A practical solver looks like this:

```python
import json, hashlib, random

with open("task_data.json", "r") as f:
    task = json.load(f)

n = int(task["n"], 16)
entries = []
for row in task["data"]:
    r = int(row["r"], 16)
    s = int(row["s"], 16)
    h = int(row["hash"], 16)
    sinv = pow(s, -1, n)
    entries.append((r, s, h, sinv))

# Repeat:
#   1) choose a random subset
#   2) anchor on one signature
#   3) build A_i, B_i from pairwise differences
#   4) turn that into a standard HNP lattice with 16 leaked bits
#   5) run lattice reduction and extract a candidate d
#   6) validate d on all 50 signatures by checking the low 16 bits of k_i
```

The exact lattice basis depends on the HNP implementation you use, but the cryptanalytic reduction above is the important step: the unknown `HW_ID` is removed by differencing good signatures.

---

## Decryption step

The last stage is trivial because the source already tells us the encryption scheme:

```python
def xor_stream(data: bytes, key32: bytes) -> bytes:
    ks = (key32 * ((len(data) // 32) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, ks))
```

So after recovering `d`:

1. compute `sha256(d_bytes)`;
2. repeat that 32-byte digest as a keystream;
3. XOR it with `encrypted_flag`.

---

## Final notes

This challenge is a nice combination of:

- **ECDSA partial nonce leakage**,
- a **small fixed suffix** instead of full nonce reuse,
- and **noise handling** via sub-sampling.

The main pitfall is trying to force all 50 signatures into one clean attack instance. The generator is faulty by design, so the robust solution is to sample subsets, recover a candidate, and validate it globally.

---

## Flag

The recovered plaintext is the challenge flag.
