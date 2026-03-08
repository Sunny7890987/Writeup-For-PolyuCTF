# Special Base — Writeup

## Challenge summary

This is a Linux ELF reverse engineering challenge. The binary asks for a flag and checks it against a transformed value. The flag format is:

```text
PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}
```

The goal is to recover the original flag from the verification routine.

---

## Initial observations

Running `file` on the binary shows that it is a stripped 64-bit PIE ELF:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

A quick `strings` pass reveals the important comparison target:

```text
SX#P#(]*mV^h>&#Mr2XJ`|X@<#0qdhd*]@X6mM?zm2]Z<&d:]2S.m|S.]MK.m&]t<M?zdVZ=
```

and the input prompt:

```text
Input your flag:
```

That already strongly suggests an encoded comparison rather than a complicated checksum.

---

## Reversing idea

After tracing the main verification logic, the binary turns out to:

1. build a custom 64-character alphabet,
2. transform the user input using that alphabet,
3. compare the result with the hardcoded encoded string.

So the challenge is effectively a **custom-alphabet Base64** problem.

During dynamic analysis, the generated alphabet can be recovered before the comparison step. The alphabet used by the program is:

```text
K-UP(X&A%afOdmN+`p7hS#2s]<r1>;we'QqM?6|V)gF{J^Y$n[*@Zl:.tz5o!0,L
```

The hardcoded target is:

```text
SX#P#(]*mV^h>&#Mr2XJ`|X@<#0qdhd*]@X6mM?zm2]Z<&d:]2S.m|S.]MK.m&]t<M?zdVZ=
```

Once we know this is just Base64 with a shuffled alphabet, the solve is straightforward:

- map the custom alphabet back to the standard Base64 alphabet,
- translate the encoded string character by character,
- decode the resulting standard Base64 string.

---

## Alphabet mapping

Standard Base64 alphabet:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

Custom alphabet recovered from the binary:

```text
K-UP(X&A%afOdmN+`p7hS#2s]<r1>;we'QqM?6|V)gF{J^Y$n[*@Zl:.tz5o!0,L
```

Replace every character in the encoded target using this mapping, and the ciphertext becomes:

```text
UFVDVEYyNntTcGVjaWFsQmFzZV9iMTMyYzFlNjk5NWY0ZGM2YWU3NmU3YjA3NGY4Zjk5Mn0=
```

Decoding that gives:

```text
PUCTF26{SpecialBase_b132c1e6995f4dc6ae76e7b074f8f992}
```

---

## Solver script

```python
import base64

custom = "K-UP(X&A%afOdmN+`p7hS#2s]<r1>;we'QqM?6|V)gF{J^Y$n[*@Zl:.tz5o!0,L"
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
enc = "SX#P#(]*mV^h>&#Mr2XJ`|X@<#0qdhd*]@X6mM?zm2]Z<&d:]2S.m|S.]MK.m&]t<M?zdVZ="

trans = str.maketrans(custom, standard)
std_b64 = enc.translate(trans)
flag = base64.b64decode(std_b64).decode()

print(std_b64)
print(flag)
```

---

## Final flag

```text
PUCTF26{SpecialBase_b132c1e6995f4dc6ae76e7b074f8f992}
```
