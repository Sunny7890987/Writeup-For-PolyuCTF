# Time is Important — Writeup

## Challenge Overview

This challenge gives us a remote service that prints an encrypted flag as hex. The provided Python source is intentionally broken up with `#` characters, but it still leaks enough structure to recover the encryption logic.

Relevant fragments from the challenge source:

```python
FLAG = b"PUCTF26{https://tinyurl.com/4az8r9py}"
import hashlib
from datetime import datetime, timezone, timedelta

def test():
    #time_str = strftime("%Y%m%d%H%M%S")
    material =# time_str + "salt"
    return ha#shlib.sha256(material.encode()).digest()

def rox(data, key):
    return bytes(data[i] ^ key[i % len(k#ey)] for i in range(len(data)))
```

Even though identifiers are partially commented out, the intent is still obvious:

- build a timestamp string with format `YYYYMMDDHHMMSS`
- append the constant string `"salt"`
- compute `SHA-256`
- XOR the flag with the resulting 32-byte digest

So the real logic is effectively:

```python
def test():
    time_str = strftime("%Y%m%d%H%M%S")
    material = time_str + "salt"
    return hashlib.sha256(material.encode()).digest()


def rox(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
```

---

## Main Idea

The challenge title and hints are the giveaway:

- **Time is important**
- **The key is ticking**
- **By the way, I like Japan**

The key depends only on the current time, down to the second. That means the key space is tiny if we know approximately when the server generated the ciphertext.

The extra hint about Japan strongly suggests the intended timezone is **JST (UTC+9)**.

Because the flag format starts with `PUCTF26{`, we can brute-force nearby timestamps and check which decrypted plaintext matches a valid flag.

---

## Encryption Model

Let:

```text
key = SHA256((time_str + "salt").encode())
```

where:

```text
time_str = YYYYMMDDHHMMSS
```

Then the ciphertext is:

```text
cipher[i] = flag[i] XOR key[i mod 32]
```

Since XOR is symmetric, decryption is the same operation:

```text
flag[i] = cipher[i] XOR key[i mod 32]
```

---

## Ciphertext

The remote service returned:

```text
80d7f6fb6793c4d48a66adbd2490f4e5fc3172f3b71052111b2bd110f2496d57baeae2c54dc386fe89558ce02faba880c32f5e
```

---

## Solving Strategy

1. Take the ciphertext hex and convert it to bytes.
2. Generate candidate timestamps around the current server time.
3. Use **JST** as the timezone.
4. For each candidate second:
   - compute `sha256(time_str + "salt")`
   - XOR it with the ciphertext
   - test whether the plaintext starts with `PUCTF26{`
5. The correct timestamp will produce a readable valid flag.

This is fast because the search space is tiny. Even checking a few minutes around the expected time is only a few hundred candidates.

---

## Solver Script

```python
import hashlib
from datetime import datetime, timedelta, timezone

cipher_hex = "80d7f6fb6793c4d48a66adbd2490f4e5fc3172f3b71052111b2bd110f2496d57baeae2c54dc386fe89558ce02faba880c32f5e"
cipher = bytes.fromhex(cipher_hex)


def rox(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


jst = timezone(timedelta(hours=9))

# Replace this with the approximate time you received the ciphertext.
# Then brute-force a window around it.
base = datetime(2026, 3, 7, 14, 53, 13, tzinfo=jst)

for delta in range(-600, 601):
    t = base + timedelta(seconds=delta)
    time_str = t.strftime("%Y%m%d%H%M%S")
    key = hashlib.sha256((time_str + "salt").encode()).digest()
    pt = rox(cipher, key)

    if pt.startswith(b"PUCTF26{"):
        print(time_str, pt.decode(errors="ignore"))
```

---

## Recovered Timestamp

The matching timestamp was:

```text
20260307145313  (JST)
```

---

## Flag

```text
PUCTF26{Tim3lsk3Y_QRlNCWqy2AqFDzjhWjlbtQWZLngH7VfA}
```

---

## Notes

### 1. Why brute force works

The timestamp is second-based, so there is only one candidate key per second. If we know the ciphertext was generated within a short time window, we only need to try a few hundred or a few thousand candidates.

### 2. Why the timezone matters

If the key is derived from local time rather than UTC, using the wrong timezone will never produce the correct key. The hint about Japan points to **UTC+9**.

### 3. Flag format mismatch

The challenge statement claimed a format like:

```text
PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}
```

but the recovered flag suffix is not a 32-character hex string. So the published format appears to be inaccurate for this challenge.

---

## Takeaway

This was a straightforward cryptanalysis challenge built around a weak key derivation method:

- the secret key was generated from predictable time data
- the encryption was only XOR with a deterministic SHA-256 digest
- the hints leaked the intended timezone
- the known flag prefix made validation trivial

Once the timestamp dependency is recognized, the challenge reduces to a small brute-force search.
