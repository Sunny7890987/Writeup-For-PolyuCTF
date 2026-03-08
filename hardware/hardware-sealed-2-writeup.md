# PolyU CTF 2026 — Sealed-2 Writeup

## Summary

`Sealed-2` depends on solving `Sealed-1` first.
In our case, `Sealed-1` gave us the BitLocker recovery material needed to unlock the Windows volume.
Once the volume was mounted, the second challenge turned into a combination of:

1. **Windows disk forensics**
2. **SPI/TPM traffic analysis**
3. **.NET reverse engineering**
4. **AES decryption**

This writeup shows the full path from the raw capture to the second flag.

---

## Files and observations

From the challenge material we had:

- a large disk image (`Sealed.img` after extraction)
- a huge `Trace.csv`
- photos showing a logic analyzer connected to `HS_SPI`

The board photos strongly suggested that the bus capture was important, so instead of attacking the encrypted disk directly, the intended route was to analyze the SPI trace first.

---

## 1. Identify the encrypted volume

After extracting the archive, I identified the disk layout:

```bash
file Sealed.img
fdisk -l Sealed.img
sudo losetup -Pf --show Sealed.img
lsblk /dev/loop0
sudo xxd -g 1 -l 16 /dev/loop0p3
sudo blkid /dev/loop0p3
```

The third partition started with `-FVE-FS-`, which confirmed it was **BitLocker**.

Example output:

```text
00000000: eb 58 90 2d 46 56 45 2d 46 53 2d 00 02 08 00 00
/dev/loop0p3: ... TYPE="BitLocker" ...
```

So the disk was a Windows BitLocker volume.

---

## 2. Characterize the raw logic trace

`Trace.csv` was too large to open comfortably, so I first profiled the channels.

A simple scanner over the CSV showed four digital channels and their transition counts:

- **CH1** had the most transitions → likely **SPI clock**
- **CH3** stayed high most of the time and toggled only around transactions → likely **chip select**
- **CH0** and **CH2** were the two data lines

This already matched the hardware photos.

---

## 3. Decode SPI transactions

I then brute-forced the usual SPI interpretations:

- rising edge vs falling edge
- CH0/CH2 as MOSI/MISO in both directions

The correct combination was:

- **CLK = CH1**
- **CS# = CH3**
- **sample on rising edge**
- **MOSI = CH0**
- **MISO = CH2**

With that mapping, the decoded traffic looked like this:

```text
MOSI: 80 00 00 01 ff
MISO: 80 d4 00 30 00

MOSI: 80 00 00 01 d1 15
MISO: 81 d4 0f 00 00 00
```

This is **not** ordinary SPI flash traffic.
Instead, it matches **TPM over SPI / TIS-style register access**:

- reads and writes to `0xD400xx`
- register accesses such as `DID_VID`, `STS`, and `FIFO`

So the trace was capturing TPM communication during boot.

---

## 4. Reconstruct TPM command/response pairs

Once the bus was recognized as TPM traffic, the next step was to rebuild full FIFO-based TPM transactions.

The core idea was:

- track writes to `TPM_STS`
- collect data written to `TPM_DATA_FIFO`
- detect `GO`
- collect response bytes read back from `TPM_DATA_FIFO`
- parse the TPM headers (`tag`, `size`, `command code` / `return code`)

That reconstruction produced multiple TPM command/response pairs.
Searching the index for `TPM2_Unseal` gave two successful calls:

```text
0053 ... cc=0x0000015e TPM2_Unseal ... rc=0x00000000
0243 ... cc=0x0000015e TPM2_Unseal ... rc=0x00000000
```

So there were **two successful TPM unseal operations** in the trace.

---

## 5. Parse the two `TPM2_Unseal` responses

### 5.1 Response `0243`

Parsing `0243_rsp.bin` yielded an ASCII secret:

```text
H0pSecret=PUCTF26{FakeFlag?_Or_SthUseful?}
```

At first glance this looked like a decoy, and it is **not** the final challenge flag.
However, it is still important.

### 5.2 Response `0053`

Parsing `0053_rsp.bin` yielded a 44-byte binary blob:

```text
2c00000001000000032000003667061e911bb81227374972089df1364aa47eb3ec3a8dc72bfcb9d063646d85
```

This blob was the BitLocker-related key material used earlier to mount the encrypted volume.
For `Sealed-2`, the key point is that the second unseal result (`0243`) is later reused by the executable.

---

## 6. Mount the BitLocker volume and inspect the user profile

After unlocking the BitLocker partition (this is why `Sealed-1` is required), I mounted the decrypted NTFS volume and searched the user desktop.

The important file was:

```text
mnt/Users/PUCTF26/Desktop/PUCTF26_GetFlag.exe
```

That executable was clearly the payload for `Sealed-2`.

---

## 7. Reverse the .NET executable

The EXE was a .NET assembly, so `monodis` was enough for a quick static analysis:

```bash
monodis "mnt/Users/PUCTF26/Desktop/PUCTF26_GetFlag.exe" > getflag.il
```

Important strings from the binary included:

```text
Hi there, want to get your second flag?
H0pSecret=
[DEBUG] Obtained H0p's master secret from TPM:
PUCTF26{
Congrats! Here is your flag:
No flag yet, try harder :)
```

The `Main()` method made the logic very clear.

### Main logic

1. Load a **128-byte ciphertext** from a static array.
2. Load a **base64 blob**.
3. Call `TpmSrkOps::EncryptDecrypt(false, blob, "1337")`.
4. Convert the returned bytes to a UTF-8 string.
5. Verify that the result is exactly 42 characters long and starts with `H0pSecret=`.
6. Strip the prefix and keep only:

```text
PUCTF26{FakeFlag?_Or_SthUseful?}
```

7. Use that 32-byte ASCII string as the **AES-256 key**.
8. Load a fixed 16-byte IV from another static array.
9. Decrypt the embedded ciphertext with **AES-CBC + PKCS#7 padding**.
10. If the plaintext starts with `PUCTF26{`, print it as the real flag.

So the so-called “fake flag” was actually the **AES key** for the real flag.

---

## 8. Extract the AES inputs from IL

The IL contained two static arrays:

- a 128-byte ciphertext
- a 16-byte IV

I located them using their private implementation detail field names:

```text
C6BE0DA1BCFBB11AF0418980294D872BD6C7850BC3884CAB59BD184A9DCA327E
837C5FA5DEF718B5EA15FDE8A0AB6877C79D34BD32C35354AACE32AB2F5D4BE0
```

In `Main()`, the AES parameters were used like this:

- `KeySize = 256`
- `Key = UTF8("PUCTF26{FakeFlag?_Or_SthUseful?}")`
- `IV = <16-byte static array>`
- `Mode = CBC`
- `Padding = PKCS7`

So we can decrypt the final flag offline with a short Python script.

---

## 9. Decrypt the final flag

A minimal solver looks like this:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"PUCTF26{FakeFlag?_Or_SthUseful?}"  # 32 bytes
iv = bytes.fromhex("<extract the 16-byte IV from IL>")
ct = bytes.fromhex("<extract the 128-byte ciphertext from IL>")

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)
print(pt.decode())
```

Once the IV and ciphertext are extracted from the IL `.data` section, this decrypts the real plaintext flag.

---

## Why this challenge is nice

`Sealed-2` chains several layers together:

- hardware observation from the board photos
- low-level SPI decoding
- TPM transaction reconstruction
- identifying `TPM2_Unseal`
- recovering a secret that only looks like a fake flag
- noticing that the "fake flag" is actually an AES key
- reversing a .NET loader to recover the real flag

The key trick is that the obvious string:

```text
H0pSecret=PUCTF26{FakeFlag?_Or_SthUseful?}
```

is **not** the answer, but also **not** useless.
It is the bridge between TPM recovery and the final AES decryption.

---

## Final notes

- `Sealed-1` gives the recovery material needed to open the disk.
- `Sealed-2` then uses the mounted Windows environment and the TPM trace.
- The decisive realization is that the TPM-unsealed ASCII string is the AES key, not the final flag.

If you want, I can also turn this into a cleaner **blog-style writeup** with code blocks for the exact CSV parser, TPM pair reconstruction script, and AES solver.
