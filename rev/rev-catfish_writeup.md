# Catfish — Writeup

## Challenge Type
Reverse Engineering

## Description
> "Did you know? Cats do not catch fish, but they can fish OvO."

## Goal
Figure out what input the binary expects and recover the hidden flag.

---

## Initial Recon
The provided file is a Linux ELF executable. Running `file` on it shows that it is a 64-bit binary.

```bash
file catfish
```

The first thing I noticed was that the program was packed with **UPX**, which is common in beginner-to-intermediate reversing challenges.

A quick strings pass and basic execution showed that the binary:
- prints some ASCII art,
- prompts the user with `What will you do?`,
- and then validates the input.

Because it was UPX-packed, the best first step was to unpack it before doing deeper analysis.

---

## Unpacking
The binary was compressed with UPX, so I unpacked it first:

```bash
upx -d catfish -o catfish_unpacked
```

After unpacking, the control flow and data sections became much easier to inspect in a disassembler/decompiler.

---

## Program Behavior
When executed, the challenge displays a cat-and-fish themed banner and waits for user input.

At first glance, it looks like a normal string-checking challenge, but there is one extra trick: **timing matters**.

The main logic does roughly this:
1. Record the start time.
2. Read user input.
3. Compare the input against the expected command.
4. Check how much time elapsed before the input was submitted.
5. Only if both checks pass, decode and print the flag.

---

## Finding the Required Input
Inside the validation function, the binary compares the user's input against a fixed string:

```c
"catch"
```

So the required input is:

```text
catch
```

This also matches the theme and the hint text. The joke is that the cat is not "grabbing" the fish immediately — it is "fishing," which implies waiting patiently.

---

## The Time Check
The interesting part is the second condition.

The program does not accept the correct input immediately. It checks the elapsed time since the prompt was shown, and only succeeds if the user enters the string within a narrow window.

The successful range is:

- **at least 25 seconds**, and
- **at most 28 seconds**

In other words, the binary expects:

```text
input == "catch"
AND
25 <= elapsed_seconds <= 28
```

This is also hinted at by the message:

> `Patience is key in fishing.`

So the intended solve is to wait a bit before typing the correct command.

---

## Flag Recovery
Once the two conditions are satisfied, the binary follows its success path and decodes the flag from a byte array stored in `.data`.

The decoding routine is simple:
- iterate over the encoded bytes,
- XOR each byte with `0x42`,
- print the resulting string.

Conceptually, it looks like this:

```c
for (int i = 0; i < len; i++) {
    decoded[i] = encoded[i] ^ 0x42;
}
decoded[len] = '\0';
puts(decoded);
```

Applying that transformation yields the final flag:

```text
PUCTF26{Y0uc47ch7h3f15hw33lld0n3_bd88034c5cfaa0f7445d89ff288e8742}
```

---

## Intended Solve
To solve the challenge manually:

1. Run the program.
2. Wait about **25 to 28 seconds**.
3. Enter:

```text
catch
```

The program then reveals the flag.

---

## Minimal Solver Strategy
A simple scripted approach would be:
- launch the program,
- sleep for about 26 seconds,
- send `catch`.

Example with Python + pwntools:

```python
from pwn import *
import time

p = process('./catfish')
time.sleep(26)
p.sendline(b'catch')
p.interactive()
```

---

## Final Flag

```text
PUCTF26{Y0uc47ch7h3f15hw33lld0n3_bd88034c5cfaa0f7445d89ff288e8742}
```

---

## Takeaways
This was a neat beginner-friendly reversing challenge with two layers:
- a normal fixed-string check,
- plus a timing-based condition to punish impatient input.

The challenge theme, the wording, and the hint all point toward the intended behavior:
- do not act immediately,
- wait patiently,
- then use the correct action: `catch`.

