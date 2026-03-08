# Rustjail — Writeup / Postmortem

## Challenge summary

The service accepts a single line of Rust code, applies a blacklist, compiles it with `rustc`, runs the resulting binary, and prints either the compiler error or a success message.

At first glance this looks like a tiny Rust sandbox escape challenge. After analyzing the provided source and the remote behavior, my conclusion is:

> **The deployed instance appears unsolvable as configured.**

This writeup explains the intended-looking ideas, the exact constraints, and why they collapse against the actual deployment.

---

## Relevant source code

The jail reads one line of input and enforces three especially important rules:

1. The raw input must contain `fn main()`.
2. The total length must be at most **32 bytes**.
3. Many file, process, macro, and import strings are blacklisted.

The service then writes the source into a temporary file under `/tmp`, compiles it with:

```text
rustc /tmp/<random>/main.rs -O -o /tmp/<random>/main
```

and runs the result.

The blacklist includes, among many others:

- `std::fs`
- `std::fs::read`
- `fs::`
- `std::io`
- `include!`
- `include_str!`
- `env!`
- `option_env!`
- `std::process`
- `Command`
- `unsafe`
- `extern`

The code also tries to normalize input before checking the blacklist:

- strip single-line comments
- strip block comments
- strip whitespace
- strip `{}`

There are also regex checks that reject patterns like `use ... fs` and `use ... process`.

---

## First observation: the blacklist is weak in theory

The implementation is obviously blacklist-based rather than semantic.

For example, it removes block comments before checking banned strings, which means token splitting tricks are theoretically possible. A payload could hide part of a banned token inside a comment in the original source and let the Rust parser reconstruct it.

In other words, the filter is brittle.

However, in this challenge the **32-byte limit** is so tight that most blacklist bypass ideas are useless in practice: they make the source longer, not shorter.

---

## The shortest runtime file-read idea

A direct read would normally be something like:

```rust
fn main(){std::fs::read("flag")}
```

This is exactly **32 bytes** long.

Unfortunately it is not a valid `main` function, because the function body ends in a tail expression of type `Result<...>` rather than `()`.

To make it type-check, we need a semicolon:

```rust
fn main(){std::fs::read("flag");}
```

That is **33 bytes**, so it already exceeds the hard limit.

Even worse, both forms are rejected anyway because the blacklist blocks:

- `std::fs`
- `std::fs::read`
- `fs::`

So the obvious runtime route is dead twice over:

- by the blacklist
- by the 32-byte budget

---

## The promising idea: compile-time file inclusion via `#[path]`

Because runtime file APIs were blocked, the next natural idea was to force the compiler itself to read the flag file.

The shortest payloads are:

```rust
#[path="flag"]mod a;fn main(){}
```

and

```rust
#[path="flag"]mod a;//fn main()
```

These are only **31 bytes**, fit the length limit, and contain `fn main()` in the raw source.

If the compiler tried to parse the flag as Rust source, it would likely produce an error that reveals the flag contents.

This is a classic and elegant approach.

### Why it fails remotely

The jail writes the source into a temporary file such as:

```text
/tmp/tmpXXXXXX/main.rs
```

and then invokes `rustc` on that file.

Rust resolves `#[path = "..."]` relative to the source file location, so:

```rust
#[path="flag"]mod a;fn main(){}
```

tries to open:

```text
/tmp/tmpXXXXXX/flag
```

not the challenge flag file.

The remote service confirms this behavior with compiler errors like:

```text
error: couldn't read /tmp/tmp1uqltr3t/flag: No such file or directory (os error 2)
```

So the best compact compile-time trick is blocked by the jail's own use of a temporary directory.

---

## Could an absolute path save it?

The next attempt is an absolute path, for example:

```rust
#[path="/flag"]mod a;fn main(){}
```

This is exactly **32 bytes**, so it still fits.

If the flag lived at `/flag`, this would be excellent.

But the deployment behavior we observed did not indicate such a file, and the provided challenge setup from our local analysis consistently pointed to `/home/ctf/flag` in the PWN container, not a short absolute path usable here.

Any realistic longer path fails immediately because the payload budget is only 32 bytes.

For example:

```rust
#[path="/home/ctf/flag"]mod a;fn main(){}
```

is far too long.

So even the compile-time oracle only works if the flag path is extremely short.

---

## Why comment-based blacklist bypasses still do not save the challenge

The blacklist can theoretically be confused with tricks like comment splitting, but the hard size cap kills them.

A bypass usually needs extra characters such as:

- block comment delimiters
- helper imports
- indirection through traits or modules
- additional syntax to restore valid Rust

That overhead is fatal under 32 bytes.

So while the filter is conceptually weak, the tight input budget prevents the usual obfuscation-based escapes from becoming practical.

---

## Bottom line

After combining the source code and the actual remote behavior, the challenge appears to be broken as deployed.

The exact conflict is:

1. `fn main()` must appear in the raw input.
2. The input length is capped at **32 bytes**.
3. Direct runtime file access is blacklisted.
4. The shortest viable compile-time include payload only works with a short path.
5. Relative `#[path="flag"]` resolves inside `/tmp/<random>/`, not where the real flag is stored.
6. The realistic real flag path is too long to fit.

That combination leaves no convincing route to retrieve the flag from the deployed service.

---

## Practical conclusion

If you are writing this up for a team or for a post-CTF note, the most honest conclusion is:

- the challenge design strongly suggests a compact compile-time file-include trick
- the deployed instance defeats that trick by compiling from a temporary directory
- the remaining restrictions make a runtime escape non-viable inside 32 bytes
- therefore the remote instance is very likely **unintended / unsolvable**

---

## Payloads worth documenting

### Best relative-path attempt

```rust
#[path="flag"]mod a;fn main(){}
```

Observed result:

```text
error: couldn't read /tmp/<random>/flag
```

### Best absolute-path attempt within 32 bytes

```rust
#[path="/flag"]mod a;fn main(){}
```

This is the last serious candidate if the organizer stored the flag at `/flag`.

### Tempting runtime read that does not work

```rust
fn main(){std::fs::read("flag")}
```

Problems:

- blocked by blacklist
- wrong return type for `main`

### Type-correct runtime read that is one byte too long

```rust
fn main(){std::fs::read("flag");}
```

Problems:

- blocked by blacklist
- length is **33 bytes**

---

## Final verdict

This was a nice idea for a micro-jail, but the shipping constraints seem inconsistent with the intended solution.

As deployed, Rustjail looks less like a hidden trick challenge and more like a challenge whose winning path was accidentally cut off.
