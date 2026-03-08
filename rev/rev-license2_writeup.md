# License 2.0 - Reverse Engineering Writeup

## Challenge Information

- **Challenge:** License 2.0 - Reverse Engineering
- **Category:** Reverse Engineering / Windows / Qt
- **Attachment:** `License_v2.zip`
- **Main binary:** `QtLicense.exe`
- **Flag format:** `PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}`

---

## Overview

This challenge ships a Windows Qt client application, not a full local activation system.  
After reversing the binary, the key finding is that the program sends an **admin-mode boolean** to a remote verifier:

```json
{
  "license_key": "...",
  "server_time": "...",
  "is_4dm1n_m0de": false
}
```

That value is controlled by the client and can be patched from `false` to `true`.

The intended vulnerability is a classic **client-side trust bug**: the server appears to trust a privilege-related field supplied by the client.

---

## Files in the ZIP

After extracting the archive, the contents are typical of a deployed Qt application:

- `QtLicense.exe`
- Qt runtime DLLs
- `platforms/`
- `imageformats/`
- `translations/`
- other dependency files

Important point:

> The ZIP contains only the client.  
> It does **not** include any backend server code or local verifier service.

---

## Initial String Analysis

Useful strings can be extracted directly from `QtLicense.exe`:

```text
https://chal.polyuctf.com:11337
/time
/license/verify
server_time
license_key
is_4dm1n_m0de
status
detail
Please enter license key.
License key is valid.
License key is incorrect.
Server time mismatch. Please try again.
Security checking failed. The program will now close.
bf4f520d495cf025a7017b51c581e254c4b2ec5f22e138dd922c23575d6804c6
```

These already reveal most of the challenge structure:

1. The binary talks to a remote endpoint:
   - `https://chal.polyuctf.com:11337`

2. It uses at least two API routes:
   - `/time`
   - `/license/verify`

3. The verification request includes:
   - `license_key`
   - `server_time`
   - `is_4dm1n_m0de`

4. The response includes:
   - `status`
   - `detail`

5. The application also performs an additional security check, likely certificate/public-key pinning.

---

## Program Flow

The client logic can be summarized as follows.

### 1. User enters a license key

The GUI prompts the user to enter a key.  
If the field is empty, the application shows:

> Please enter license key.

### 2. The client requests server time

Before verification, the program sends:

```http
GET /time
```

and expects a JSON response containing `server_time`.

If that step fails, it shows:

> Cannot get time.

### 3. The client sends a verification request

The program then sends:

```http
POST /license/verify
```

with a JSON payload equivalent to:

```json
{
  "license_key": "user_input",
  "server_time": "value_from_/time",
  "is_4dm1n_m0de": false
}
```

### 4. The client displays the server response

If the returned JSON indicates success, the client displays the `detail` field.

This is important because it means:

- the flag is **not** generated locally,
- the interesting output is expected to come from the remote verifier,
- the client mainly acts as a transport and display layer.

---

## Root Cause

The bug is the field:

```json
"is_4dm1n_m0de": false
```

This value is determined by the client and sent to the server as part of the verification request.

That is a design flaw. A server should never trust client-supplied privilege indicators such as:

- `is_admin`
- `role`
- `vip`
- `premium`
- `debug`
- `internal`

In this challenge, the client hardcodes the field to `false`, but because the application is under the attacker’s control, it can be patched.

So the intended weakness is:

> The server appears to rely on a privilege-related value supplied by the client.

---

## Locating the Patch

In the code that builds the request JSON, the relevant instruction is:

```asm
1400024f1: 33 d2    xor edx, edx
```

This sets the corresponding boolean argument to zero, i.e. `false`.

### Patch location

- **RVA:** `0x24f1`
- **File offset:** `0x18f1`

### Original bytes

```text
33 d2
```

### Original instruction

```asm
xor edx, edx
```

### Patched bytes

```text
b2 01
```

### Patched instruction

```asm
mov dl, 1
```

After patching, the request changes from:

```json
"is_4dm1n_m0de": false
```

to:

```json
"is_4dm1n_m0de": true
```

---

## Why This Works

The application includes an admin-mode field but does not expose it in the UI.  
Under normal execution, it always sends `false`.

Once patched, the client claims to be in admin mode. If the backend trusts that field, the request is routed into a hidden or privileged code path.

That hidden path is likely what returns the interesting `detail` value, which is expected to contain the flag.

This also matches the observed success path in the client:

- parse response JSON,
- check `status`,
- display `detail`.

---

## TLS / Security Check

The binary also contains the following message and a long SHA-256-looking value:

```text
Security checking failed. The program will now close.
bf4f520d495cf025a7017b51c581e254c4b2ec5f22e138dd922c23575d6804c6
```

Combined with Qt network usage, this strongly suggests that the client performs additional certificate or public-key pinning.

That means the challenge is not just about intercepting traffic with a proxy and editing the request. The author likely intended solvers to:

1. reverse the client,
2. find the hidden field,
3. patch the binary directly,
4. let the patched client send the privileged request itself.

---

## Practical Exploitation

### Static patch

Open the executable in a hex editor and modify:

- **file offset:** `0x18f1`

Change:

```text
33 d2
```

to:

```text
b2 01
```

Save the modified binary and run it.

### Dynamic patch

Using a debugger such as x64dbg:

1. Load `QtLicense.exe`
2. Navigate to address `1400024f1`
3. Replace

   ```asm
   xor edx, edx
   ```

   with

   ```asm
   mov dl, 1
   ```

4. Continue execution
5. Enter a license key and let the application send the request

If the remote service is reachable and trusts the field, the response should go through the privileged path and reveal the flag in `detail`.

---

## Why the Exact Flag Cannot Be Recovered from the ZIP Alone

This is the most important limitation to state honestly.

From the provided attachment, I could confirm:

- the client talks to a remote service,
- the request structure,
- the presence of the `is_4dm1n_m0de` field,
- the vulnerable trust boundary,
- the correct patch location,
- the fact that the client displays server-supplied `detail`.

However, I could **not** confirm an offline local flag source because:

- there is no embedded `PUCTF26{...}` string in the binary,
- there is no obvious local flag-generation routine,
- the final success message appears to come from the remote verifier.

So the exact flag is not recoverable from the client alone unless one of the following is available:

- the original remote endpoint is still online,
- the server code is obtained,
- a recorded successful response is available.

Any precise final flag string produced without that would be a guess.

---

## Final Conclusion

This challenge is a client-side trust failure wrapped in a Qt GUI application.

### Intended solve path

1. Reverse `QtLicense.exe`
2. Discover that the verification request includes a hidden field:
   - `is_4dm1n_m0de`
3. Identify that the client hardcodes it to `false`
4. Patch the relevant instruction:
   - `33 d2` → `b2 01`
   - `xor edx, edx` → `mov dl, 1`
5. Force the client to send:

   ```json
   "is_4dm1n_m0de": true
   ```

6. Trigger the privileged verifier path
7. Read the returned flag from the response `detail`

### Core lesson

> Never trust privilege-related fields supplied by the client.

---

## Patch Summary

- **RVA:** `0x24f1`
- **File offset:** `0x18f1`
- **Original bytes:** `33 d2`
- **Patched bytes:** `b2 01`

---

## Honest Note

This writeup fully explains:

- the reverse engineering process,
- the bug,
- the patch,
- the intended exploitation path.

But the exact final `PUCTF26{...}` value cannot be extracted honestly from the supplied ZIP alone, because the backend responsible for returning it is not included in the challenge files.
