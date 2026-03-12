# License 2.0 - Reverse Engineering Writeup

## Challenge Information

- **Challenge:** License 2.0 - Reverse Engineering
- **Category:** Reverse Engineering / Windows / Qt
- **Attachment:** `License_v2.zip`
- **Main binary:** `QtLicense.exe`
- **Flag format:** `PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}`

---

## Flag

```text
PUCTF26{y0u_hv_4ct1v4t3d_w1th0ut_4_k3y_a9f3c4b1e7d28f5096bc1a4e3d5f8c72}
```

---

## Overview

This challenge ships a Windows Qt client application rather than a fully local activation system.  
After reversing the binary, the key finding is that the program sends an admin-mode boolean to a remote verifier:

```json
{
  "license_key": "...",
  "server_time": "...",
  "is_4dm1n_m0de": false
}
```

That value is controlled by the client and can be patched from `false` to `true`.

The intended vulnerability is a classic client-side trust bug: the server trusts a privilege-related field supplied by the client.

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

These strings reveal most of the challenge structure:

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

5. The application also performs an additional security check, likely certificate or public-key pinning.

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

- the flag is not generated locally,
- the interesting output is returned by the remote verifier,
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

In this challenge, the client hardcodes the field to `false`, but because the application is under the attacker's control, it can be patched.

So the intended weakness is:

> The server relies on a privilege-related value supplied by the client.

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

Once patched, the client claims to be in admin mode. Because the backend trusts that field, the request is routed into a hidden or privileged code path.

That privileged path returns the interesting `detail` value, which contains the flag.

This also matches the success path in the client:

- parse response JSON,
- check `status`,
- display `detail`.

---

## TLS / Security Check

The binary also contains the following message and a SHA-256-looking value:

```text
Security checking failed. The program will now close.
bf4f520d495cf025a7017b51c581e254c4b2ec5f22e138dd922c23575d6804c6
```

Combined with Qt network usage, this strongly suggests that the client performs additional certificate or public-key pinning.

That means the challenge is not just about intercepting traffic with a proxy and editing the request. The intended solve path is to:

1. reverse the client,
2. find the hidden field,
3. patch the binary directly,
4. let the patched client send the privileged request itself.

---

## Exploitation Steps

### 1. Extract the archive

```bash
unzip License_v2.zip -d License_v2_extracted
```

### 2. Patch the binary

Patch location:

- **File offset:** `0x18f1`

Change:

```text
33 d2
```

to:

```text
b2 01
```

This changes:

```asm
xor edx, edx
```

to:

```asm
mov dl, 1
```

which flips `is_4dm1n_m0de` from `false` to `true`.

### 3. Interact with the server

First request `/time` to obtain the current server time, then send a `POST` request to `/license/verify` with a payload like:

```json
{
  "license_key": "any_key",
  "server_time": "2026-03-12T14:50:22.848250+00:00",
  "is_4dm1n_m0de": true
}
```

The server returns a successful response containing the flag.

---

## Proof-of-Concept Script

```python
#!/usr/bin/env python3
import requests
import json
import sys

url = "https://chal.polyuctf.com:11337"
# Disable SSL warnings for self-signed cert
requests.packages.urllib3.disable_warnings()

# Step 1: Get server time
print("Getting server time...")
time_resp = requests.get(f"{url}/time", verify=False)
if time_resp.status_code != 200:
    print(f"Failed to get time: {time_resp.text}")
    sys.exit(1)
time_data = time_resp.json()
server_time = time_data['server_time']
print(f"Server time: {server_time}")

# Step 2: Send verification request with admin mode true
payload = {
    "license_key": "any_key",
    "server_time": server_time,
    "is_4dm1n_m0de": True
}
print(f"Sending payload: {json.dumps(payload)}")
verify_resp = requests.post(f"{url}/license/verify", json=payload, verify=False)
print(f"Response status: {verify_resp.status_code}")
print(f"Response body: {verify_resp.text}")

# Parse response
if verify_resp.status_code == 200:
    resp_json = verify_resp.json()
    print("\n=== Response ===")
    print(json.dumps(resp_json, indent=2))
    if resp_json.get('ok'):
        print(f"\nFlag might be in 'detail' field: {resp_json.get('detail')}")
    else:
        print(f"Error: {resp_json.get('message')}")
else:
    print("Request failed")
```

---

## Validation

The recovered flag is:

```text
PUCTF26{y0u_hv_4ct1v4t3d_w1th0ut_4_k3y_a9f3c4b1e7d28f5096bc1a4e3d5f8c72}
```

It matches the required format:

```text
PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}
```

So the challenge is solved successfully.

---

## Final Conclusion

This challenge is a client-side trust failure wrapped in a Qt GUI application.

### Intended solve path

1. Reverse `QtLicense.exe`
2. Discover that the verification request includes a hidden field:
   - `is_4dm1n_m0de`
3. Identify that the client hardcodes it to `false`
4. Patch the relevant instruction:
   - `33 d2` -> `b2 01`
   - `xor edx, edx` -> `mov dl, 1`
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
