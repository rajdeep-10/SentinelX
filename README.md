# SentinelX

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A Python CLI web application vulnerability scanner **and exploitation framework** — built on the principle that a finding isn't real until it's been proven. Every module scans, detects, then exploits to demonstrate actual impact: real data extraction, real remote shells, real credential theft — not just a flagged CWE ID.

Project 4 of a 4-part cybersecurity portfolio. Built and iterated against a live [DVWA](https://github.com/digininja/DVWA) instance, with an interactive guided CLI, a config-driven architecture for pointing at other targets, and every fix in its history verified against a reproduced bug — not assumed from a code read.

```
  Recon (any target, no login)  →  Scan  →  Exploit  →  Risk-Rated Report
     misconfig + discovery         7 modules   proof-of-impact   JSON + Markdown-style .txt
```

---

## Why This Exists

Most student-built scanners stop at detection — flag a CWE, print a severity, move on. That's not what a real pentest report needs, and it's not what proves you understand the vulnerability. SentinelX was built so every module also answers "so what" — SQLi doesn't just get flagged, it dumps the `users` table and cracks the hashes. File upload doesn't just get flagged, it gets a working webshell and a root-adjacent interactive session. CSRF doesn't just get flagged, it forges a real request using the vulnerable form's own fields and shows the response actually changed.

The build process itself was also a real debugging exercise, not a tutorial follow-along: this repo's history includes a full audit pass where every module was tested against a target it was never designed for, real bugs were found and reproduced before being called bugs, and every fix was re-verified against both the new target and the original DVWA baseline to confirm nothing regressed.

---

## Proof of Concept — A Real Run Against DVWA

```
$ python3 main.py
? Target IP or URL: http://127.0.0.1
? Is this a DVWA instance? Yes

============================================================
   PHASE 1: RECON (no login required)
============================================================
[+] MISCONFIG SCAN COMPLETE
    CRITICAL : 1   HIGH : 8   MEDIUM : 3   LOW : 3   TOTAL : 15

? Username: admin
? Password: password
[+] Login successful — session cookie active
[*] Crawl complete: 9 pages with forms, 9 forms, 21 total inputs discovered

? Select modules: done (7 selections)
? Run mode: Automatic

[!] SQLi found -> /vulnerabilities/sqli/  param='id'  severity=CRITICAL
[!] EXTRACTED CREDENTIALS:
    admin:5f4dcc3b5aa765d61d8327deb882cf99
    gordonb:e99a18c428cb38d5f260853678922e03
    ...
[!] Command injection CONFIRMED -> /vulnerabilities/exec/  verified as: 'www-data'
[!] CSRF EXPLOIT LIKELY SUCCESSFUL -> /vulnerabilities/csrf/
[+] Upload succeeded: /hackable/uploads/shell.php — Shell is live and executing commands
[!] IDOR found -> 6 unauthorized records accessible via id= tampering

============================================================
   SCAN COMPLETE
============================================================
Risk score: 100/100
  CRITICAL   7      HIGH   19      MEDIUM   3      LOW   3

[+] Report saved: sentinelx_report_20260724_010010.json / .txt
```

32 findings across all 7 exploitable modules in a single automated run, including full credential extraction, a live webshell, and confirmed remote command execution. Full command reference and cheat sheet: **[COMMANDS.md](COMMANDS.md)**.

---

## Architecture

```
                         ┌───────────────────────┐
                         │       main.py          │   <- guided CLI, run this
                         │  (interactive, arrow-   │
                         │   key module picker)    │
                         └───────────┬─────────────┘
                                    │
                    ┌────────────────┼────────────────┐
                    │                │                │
            ┌───────▼───────┐ ┌──────▼──────┐ ┌────────▼────────┐
            │   config.py    │ │  crawler.py │ │ misconfig_       │
            │  TargetConfig  │ │  login +     │ │ scanner.py       │
            │  (DVWA or      │ │  form/link   │ │ (headers,        │
            │   custom)      │ │  discovery   │ │  cookies, paths) │
            └────────────────┘ └──────┬──────┘ └──────────────────┘
                                     │
        ┌─────────────┬──────────────┼──────────────┬─────────────┐
        │             │              │              │             │
  ┌─────▼─────┐ ┌─────▼─────┐ ┌──────▼──────┐ ┌──────▼─────┐ ┌────▼─────┐
  │  sqli_     │ │  xss_      │ │  cmdi_       │ │  csrf_     │ │  idor /   │
  │  scanner + │ │  scanner + │ │  scanner     │ │  scanner   │ │  brute /  │
  │  exploiter │ │  cookie_   │ │  (detect +   │ │  (detect + │ │  file_    │
  │  (detect + │ │  theft     │ │   exploit)   │ │   forge)   │ │  upload   │
  │   extract) │ │            │ │              │ │            │ │           │
  └────────────┘ └────────────┘ └──────────────┘ └────────────┘ └───────────┘
        │             │              │              │             │
        └─────────────┴──────────────┼──────────────┴─────────────┘
                                     │
                        ┌────────────▼─────────────┐
                        │   Unified finding model:  │
                        │   type, severity, url,    │
                        │   evidence, exploitation  │
                        └────────────┬─────────────┘
                                     │
                        ┌────────────▼─────────────┐
                        │  Risk-scored JSON + .txt   │
                        │  report + on-screen table  │
                        └───────────────────────────┘
```

Every module was built standalone first (they still exist independently as `tests/test_*.py` scripts), then wired together in `main.py` sharing one finding format — the same incremental order used in this portfolio's other projects, so each module could be verified against a real target before being combined.

---

## Usage

**Guided mode (recommended):**
```bash
python3 main.py
```
Walks you through target setup, runs recon automatically (works on any target — no login needed), then lets you pick modules and run mode (Automatic or Manual, which pauses for confirmation before every real exploit action).

**Individual modules:**
```bash
python3 tests/test_sqli.py       # SQLi detect + full exploitation
python3 tests/test_cmdi.py       # Command injection + interactive shell
python3 tests/test_csrf.py       # CSRF detect + forge exploit
python3 tests/test_upload.py     # Webshell upload + interactive shell
```

Full command list, flags, and an nmap-style cheat sheet for every module: **[COMMANDS.md](COMMANDS.md)**

---

## Design Decisions Worth Noting

| Decision | Reasoning |
|---|---|
| Scan-then-exploit on every module | A finding a scanner can't prove is a guess. Every module was built to demonstrate real impact, not just pattern-match a payload response. |
| Config-driven target layer (`config.py`) instead of hardcoded DVWA strings | Lets scanning modules (SQLi, XSS, misconfig, discovery-mode crawling) generalize to other targets — a real CTF/VulnHub box — without touching module code. |
| Recon phase requires zero login | Misconfig scanning and link-discovery crawling work the moment you have an IP — mirrors how real recon starts, before any credentials are known. |
| Manual mode confirms before every exploit, not every module | Pausing on pure-detection steps (misconfig, IDOR tampering) adds friction with no learning value. Pausing before a real forged request, extraction, or shell is where the confirmation actually matters. |
| Small curated brute-force wordlist by default, full wordlist support optional | A 12-word list demonstrates the technique cleanly in seconds; `wordlist_path` accepts any real list (tested against a real 14M-entry rockyou.txt run) for when a genuine crack attempt is needed. |
| Interrupt-safe scanning | A Ctrl+C mid-scan returns everything found up to that point instead of discarding the whole run — confirmed this actually mattered after losing a full multi-module finding set to an early version that didn't handle this. |
| JSON + human-readable .txt report, both from one run | JSON for anything that needs to consume the data programmatically later; the .txt report is written to be handed to someone directly, with a computed risk score and full per-finding evidence. |

---

## Bugs Found & Fixed

Every one of these was reproduced against a real target before being called a bug — not assumed from reading the code.

1. **Command injection output extraction only worked on `<pre>`-wrapped responses.** `cmdi_scanner.py`'s `_extract_output()` was hardcoded to DVWA's exact output format. Reproduced this as a real false negative on a mock target that rendered command output in a plain `<div>` — injection succeeded, scanner reported nothing. Fixed with a fallback: try `<pre>` first, fall back to full-page text extraction. Re-verified DVWA's exact output was unaffected.

2. **CSRF exploitation only ever ran against one hardcoded DVWA URL.** Detection correctly flagged missing tokens on any target, but `exploit_csrf()` only fired if the URL contained the literal string `"csrf"`, and forged DVWA's exact password-change field names. On a mock target with a completely different vulnerable form, this meant: correctly detected, silently never exploited. Rewrote to forge a request using the actual vulnerable form's own field names (read from the crawler's discovery), with generic success detection instead of a hardcoded string. Re-run against real DVWA correctly went from evaluating 1 form to 4.

3. **File upload success detection only recognized DVWA's exact wording and path.** `check_upload_success()` would report "all uploads blocked" on a target that used different phrasing or a different upload directory — even when the upload genuinely succeeded. Fixed to extract the real path from the response when present, with a configurable fallback directory hint. Verified byte-identical DVWA behavior plus success on a target with a totally different field name and path structure.

4. **SQLi data extraction was anchored to DVWA's literal `"First name:"` label.** A successful UNION injection on any other target — data sitting right there in the response — would still return `None`, because extraction only recognized that one exact label. Fixed with a two-tier approach: try the label match first (DVWA output stays identical), fall back to stripped full-text extraction otherwise. Re-verified against a real DVWA run: full 5-user credential dump, later cracked 5/5 via the hash cracker, unchanged.

5. **A Ctrl+C mid-scan discarded the entire report, not just the interrupted module.** Interrupting a long brute-force run (real scenario: a 14-million-entry rockyou.txt scan) exited before the report was ever written — losing every finding from every module that had already completed in that run: SQLi credentials, a live webshell, confirmed command execution, all real, all gone. Fixed by catching the interrupt at the module-orchestration level so completed findings are preserved and still written to the report. Verified with a targeted test simulating an interrupt mid-way through a later module.

6. **The ASCII banner rendered as "WEBX" instead of "SentinelX."** A hand-typed block-art banner had a character-counting error. Fixed properly on the second pass after a font-based fix (`pyfiglet`) turned out to depend on a font (`blocky`) not bundled in the target machine's installed `pyfiglet` package — which crashed the tool outright with `FontNotFound`. Final fix: generated the desired thick block-art glyphs once, then hardcoded the literal characters directly into the script, removing the runtime font dependency entirely so it can't break on a different machine's package set again.

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| Web application vulnerability classes (OWASP Top 10-adjacent) | SQLi, XSS, CSRF, IDOR, command injection, insecure file upload, security misconfiguration — all built and exploited, not just described |
| Exploitation, not just detection | UNION-based SQLi data extraction, webshell deployment + interactive RCE, forged CSRF requests, XSS-driven cookie theft |
| Config-driven architecture | `TargetConfig` abstraction generalizing scanning logic away from a single hardcoded target |
| Regression-safe iterative development | Every fix in this repo's history was re-verified against the original DVWA baseline before being considered done |
| Root-cause debugging over assumption | Every listed bug was reproduced against a live or mocked target first — see Bugs Found & Fixed |
| CLI/UX design for a technical tool | Guided interactive flow (`main.py`) with recon-first sequencing, manual/automatic exploitation modes, and risk-scored reporting |
| Threaded/interactive tooling | Live interactive shells for SQLi, command injection, and webshell sessions |

---

## Setup

```bash
git clone https://github.com/rajdeep-10/SentinelX.git
cd SentinelX
pip install -r requirements.txt --break-system-packages
python3 main.py
```

Requires Python 3.8+. Tested on Kali Linux against a local DVWA instance (security level: low).

---

## Legal & Ethical Use

This tool performs real exploitation — data extraction, remote code execution, credential theft simulation, forged requests. It is built strictly for authorized security testing and educational use: your own lab virtual machines, deliberately vulnerable practice targets (DVWA, Metasploitable2, VulnHub, TryHackMe, HackTheBox), or systems you have explicit written authorization to test.

**Do not run this against any system you do not own or do not have explicit permission to test.** Unauthorized access to computer systems is illegal under laws including the U.S. Computer Fraud and Abuse Act and equivalent legislation in most countries, regardless of whether a vulnerability is successfully exploited.

All testing for this project was performed against DVWA running locally on an isolated Kali VM, with no exposure to any third-party system.

---

## License

MIT — see [LICENSE](LICENSE).

## Author

**Rajdeep Goswami** — [github.com/rajdeep-10](https://github.com/rajdeep-10)
CEH / CEH Practical / CEH Master. Project 4 of a 4-part cybersecurity portfolio (see also: [ThreatMapper](https://github.com/rajdeep-10/ThreatMapper), [PacketHound](https://github.com/rajdeep-10/PacketHound), [PrivEscChecker](https://github.com/rajdeep-10/PrivEscChecker)).
