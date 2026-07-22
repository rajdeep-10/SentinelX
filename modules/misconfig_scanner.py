import requests
from colorama import Fore, init
import re

init(autoreset=True)

class MisconfigScanner:
    """
    Checks for security misconfigurations that don't require
    injection or exploitation — the misconfiguration itself is
    the finding. Three categories:
    1. Missing HTTP security headers
    2. Insecure cookie flags
    3. Exposed sensitive paths (admin panels, config files, etc.)
    """

    SECURITY_HEADERS = {
        "X-Frame-Options":        ("HIGH",   "Allows clickjacking attacks — page can be embedded in an iframe"),
        "X-Content-Type-Options": ("MEDIUM", "Browser may MIME-sniff responses, enabling content injection"),
        "X-XSS-Protection":       ("MEDIUM", "No browser-level XSS filter hint (legacy but still checked)"),
        "Content-Security-Policy":("HIGH",   "No CSP means XSS payloads can load external scripts freely"),
        "Strict-Transport-Security":("HIGH", "No HSTS — connections can be downgraded from HTTPS to HTTP"),
        "Referrer-Policy":        ("LOW",    "Referrer header may leak sensitive URLs to third parties"),
        "Permissions-Policy":     ("LOW",    "Browser features (camera, mic, geolocation) not restricted"),
    }

    SENSITIVE_PATHS = [
        ("/.git/HEAD",              "CRITICAL", "Git repository exposed — source code and history accessible"),
        ("/.env",                   "CRITICAL", "Environment file exposed — may contain API keys, DB passwords"),
        ("/config.php",             "HIGH",     "PHP config file potentially exposed"),
        ("/phpinfo.php",            "HIGH",     "PHP info page leaks server config, modules, environment vars"),
        ("/admin/",                 "MEDIUM",   "Admin panel accessible — check for weak credentials"),
        ("/backup/",                "HIGH",     "Backup directory exposed — may contain source or DB dumps"),
        ("/wp-admin/",              "MEDIUM",   "WordPress admin panel detected"),
        ("/server-status",          "MEDIUM",   "Apache server-status page may be publicly accessible"),
        ("/robots.txt",             "LOW",      "Robots.txt may reveal hidden paths disallowed for crawlers"),
        ("/crossdomain.xml",        "LOW",      "Flash crossdomain policy file — check for overly permissive rules"),
        ("/hackable/uploads/",      "CRITICAL", "DVWA upload directory publicly browsable"),
    ]

    def __init__(self, session, base_url="http://127.0.0.1"):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.findings = []

    # ─────────────────────────────────────────────
    # CHECK 1 — Missing security headers
    # ─────────────────────────────────────────────
    def check_headers(self):
        print(f"{Fore.BLUE}[*] Checking security headers...")

        try:
            resp = self.session.get(self.base_url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Could not reach target: {e}")
            return

        headers_present = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, impact) in self.SECURITY_HEADERS.items():
            if header.lower() not in headers_present:
                print(f"{Fore.YELLOW}[!] MISSING {header:<35} [{severity}]")
                self.findings.append({
                    "type":      "MISSING_SECURITY_HEADER",
                    "severity":  severity,
                    "header":    header,
                    "impact":    impact,
                    "url":       self.base_url
                })
            else:
                print(f"{Fore.GREEN}[+] PRESENT {header:<35} = {headers_present[header.lower()][:60]}")

    # ─────────────────────────────────────────────
    # CHECK 2 — Cookie security flags
    # ─────────────────────────────────────────────
    def check_cookies(self):
        print(f"\n{Fore.BLUE}[*] Checking cookie security flags...")

        for cookie in self.session.cookies:
            issues = []

            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly — JavaScript can read this cookie (enables XSS session theft)")

            if not cookie.secure:
                issues.append("missing Secure flag — cookie transmitted over plain HTTP")

            if issues:
                for issue in issues:
                    print(f"{Fore.YELLOW}[!] Cookie '{cookie.name}': {issue}")
                    self.findings.append({
                        "type":     "INSECURE_COOKIE",
                        "severity": "HIGH",
                        "cookie":   cookie.name,
                        "issue":    issue,
                        "url":      self.base_url
                    })
            else:
                print(f"{Fore.GREEN}[+] Cookie '{cookie.name}' — HttpOnly and Secure flags set")

    # ─────────────────────────────────────────────
    # CHECK 3 — Exposed sensitive paths
    # ─────────────────────────────────────────────
    def check_exposed_paths(self):
        print(f"\n{Fore.BLUE}[*] Checking for exposed sensitive paths...")

        for path, severity, description in self.SENSITIVE_PATHS:
            url = f"{self.base_url}{path}"

            try:
                resp = self.session.get(url, timeout=8, allow_redirects=True)
            except requests.exceptions.RequestException:
                continue

            if resp.status_code in (200, 301, 302, 403):
                # 403 still confirms the path exists (just access-controlled)
                status_label = str(resp.status_code)
                if resp.status_code == 403:
                    severity = min(severity, "MEDIUM")
                    status_label = "403 (exists but access denied)"

                print(f"{Fore.YELLOW}[!] FOUND {path:<35} HTTP {status_label} [{severity}]")
                print(f"{Fore.YELLOW}    {description}")

                self.findings.append({
                    "type":        "EXPOSED_PATH",
                    "severity":    severity,
                    "url":         url,
                    "status_code": resp.status_code,
                    "description": description
                })
            else:
                print(f"{Fore.GREEN}[+] NOT FOUND {path:<30} HTTP {resp.status_code}")

    # ─────────────────────────────────────────────
    # FULL SCAN
    # ─────────────────────────────────────────────
    def scan(self):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   MISCONFIGURATION SCAN -> {self.base_url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        self.check_headers()
        self.check_cookies()
        self.check_exposed_paths()

        critical = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high     = [f for f in self.findings if f["severity"] == "HIGH"]
        medium   = [f for f in self.findings if f["severity"] == "MEDIUM"]
        low      = [f for f in self.findings if f["severity"] == "LOW"]

        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   MISCONFIG SCAN COMPLETE")
        print(f"{Fore.RED}   CRITICAL : {len(critical)}")
        print(f"{Fore.YELLOW}   HIGH     : {len(high)}")
        print(f"{Fore.BLUE}   MEDIUM   : {len(medium)}")
        print(f"{Fore.WHITE}   LOW      : {len(low)}")
        print(f"{Fore.CYAN}   TOTAL    : {len(self.findings)}")
        print(f"{Fore.CYAN}{'='*55}\n")

        return self.findings
