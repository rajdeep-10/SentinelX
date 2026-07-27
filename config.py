"""
config.py — Target configuration for SentinelX.

This file is what makes SentinelX work against a target OTHER than
DVWA. Instead of modules hardcoding login URLs, field names, and
success/failure strings, everything target-specific lives here.

HOW TO POINT SENTINELX AT A NEW TARGET (e.g. a VulnHub box):
  1. Copy this file to config_<target_name>.py
  2. Fill in base_url and, if the target has a login form, the
     login_url / login fields / success+failure indicators.
  3. Run main.py with --config config_<target_name>.py

WHAT WORKS WITHOUT ANY LOGIN CONFIG AT ALL:
  - misconfig_scanner (headers, cookie flags, exposed paths)
  - crawler's generic link discovery (no login required)

WHAT REQUIRES login_url/login fields to be filled in correctly:
  - Any module that needs an authenticated session first:
    sqli_scanner, xss_scanner, cmdi_scanner, csrf_scanner,
    idor_scanner, brute_scanner (brute-forces the login itself,
    so only login_url/field names are needed, not credentials)

WHAT IS DVWA-SPECIFIC AND WILL NOT WORK ON OTHER TARGETS EVEN WITH
CONFIG CHANGES (documented honestly, not hidden):
  - sqli_exploiter's exact extraction technique assumes DVWA's
    response format
  - csrf_scanner's exploit_csrf() forges DVWA's specific
    password-change form fields
  - file_upload's webshell path assumes DVWA's upload directory
    structure
  - idor_scanner's direct-enumeration test is hardcoded to DVWA's
    SQLi page
  These are proof-of-concept exploits built to demonstrate real
  impact on DVWA specifically. On a new target, use the scanning
  modules to find the vulnerability, then exploit manually — same
  as a real engagement.
"""


from typing import Optional

SEVERITY_WEIGHT: dict[str, int] = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


class TargetConfig:
    def __init__(
        self,
        name: str = "DVWA",
        base_url: str = "http://127.0.0.1",
        # --- login (leave login_url as None if target has no login) ---
        login_url: str | None = "/login.php",
        username_field: str = "username",
        password_field: str = "password",
        token_field: str | None = "user_token",          # CSRF token field name on login form, or None
        extra_login_fields: dict[str, str] | None = None,  # dict of any additional required fields
        login_success_check: str = "cookie",      # "cookie" (session cookie set) or "text" (string appears on success)
        login_success_text: str | None = None,    # required if login_success_check == "text"
        login_failure_text: str = "Login failed",
        # --- security level (DVWA-specific, ignored for other targets) ---
        security_level_url: str | None = "/security.php",
        security_level_field: str = "security",
        # --- crawling ---
        crawl_mode: str = "fixed",                # "fixed" = use fixed_pages list, "discover" = follow links from base_url
        fixed_pages: list[str] | None = None,     # list of relative paths to crawl (used when crawl_mode == "fixed")
        discover_depth: int = 2,                  # link-following depth when crawl_mode == "discover"
        # --- brute force page ---
        brute_url: str | None = "/vulnerabilities/brute/",
        brute_username_field: str = "username",
        brute_password_field: str = "password",
        brute_success_text: str = "Welcome to the password protected area",
        brute_failure_text: str = "Username and/or password incorrect",
        # --- known IDOR-style target page (optional, used by idor_scanner's direct test) ---
        idor_direct_url: str | None = None,
        idor_direct_param: str = "id",
        idor_id_range: list[str] | None = None,
    ):
        self.name = name
        self.base_url = base_url.rstrip("/")

        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.token_field = token_field
        self.extra_login_fields = extra_login_fields or {"Login": "Login"}
        self.login_success_check = login_success_check
        self.login_success_text = login_success_text
        self.login_failure_text = login_failure_text

        self.security_level_url = security_level_url
        self.security_level_field = security_level_field

        self.crawl_mode = crawl_mode
        self.fixed_pages = fixed_pages or []
        self.discover_depth = discover_depth

        self.brute_url = brute_url
        self.brute_username_field = brute_username_field
        self.brute_password_field = brute_password_field
        self.brute_success_text = brute_success_text
        self.brute_failure_text = brute_failure_text

        self.idor_direct_url = idor_direct_url
        self.idor_direct_param = idor_direct_param
        self.idor_id_range = idor_id_range or []

    def full_url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"


# ─────────────────────────────────────────────────────────────
# Built-in DVWA config — used by default so existing workflow
# (test_*.py files, your Kali DVWA setup) keeps working unchanged
# ─────────────────────────────────────────────────────────────
DVWA_CONFIG = TargetConfig(
    name="DVWA",
    base_url="http://127.0.0.1",
    login_url="/login.php",
    username_field="username",
    password_field="password",
    token_field="user_token",
    extra_login_fields={"Login": "Login"},
    login_success_check="text",
    login_failure_text="Login failed",
    security_level_url="/security.php",
    security_level_field="security",
    crawl_mode="fixed",
    fixed_pages=[
        "vulnerabilities/sqli/",
        "vulnerabilities/sqli_blind/",
        "vulnerabilities/xss_r/",
        "vulnerabilities/xss_s/",
        "vulnerabilities/xss_d/",
        "vulnerabilities/exec/",
        "vulnerabilities/csrf/",
        "vulnerabilities/upload/",
        "vulnerabilities/brute/",
        "vulnerabilities/fi/",
    ],
    brute_url="/vulnerabilities/brute/",
    brute_username_field="username",
    brute_password_field="password",
    brute_success_text="Welcome to the password protected area",
    brute_failure_text="Username and/or password incorrect",
    idor_direct_url="/vulnerabilities/sqli/",
    idor_direct_param="id",
    idor_id_range=["1", "2", "3", "4", "5"],
)


# ─────────────────────────────────────────────────────────────
# Generic "no login" config — for pointing scanning modules at
# an arbitrary target (VulnHub box, CTF box) with no known login
# flow yet. Only login-free modules (misconfig, generic crawl)
# will do anything useful with this until you fill in login info.
# ─────────────────────────────────────────────────────────────
def generic_config(base_url):
    return TargetConfig(
        name="Generic Target",
        base_url=base_url,
        login_url=None,
        security_level_url=None,   # not a DVWA target — no security-level concept
        brute_url=None,            # unknown target — no assumed brute-force page either
        crawl_mode="discover",
        discover_depth=2,
    )
