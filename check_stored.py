from modules.crawler import Crawler

crawler = Crawler("http://127.0.0.1")
crawler.login()
crawler.set_security_level("low")

resp = crawler.session.get("http://127.0.0.1/vulnerabilities/xss_s/", timeout=10)

# Print just the guestbook content section so we can see if our
# payload actually got stored and is present in the page
import re
match = re.search(r'<div class="vulnerable_code_area">(.*?)</div>\s*</div>', resp.text, re.DOTALL)
if match:
    print(match.group(1))
else:
    print("Could not isolate guestbook section, printing full page:")
    print(resp.text)
