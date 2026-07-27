from modules.crawler import Crawler
from modules.brute_scanner import BruteForceScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    scanner = BruteForceScanner(crawler.session, base_url="http://127.0.0.1")
    findings = scanner.scan(username="admin", wordlist_path="/usr/share/wordlists/rockyou.txt")
