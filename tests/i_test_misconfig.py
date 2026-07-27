from modules.crawler import Crawler
from modules.misconfig_scanner import MisconfigScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    scanner = MisconfigScanner(crawler.session, base_url="http://127.0.0.1")
    findings = scanner.scan()
