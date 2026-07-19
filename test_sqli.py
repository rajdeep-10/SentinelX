from modules.crawler import Crawler
from modules.sqli_scanner import SQLiScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    forms = crawler.crawl_all()

    scanner = SQLiScanner(crawler.session)
    findings = scanner.scan_all(forms)
