from modules.crawler import Crawler
from modules.idor_scanner import IDORScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    forms = crawler.crawl_all()

    scanner = IDORScanner(crawler.session, base_url="http://127.0.0.1")
    findings = scanner.scan_all(forms)
