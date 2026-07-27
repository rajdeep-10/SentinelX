from modules.crawler import Crawler
from modules.csrf_scanner import CSRFScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    forms = crawler.crawl_all()

    scanner = CSRFScanner(crawler.session, base_url="http://127.0.0.1")
    findings = scanner.scan_all(forms)
