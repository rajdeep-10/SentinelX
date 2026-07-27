from modules.crawler import Crawler
from modules.sqli_scanner import SQLiScanner
from modules.xss_scanner import XSSScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")
    forms = crawler.crawl_all()

    sqli_scanner = SQLiScanner(crawler.session)
    sqli_findings = sqli_scanner.scan_all(forms)

    xss_scanner = XSSScanner(crawler.session)
    xss_findings = xss_scanner.scan_all(forms)
