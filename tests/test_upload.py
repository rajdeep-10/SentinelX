from modules.crawler import Crawler
from modules.file_upload import FileUploadScanner

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    crawler.set_security_level("low")

    scanner = FileUploadScanner(crawler.session, base_url="http://127.0.0.1")
    findings = scanner.scan()
