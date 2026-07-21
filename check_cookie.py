from modules.crawler import Crawler

crawler = Crawler("http://127.0.0.1")
if crawler.login():
    for cookie in crawler.session.cookies:
        print(f"Cookie name: {cookie.name}")
        print(f"Value: {cookie.value}")
        print(f"HttpOnly flag: {cookie.has_nonstandard_attr('HttpOnly')}")
        print(f"Raw cookie object: {cookie}")
