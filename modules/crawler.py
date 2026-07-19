import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, init

init(autoreset=True)

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.logged_in = False
        self.discovered_forms = {}
        self.visited_urls = set()

    def login(self, username="admin", password="password"):
        login_url = f"{self.base_url}/login.php"

        print(f"{Fore.BLUE}[*] Fetching login page to grab CSRF token...")

        resp = self.session.get(login_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        token_input = soup.find("input", {"name": "user_token"})
        if not token_input:
            print(f"{Fore.RED}[-] Could not find CSRF token on login page — is DVWA running?")
            return False

        csrf_token = token_input.get("value")
        print(f"{Fore.GREEN}[+] Got CSRF token: {csrf_token[:10]}...")

        login_data = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": csrf_token
        }

        print(f"{Fore.BLUE}[*] Logging in as '{username}'...")
        resp = self.session.post(login_url, data=login_data, timeout=10)

        if "login.php" in resp.url or "Login failed" in resp.text:
            print(f"{Fore.RED}[-] Login failed — check credentials")
            return False

        self.logged_in = True
        print(f"{Fore.GREEN}[+] Login successful — session cookie active")
        return True

    def set_security_level(self, level="low"):
        if not self.logged_in:
            print(f"{Fore.RED}[-] Must log in before setting security level")
            return False

        security_url = f"{self.base_url}/security.php"

        resp = self.session.get(security_url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        csrf_token = token_input.get("value") if token_input else ""

        data = {
            "security": level,
            "seclev_submit": "Submit",
            "user_token": csrf_token
        }

        self.session.post(security_url, data=data, timeout=10)
        print(f"{Fore.GREEN}[+] Security level set to '{level}'")
        return True

    def crawl_page(self, path):
        url = urljoin(self.base_url + "/", path)

        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        try:
            resp = self.session.get(url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Failed to fetch {url}: {e}")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        forms_on_page = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            full_action_url = urljoin(url, action) if action else url
            method = form.get("method", "get").lower()

            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", "")
                    })

            if inputs:
                forms_on_page.append({
                    "action": full_action_url,
                    "method": method,
                    "inputs": inputs
                })

        if forms_on_page:
            self.discovered_forms[url] = forms_on_page
            print(f"{Fore.GREEN}[+] {path:<30} -> {len(forms_on_page)} form(s), "
                  f"{sum(len(f['inputs']) for f in forms_on_page)} input(s)")
        else:
            print(f"{Fore.YELLOW}[?] {path:<30} -> no forms found")

    DVWA_PAGES = [
        "vulnerabilities/sqli/",
        "vulnerabilities/sqli_blind/",
        "vulnerabilities/xss_r/",
        "vulnerabilities/xss_s/",
        "vulnerabilities/xss_d/",
        "vulnerabilities/exec/",
        "vulnerabilities/csrf/",
        "vulnerabilities/upload/",
        "vulnerabilities/brute/",
        "vulnerabilities/fi/",
    ]

    def crawl_all(self):
        if not self.logged_in:
            print(f"{Fore.RED}[-] Must log in before crawling")
            return

        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   CRAWLING TARGET -> {self.base_url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        for page in self.DVWA_PAGES:
            self.crawl_page(page)

        total_forms = sum(len(v) for v in self.discovered_forms.values())
        total_inputs = sum(len(f["inputs"]) for forms in self.discovered_forms.values() for f in forms)

        print(f"\n{Fore.CYAN}[*] Crawl complete: {len(self.discovered_forms)} pages with forms, "
              f"{total_forms} forms, {total_inputs} total inputs discovered")

        return self.discovered_forms


if __name__ == "__main__":
    crawler = Crawler("http://127.0.0.1")
    if crawler.login():
        crawler.set_security_level("low")
        crawler.crawl_all()
