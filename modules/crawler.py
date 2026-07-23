import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, init

from config import DVWA_CONFIG

init(autoreset=True)


class Crawler:
    """
    Config-driven crawler.

    Backward compatible: Crawler("http://127.0.0.1") with no config
    behaves exactly like before (DVWA defaults, fixed page list).

    For a new target: Crawler(config=my_target_config), where
    my_target_config.crawl_mode == "discover" makes it follow links
    from base_url instead of using a fixed page list — this is what
    lets it explore a VulnHub/CTF box it has never seen before.
    """

    def __init__(self, base_url=None, config=None):
        if config is not None:
            self.config = config
        else:
            self.config = DVWA_CONFIG
            if base_url:
                self.config.base_url = base_url.rstrip("/")

        self.base_url = self.config.base_url
        self.session = requests.Session()
        self.logged_in = False
        self.discovered_forms = {}
        self.visited_urls = set()

    # ─────────────────────────────────────────────
    # LOGIN — uses config's field names/URL, falls back
    # to "no login needed" if config.login_url is None
    # ─────────────────────────────────────────────
    def login(self, username="admin", password="password"):
        cfg = self.config

        if cfg.login_url is None:
            print(f"{Fore.YELLOW}[*] No login configured for this target — "
                  f"skipping authentication, treating session as ready")
            self.logged_in = True
            return True

        login_url = cfg.full_url(cfg.login_url)

        print(f"{Fore.BLUE}[*] Fetching login page...")

        try:
            resp = self.session.get(login_url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Could not reach login page: {e}")
            return False

        soup = BeautifulSoup(resp.text, "html.parser")

        login_data = {
            cfg.username_field: username,
            cfg.password_field: password,
        }
        login_data.update(cfg.extra_login_fields)

        csrf_token = None
        if cfg.token_field:
            token_input = soup.find("input", {"name": cfg.token_field})
            if token_input:
                csrf_token = token_input.get("value")
                login_data[cfg.token_field] = csrf_token
                print(f"{Fore.GREEN}[+] Got CSRF token: {csrf_token[:10]}...")
            else:
                print(f"{Fore.YELLOW}[*] No token field '{cfg.token_field}' found on "
                      f"login page — continuing without it")

        print(f"{Fore.BLUE}[*] Logging in as '{username}'...")
        try:
            resp = self.session.post(login_url, data=login_data, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Login request failed: {e}")
            return False

        if cfg.login_success_check == "text" and cfg.login_success_text:
            success = cfg.login_success_text in resp.text
        else:
            success = cfg.login_failure_text not in resp.text

        if not success:
            print(f"{Fore.RED}[-] Login failed — check credentials or config field names")
            return False

        self.logged_in = True
        print(f"{Fore.GREEN}[+] Login successful — session cookie active")
        return True

    def set_security_level(self, level="low"):
        cfg = self.config
        if not cfg.security_level_url:
            return True

        if not self.logged_in:
            print(f"{Fore.RED}[-] Must log in before setting security level")
            return False

        security_url = cfg.full_url(cfg.security_level_url)

        try:
            resp = self.session.get(security_url, timeout=10)
        except requests.exceptions.RequestException:
            return False

        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", {"name": cfg.token_field}) if cfg.token_field else None
        csrf_token = token_input.get("value") if token_input else ""

        data = {cfg.security_level_field: level, "seclev_submit": "Submit"}
        if cfg.token_field:
            data[cfg.token_field] = csrf_token

        self.session.post(security_url, data=data, timeout=10)
        print(f"{Fore.GREEN}[+] Security level set to '{level}'")
        return True

    # ─────────────────────────────────────────────
    # PAGE CRAWL — fetch one page, extract forms
    # ─────────────────────────────────────────────
    def crawl_page(self, path):
        url = urljoin(self.base_url + "/", path) if not path.startswith("http") else path

        if url in self.visited_urls:
            return []

        self.visited_urls.add(url)

        try:
            resp = self.session.get(url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Failed to fetch {url}: {e}")
            return []

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

        display_path = path if len(path) <= 30 else path[:27] + "..."
        if forms_on_page:
            self.discovered_forms[url] = forms_on_page
            print(f"{Fore.GREEN}[+] {display_path:<30} -> {len(forms_on_page)} form(s), "
                  f"{sum(len(f['inputs']) for f in forms_on_page)} input(s)")
        else:
            print(f"{Fore.YELLOW}[?] {display_path:<30} -> no forms found")

        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full_link = urljoin(url, href)
            parsed_base = urlparse(self.base_url)
            parsed_link = urlparse(full_link)
            if parsed_link.netloc == parsed_base.netloc:
                links.append(full_link)

        return links

    # ─────────────────────────────────────────────
    # DISCOVERY MODE — real link-following crawl for
    # unknown targets (VulnHub/CTF boxes), no fixed
    # page list required
    # ─────────────────────────────────────────────
    def crawl_discover(self, depth=2):
        to_visit = [(self.base_url, 0)]
        visited_for_bfs = set()

        while to_visit:
            url, current_depth = to_visit.pop(0)

            if url in visited_for_bfs or current_depth > depth:
                continue
            visited_for_bfs.add(url)

            path = url.replace(self.base_url, "").lstrip("/")
            links = self.crawl_page(path)

            if current_depth < depth:
                for link in links:
                    if link not in visited_for_bfs:
                        to_visit.append((link, current_depth + 1))

    def crawl_all(self):
        if not self.logged_in:
            print(f"{Fore.RED}[-] Must log in before crawling")
            return {}

        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   CRAWLING TARGET -> {self.base_url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        if self.config.crawl_mode == "discover":
            print(f"{Fore.BLUE}[*] Discovery mode — following links "
                  f"(depth {self.config.discover_depth}), no fixed page list\n")
            self.crawl_discover(depth=self.config.discover_depth)
        else:
            for page in self.config.fixed_pages:
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
