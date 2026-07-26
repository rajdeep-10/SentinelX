import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
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
    # AUTO-DETECT LOGIN — inspects a page for a login form and
    # extracts its real field names automatically. This is what
    # removes the need to hand-write a TargetConfig for a new
    # target: point this at any URL with a login form and it
    # figures out the field names itself.
    # ─────────────────────────────────────────────
    def detect_login_form(self, page_url=None):
        """
        Fetches page_url (or self.base_url if not given), finds the
        first <form> containing a password-type input, and returns
        a dict describing it: {form_url, method, username_field,
        password_field, token_field, extra_fields} — or None if no
        login-shaped form is found on that page.

        This does NOT know your actual username/password — only the
        form's structure. You still supply real credentials, same as
        typing them into a browser yourself.
        """
        url = page_url or self.base_url

        try:
            resp = self.session.get(url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Could not fetch {url} to detect a login form: {e}")
            return None

        soup = BeautifulSoup(resp.text, "html.parser")

        for form in soup.find_all("form"):
            password_input = form.find("input", {"type": "password"})
            if not password_input:
                continue

            password_field = password_input.get("name")
            if not password_field:
                continue

            # Username field: first text/email input in the same form
            username_input = form.find("input", {"type": ["text", "email"]})
            if not username_input or not username_input.get("name"):
                # Some login forms omit type="text" (defaults to text) —
                # fall back to the first input with a name that isn't
                # the password field and isn't a hidden csrf-looking field
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    itype = inp.get("type", "text")
                    if name and name != password_field and itype not in ("submit", "hidden"):
                        username_input = inp
                        break

            if not username_input or not username_input.get("name"):
                continue  # can't find a username-shaped field, not a usable login form

            username_field = username_input.get("name")

            # Any hidden field is treated as a token/extra field to carry
            # through automatically (CSRF tokens, etc.)
            token_field = None
            extra_fields = {}
            for inp in form.find_all("input", {"type": "hidden"}):
                name = inp.get("name")
                if not name:
                    continue
                if token_field is None:
                    token_field = name  # first hidden field, refreshed at login time
                else:
                    extra_fields[name] = inp.get("value", "")

            # <select> dropdowns need a value too, or the form submission
            # is incomplete (e.g. bWAPP's security_level dropdown) — send
            # the first <option>'s value as a sane default
            for select in form.find_all("select"):
                name = select.get("name")
                if not name:
                    continue
                first_option = select.find("option")
                if first_option is not None:
                    extra_fields[name] = first_option.get("value", first_option.text.strip())

            # Submit control — some forms use <input type="submit">,
            # others use <button type="submit"> (bWAPP does the latter)
            submit = form.find("input", {"type": "submit"}) or form.find("button", {"type": "submit"})
            if submit and submit.get("name"):
                extra_fields[submit.get("name")] = submit.get("value", "Submit")

            action = form.get("action", "")
            form_url = urljoin(url, action) if action else url
            method = form.get("method", "post").lower()

            print(f"{Fore.GREEN}[+] Detected login form at {form_url}")
            print(f"{Fore.GREEN}    username field: '{username_field}'  "
                  f"password field: '{password_field}'"
                  + (f"  token field: '{token_field}'" if token_field else ""))

            return {
                "form_url": form_url,
                "method": method,
                "username_field": username_field,
                "password_field": password_field,
                "token_field": token_field,
                "extra_fields": extra_fields,
            }

        print(f"{Fore.YELLOW}[?] No login form with a password field found on {url}")
        return None

    def login_auto(self, username, password, page_url=None):
        """
        Detects a login form on page_url (or self.base_url), then
        logs in using whatever field names it found — no TargetConfig
        needed for this target's login flow. Returns True/False.
        """
        detected = self.detect_login_form(page_url)
        if detected is None:
            return False

        login_data = {
            detected["username_field"]: username,
            detected["password_field"]: password,
        }
        login_data.update(detected["extra_fields"])

        csrf_value = None
        if detected["token_field"]:
            # Re-fetch to get a fresh token value (forms often rotate
            # tokens per-request, so the one from detect isn't safe to reuse)
            try:
                resp = self.session.get(page_url or self.base_url, timeout=10)
                soup = BeautifulSoup(resp.text, "html.parser")
                token_input = soup.find("input", {"name": detected["token_field"]})
                if token_input:
                    csrf_value = token_input.get("value", "")
                    login_data[detected["token_field"]] = csrf_value
            except requests.exceptions.RequestException:
                pass

        try:
            if detected["method"] == "get":
                resp = self.session.get(detected["form_url"], params=login_data, timeout=10)
            else:
                resp = self.session.post(detected["form_url"], data=login_data, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Login request failed: {e}")
            return False

        # No target-specific success string to check against — use a
        # simple heuristic: if the response no longer contains a
        # password field, assume login succeeded (redirected to a
        # logged-in page). Not perfect, but works on most real apps
        # and is honest about being a heuristic, not a guarantee.
        still_has_password_field = 'type="password"' in resp.text or "type='password'" in resp.text

        if still_has_password_field:
            print(f"{Fore.RED}[-] Login likely failed — page still shows a password field "
                  f"(wrong credentials, or this app needs manual verification)")
            return False

        print(f"{Fore.GREEN}[+] Login appears successful (no password field in response)")
        self.logged_in = True
        return True

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

        # URL query-string parameters, sqlmap-style: any link like
        # page.php?id=1 is itself a scannable target, independent of
        # whether the page also has an HTML <form>. This is what lets
        # SentinelX test parameters on pages that take input purely via
        # GET (e.g. test.php?file=..., page.php?id=...) without needing
        # a form or a login — same as `sqlmap -u "url?param=value"`.
        parsed_self = urlparse(url)
        if parsed_self.query:
            qs_params = parse_qs(parsed_self.query)
            if qs_params:
                base_no_query = url.split("?")[0]
                forms_on_page.append({
                    "action": base_no_query,
                    "method": "get",
                    "inputs": [
                        {"name": name, "type": "text", "value": vals[0] if vals else ""}
                        for name, vals in qs_params.items()
                    ],
                    "source": "url_param"  # distinguishes from a real <form>
                })

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
    # Common parameter names worth probing on any page that took no
    # query string of its own — this is what catches something like
    # test.php?file=... when nothing links to it with that parameter
    # already attached. Not exhaustive (that's what dedicated param
    # fuzzers like Arjun/ParamSpider are for), but catches the most
    # common real-world cases without needing prior knowledge of the
    # target's parameter names.
    COMMON_PARAM_NAMES = [
        "id", "file", "page", "path", "view", "cat", "category",
        "search", "q", "query", "name", "user", "username", "url",
        "redirect", "next", "return", "dir", "doc", "document",
    ]

    def probe_common_params(self, url):
        """For a page with no query string, try each common param
        name with a unique marker and check whether that exact
        marker gets reflected back. Before trusting this signal at
        all, first check with a parameter name that cannot possibly
        be real (a long random string) — if ITS marker also gets
        reflected, the page echoes back whatever you send it
        regardless of parameter name (e.g. a debug $_GET dump), and
        no marker-reflection signal from this page can be trusted at
        all. In that case, we correctly report nothing rather than
        every parameter."""
        fake_param = "zzz_definitely_not_a_real_param_9f3a"
        fake_marker = "sxfakecheck9f3a"

        try:
            fake_resp = self.session.get(url, params={fake_param: fake_marker}, timeout=10)
        except requests.exceptions.RequestException:
            return []

        if fake_marker in fake_resp.text:
            # This page echoes ANY parameter's value regardless of
            # name — marker reflection can't distinguish real params
            # from fake ones here, so don't report any as "found"
            return []

        found_params = []
        for i, param in enumerate(self.COMMON_PARAM_NAMES):
            marker = f"sx{i:03d}q7z9f3a"
            try:
                resp = self.session.get(url, params={param: marker}, timeout=10)
            except requests.exceptions.RequestException:
                continue

            if marker in resp.text:
                found_params.append(param)

        return found_params

    # Small built-in fallback wordlist for path brute-forcing when no
    # external wordlist is given — covers common real-world names so
    # this still finds something with zero setup. For a real engagement,
    # pass a real wordlist (e.g. dirb's common.txt) instead.
    BUILTIN_PATH_WORDLIST = [
        "admin", "login", "test", "config", "backup", "uploads", "upload",
        "images", "img", "css", "js", "api", "panel", "dashboard",
        "user", "users", "account", "profile", "settings", "search",
        "add", "edit", "delete", "view", "show", "list", "index",
        "home", "about", "contact", "info", "help", "docs", "download",
        "file", "files", "data", "db", "database", "sql", "phpmyadmin",
        "wp-admin", "wp-login", "administrator", "manage", "manager",
        "console", "debug", "dev", "staging", "old", "bak", "tmp",
        "temp", "log", "logs", "error", "errors", "auth", "register",
        "signup", "reset", "forgot", "logout", "session", "token",
        "c", "in", "out", "go", "redirect", "include", "inc",
    ]

    def brute_force_paths(self, wordlist_path=None, extensions=None):
        """Probes common (or wordlist-supplied) paths to find pages
        that aren't linked anywhere — e.g. test.php on a CTF box.
        Same purpose as gobuster/dirb, built in so recon finds these
        on its own. Returns [(path, status_code), ...] for non-404s."""
        extensions = extensions or ["", ".php", ".html", ".txt"]

        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Fore.YELLOW}[!] Wordlist not found: {wordlist_path} — "
                      f"using small built-in list instead")
                words = self.BUILTIN_PATH_WORDLIST
        else:
            words = self.BUILTIN_PATH_WORDLIST

        print(f"{Fore.BLUE}[*] Brute-forcing paths ({len(words)} words x "
              f"{len(extensions)} extension(s) = {len(words) * len(extensions)} requests)...")

        found_paths = []
        for word in words:
            for ext in extensions:
                candidate = f"{word}{ext}"
                url = f"{self.base_url}/{candidate}"
                try:
                    resp = self.session.get(url, timeout=6, allow_redirects=False)
                except requests.exceptions.RequestException:
                    continue

                if resp.status_code != 404:
                    found_paths.append((candidate, resp.status_code))
                    print(f"{Fore.GREEN}[+] Found: /{candidate}  (HTTP {resp.status_code})")

        print(f"{Fore.CYAN}[*] Path brute-force complete: {len(found_paths)} path(s) found")
        return found_paths

    def crawl_discover(self, depth=2, probe_params=True, brute_force=True, wordlist_path=None):
        # Path brute-force FIRST — this is what finds pages like
        # test.php that nothing links to, so link-following + param
        # probing below have more real pages to work with
        if brute_force:
            found_paths = self.brute_force_paths(wordlist_path=wordlist_path)
            for candidate, status in found_paths:
                if status < 400:  # skip 403/401 — can't productively crawl those
                    full_url = f"{self.base_url}/{candidate}"
                    if full_url not in self.visited_urls:
                        self.crawl_page(candidate)
                        if probe_params:
                            found_params = self.probe_common_params(full_url)
                            if found_params:
                                print(f"{Fore.GREEN}[+] {full_url} accepts "
                                      f"parameter(s): {', '.join(found_params)}")
                                self.discovered_forms.setdefault(full_url, [])
                                self.discovered_forms[full_url].append({
                                    "action": full_url,
                                    "method": "get",
                                    "inputs": [{"name": p, "type": "text", "value": "1"}
                                               for p in found_params],
                                    "source": "param_probe"
                                })

        to_visit = [(self.base_url, 0)]
        visited_for_bfs = set()

        while to_visit:
            url, current_depth = to_visit.pop(0)

            if url in visited_for_bfs or current_depth > depth:
                continue
            visited_for_bfs.add(url)

            path = url.replace(self.base_url, "").lstrip("/")
            links = self.crawl_page(path)

            # If this page had no query string of its own, probe it
            # for common hidden parameters (e.g. test.php with no
            # visible ?file= anywhere, but the page actually uses one)
            if probe_params and "?" not in url:
                found = self.probe_common_params(url)
                if found:
                    print(f"{Fore.GREEN}[+] {url} accepts parameter(s) not "
                          f"visible in any link: {', '.join(found)}")
                    self.discovered_forms.setdefault(url, [])
                    self.discovered_forms[url].append({
                        "action": url,
                        "method": "get",
                        "inputs": [{"name": p, "type": "text", "value": "1"} for p in found],
                        "source": "param_probe"
                    })

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
