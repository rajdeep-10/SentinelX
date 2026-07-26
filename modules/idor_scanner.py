import requests
from colorama import Fore, init
from bs4 import BeautifulSoup

init(autoreset=True)


class IDORScanner:
    """
    Detects Insecure Direct Object Reference (IDOR) vulnerabilities by
    tampering with ID-like parameters and checking whether the server
    returns different users' data without any ownership/authorization
    check.
    """

    ID_PARAM_NAMES = ["id", "user_id", "uid", "account_id", "record_id",
                       "order_id", "invoice_id", "profile_id"]

    def __init__(self, session, base_url="http://127.0.0.1", config=None):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.findings = []

        if config is not None:
            if config.idor_direct_url:
                self.direct_url = config.full_url(config.idor_direct_url)
                self.direct_param = config.idor_direct_param
                self.direct_id_range = config.idor_id_range
            else:
                # A real config was given (DVWA or custom) but it has no
                # direct-test target configured — don't run the direct
                # test at all rather than silently falling back to
                # DVWA's specific page, which would be wrong on any
                # other target
                self.direct_url = None
                self.direct_param = None
                self.direct_id_range = []
        else:
            # No config given at all (old-style call, e.g. standalone
            # test scripts) — keep the original DVWA default for
            # backward compatibility
            self.direct_url = f"{self.base_url}/vulnerabilities/sqli/"
            self.direct_param = "id"
            self.direct_id_range = ["1", "2", "3", "4", "5"]

    def looks_like_id(self, param_name, param_value):
        name = param_name.lower()
        if any(idname == name for idname in self.ID_PARAM_NAMES):
            return True
        if param_value.isdigit():
            return True
        return False

    def test_parameter(self, url, method, param_name, original_value, base_params):
        try:
            original_int = int(original_value)
        except (ValueError, TypeError):
            original_int = 1

        try:
            if method == "post":
                baseline_resp = self.session.post(url, data=base_params, timeout=10)
            else:
                baseline_resp = self.session.get(url, params=base_params, timeout=10)
        except requests.exceptions.RequestException:
            return None

        baseline_text = baseline_resp.text
        baseline_len = len(baseline_text)

        test_values = [str(original_int + 1), str(max(original_int - 1, 1))]

        for test_val in test_values:
            test_params = dict(base_params)
            test_params[param_name] = test_val

            try:
                if method == "post":
                    test_resp = self.session.post(url, data=test_params, timeout=10)
                else:
                    test_resp = self.session.get(url, params=test_params, timeout=10)
            except requests.exceptions.RequestException:
                continue

            test_text = test_resp.text
            test_len = len(test_text)

            # Meaningful content difference — not just whitespace or
            # timestamp differences — indicates different data returned
            length_diff = abs(baseline_len - test_len)

            # Also check if the page content changed significantly
            # by comparing a clean text extract
            baseline_soup = BeautifulSoup(baseline_text, "html.parser")
            test_soup = BeautifulSoup(test_text, "html.parser")

            baseline_content = baseline_soup.get_text(strip=True)
            test_content = test_soup.get_text(strip=True)

            content_changed = (
                baseline_content != test_content and
                length_diff > 30
            )

            # Additional check: make sure we're not just seeing a
            # generic "not found" or error page for the modified ID
            error_indicators = ["not found", "invalid", "error",
                                 "does not exist", "no record"]
            test_has_error = any(
                e in test_content.lower() for e in error_indicators
            )

            if content_changed and not test_has_error:
                return {
                    "original_id": original_int,
                    "tampered_id": test_val,
                    "length_diff": length_diff,
                    "evidence": f"Response changed by {length_diff} bytes when ID changed from {original_int} to {test_val}"
                }

        return None

    def scan_all(self, discovered_forms):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   IDOR VULNERABILITY SCAN")
        print(f"{Fore.CYAN}{'='*55}\n")

        # Check forms for ID-like parameters
        for url, forms in discovered_forms.items():
            for form in forms:
                method = form["method"]
                inputs = form["inputs"]
                base_params = {
                    inp["name"]: inp.get("value", "1")
                    for inp in inputs
                }

                for inp in inputs:
                    param_name = inp["name"]
                    param_value = inp.get("value", "")

                    if not self.looks_like_id(param_name, param_value):
                        # Try with a default value of "1" for params
                        # that look like IDs by name even if no default
                        if any(idname == param_name.lower()
                               for idname in self.ID_PARAM_NAMES):
                            param_value = "1"
                        else:
                            continue

                    print(f"{Fore.BLUE}[*] Testing IDOR: {url} param='{param_name}' value='{param_value}'")

                    result = self.test_parameter(
                        url, method, param_name,
                        param_value, base_params
                    )

                    if result:
                        print(f"{Fore.RED}[!] IDOR found -> {url} param='{param_name}'")
                        print(f"{Fore.YELLOW}    {result['evidence']}")

                        self.findings.append({
                            "type":      "IDOR",
                            "severity":  "HIGH",
                            "url":       url,
                            "parameter": param_name,
                            "method":    method,
                            "evidence":  result["evidence"]
                        })
                    else:
                        print(f"{Fore.GREEN}[+] No IDOR detected on '{param_name}' in {url}")

        # Also test the configured "known good" direct-enumeration target
        # (defaults to DVWA's SQLi page, which uses ?id= as a classic
        # IDOR test target). Skipped entirely if no such target is
        # configured for this target.
        if self.direct_url and self.direct_id_range:
            print(f"\n{Fore.BLUE}[*] Testing {self.direct_url} "
                  f"'{self.direct_param}' parameter directly...")
            for test_id in self.direct_id_range:
                try:
                    resp = self.session.get(
                        self.direct_url,
                        params={self.direct_param: test_id, "Submit": "Submit"},
                        timeout=10
                    )
                    soup = BeautifulSoup(resp.text, "html.parser")
                    pre = soup.find("pre")
                    if pre:
                        content = pre.get_text(strip=True)
                        if content:
                            print(f"{Fore.RED}[!] {self.direct_param}={test_id} returns data: {content[:80]}")
                            self.findings.append({
                                "type":      "IDOR",
                                "severity":  "HIGH",
                                "url":       self.direct_url,
                                "parameter": self.direct_param,
                                "method":    "get",
                                "evidence":  f"Authenticated user can access any user's record by changing {self.direct_param}={test_id} — no ownership check: {content[:80]}"
                            })
                except requests.exceptions.RequestException:
                    continue

        if not self.findings:
            print(f"{Fore.YELLOW}[?] No clear IDOR findings")
            if self.direct_url and "vulnerabilities/sqli" in self.direct_url:
                print(f"{Fore.YELLOW}    DVWA's design doesn't expose clean IDOR via forms —")
                print(f"{Fore.YELLOW}    the SQLi page's ?id= parameter is the closest analog")
                print(f"{Fore.YELLOW}    (unauthorized data access is better demonstrated via SQLi extraction)")

        print(f"\n{Fore.CYAN}[*] IDOR scan complete: {len(self.findings)} finding(s)")
        return self.findings
