import requests
from colorama import Fore, init
import random
import string

init(autoreset=True)

class XSSScanner:
    def __init__(self, session):
        self.session = session
        self.findings = []

    def _generate_token(self):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _build_payloads(self, token):
        return [
            {
                "payload": f"<script>alert('{token}')</script>",
                "variant": "basic script tag"
            },
            {
                "payload": f"<img src=x onerror=alert('{token}')>",
                "variant": "event handler (onerror) - bypasses filters that only block <script>"
            },
            {
                "payload": f"<ScRiPt>alert('{token}')</sCriPt>",
                "variant": "mixed case - bypasses naive case-sensitive filters"
            },
        ]

    def test_input(self, url, method, param_name, other_params):
        token = self._generate_token()
        payloads = self._build_payloads(token)

        for p in payloads:
            test_params = other_params.copy()
            test_params[param_name] = p["payload"]

            try:
                if method == "post":
                    resp = self.session.post(url, data=test_params, timeout=10)
                else:
                    resp = self.session.get(url, params=test_params, timeout=10)
            except requests.exceptions.RequestException:
                continue

            if p["payload"] in resp.text:
                return {
                    "variant": p["variant"],
                    "payload": p["payload"],
                    "token": token
                }

        return None

    def scan_form(self, url, form):
        method = form["method"]
        inputs = form["inputs"]

        base_params = {inp["name"]: inp.get("value", "test") for inp in inputs}

        for inp in inputs:
            param_name = inp["name"]

            if inp["type"] in ("submit", "hidden") or "token" in param_name.lower():
                continue

            result = self.test_input(url, method, param_name, base_params)

            if result:
                finding = {
                    "type": "XSS_REFLECTED",
                    "severity": "CRITICAL",
                    "url": url,
                    "parameter": param_name,
                    "method": method,
                    "variant_confirmed": result["variant"],
                    "evidence": f"payload reflected unescaped: {result['payload']}"
                }
                self.findings.append(finding)

                print(f"{Fore.RED}[!] XSS found -> {url}  param='{param_name}'  "
                      f"variant='{result['variant']}'")

    def scan_all(self, discovered_forms):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   XSS (REFLECTED) SCAN")
        print(f"{Fore.CYAN}{'='*55}\n")

        for url, forms in discovered_forms.items():
            for form in forms:
                self.scan_form(form["action"], form)

        print(f"\n{Fore.CYAN}[*] XSS scan complete: {len(self.findings)} finding(s)")
        return self.findings
