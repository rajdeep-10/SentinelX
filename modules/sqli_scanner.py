import requests
from colorama import Fore, init
import re
import time

init(autoreset=True)

class SQLiScanner:
    ERROR_SIGNATURES = [
        "sql syntax",
        "mysql_fetch",
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sqlstate",
        "pg_query()",
        "sqlite3.operationalerror",
    ]

    def __init__(self, session):
        self.session = session
        self.findings = []

    def test_error_based(self, url, method, param_name, other_params):
        payload = "'"

        test_params = other_params.copy()
        test_params[param_name] = payload

        try:
            if method == "post":
                resp = self.session.post(url, data=test_params, timeout=10)
            else:
                resp = self.session.get(url, params=test_params, timeout=10)
        except requests.exceptions.RequestException:
            return None

        body_lower = resp.text.lower()

        for signature in self.ERROR_SIGNATURES:
            if signature in body_lower:
                return {
                    "technique": "error-based",
                    "evidence": signature,
                    "confidence": "high"
                }

        return None

    def test_boolean_blind(self, url, method, param_name, other_params):
        true_payload  = "' OR '1'='1"
        false_payload = "' AND '1'='2"

        true_params = other_params.copy()
        true_params[param_name] = true_payload

        false_params = other_params.copy()
        false_params[param_name] = false_payload

        try:
            if method == "post":
                resp_true  = self.session.post(url, data=true_params, timeout=10)
                resp_false = self.session.post(url, data=false_params, timeout=10)
            else:
                resp_true  = self.session.get(url, params=true_params, timeout=10)
                resp_false = self.session.get(url, params=false_params, timeout=10)
        except requests.exceptions.RequestException:
            return None

        len_true  = len(resp_true.text)
        len_false = len(resp_false.text)

        length_diff = abs(len_true - len_false)

        if length_diff > 20:
            return {
                "technique": "boolean-blind",
                "evidence": f"response length differs by {length_diff} bytes "
                             f"(true={len_true}, false={len_false})",
                "confidence": "high"
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

            error_result = self.test_error_based(url, method, param_name, base_params)
            blind_result  = self.test_boolean_blind(url, method, param_name, base_params)

            if error_result or blind_result:
                techniques_hit = [r["technique"] for r in [error_result, blind_result] if r]

                severity = "CRITICAL" if len(techniques_hit) == 2 else "HIGH"

                finding = {
                    "type": "SQL_INJECTION",
                    "severity": severity,
                    "url": url,
                    "parameter": param_name,
                    "method": method,
                    "techniques_confirmed": techniques_hit,
                    "evidence": [r["evidence"] for r in [error_result, blind_result] if r]
                }
                self.findings.append(finding)

                print(f"{Fore.RED}[!] SQLi found -> {url}  param='{param_name}'  "
                      f"techniques={techniques_hit}  severity={severity}")

    def scan_all(self, discovered_forms):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   SQL INJECTION SCAN")
        print(f"{Fore.CYAN}{'='*55}\n")

        for url, forms in discovered_forms.items():
            for form in forms:
                self.scan_form(form["action"], form)

        print(f"\n{Fore.CYAN}[*] SQLi scan complete: {len(self.findings)} finding(s)")
        return self.findings
