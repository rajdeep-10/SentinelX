#!/usr/bin/env python3
"""
sentinelx.py — flag-based CLI, no interactive prompts.

Works the way nmap/gobuster/nikto/sqlmap/hydra do: give it a target
and flags, it runs, it prints results, it exits. No wizard, no
"is this DVWA?" questions.

USAGE EXAMPLES:

  # Recon only (headers, cookies, exposed paths, link discovery) —
  # works on ANY target immediately, no login, no setup:
  python3 sentinelx.py -u http://192.168.98.132

  # Recon + crawl to a specific depth:
  python3 sentinelx.py -u http://192.168.98.132 --depth 3

  # Targeted SQLi test against a known parameter (like sqlmap -u):
  python3 sentinelx.py -u "http://target/page.php?id=1" --sqli

  # Targeted SQLi with full exploitation (extract data):
  python3 sentinelx.py -u "http://target/page.php?id=1" --sqli --exploit

  # Brute-force a known login form (like hydra):
  python3 sentinelx.py -u http://target/login.php --brute \\
      -U admin --user-field username --pass-field password

  # Brute-force with a custom wordlist:
  python3 sentinelx.py -u http://target/login.php --brute \\
      -U admin --user-field username --pass-field password \\
      -w /usr/share/wordlists/rockyou.txt

  # Full authenticated scan (crawl + login + every module):
  python3 sentinelx.py -u http://target --login-url /login.php \\
      --user-field username --pass-field password \\
      -U admin -P password --full

  # DVWA shortcut (keeps the old convenience for the known target):
  python3 sentinelx.py -u http://127.0.0.1 --dvwa -U admin -P password --full

  # Command injection test on a known parameter:
  python3 sentinelx.py -u "http://target/exec.php" --cmdi \\
      --param ip --method post

  # Save a JSON report:
  python3 sentinelx.py -u http://target --full -o report.json
"""

import sys
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from colorama import Fore, init as colorama_init

from config import TargetConfig, DVWA_CONFIG, generic_config
from modules.crawler import Crawler
from modules.misconfig_scanner import MisconfigScanner
from modules.sqli_scanner import SQLiScanner
from modules.sqli_exploiter import SQLiExploiter
from modules.xss_scanner import XSSScanner
from modules.cookie_theft import CookieTheftExploit
from modules.cmdi_scanner import CommandInjectionScanner
from modules.csrf_scanner import CSRFScanner
from modules.file_upload import FileUploadScanner
from modules.idor_scanner import IDORScanner
from modules.brute_scanner import BruteForceScanner

colorama_init(autoreset=True)

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def build_parser():
    p = argparse.ArgumentParser(
        prog="sentinelx.py",
        description="SentinelX — web vulnerability scanner & exploitation framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-u", "--url", required=True, help="Target URL or IP")

    # Mode flags — pick what to run, like choosing a tool's mode
    p.add_argument("--recon", action="store_true",
                    help="Run recon only: misconfig scan + discovery crawl (default if no other mode given)")
    p.add_argument("--full", action="store_true",
                    help="Run recon + login (if creds given) + every applicable module")
    p.add_argument("--sqli", action="store_true", help="Run SQLi scan on the target URL/param")
    p.add_argument("--xss", action="store_true", help="Run XSS scan on the target URL/param")
    p.add_argument("--cmdi", action="store_true", help="Run command injection scan on the target URL/param")
    p.add_argument("--csrf", action="store_true", help="Run CSRF scan (requires a crawl first)")
    p.add_argument("--upload", action="store_true", help="Attempt file upload exploitation")
    p.add_argument("--idor", action="store_true", help="Run IDOR scan")
    p.add_argument("--brute", action="store_true", help="Brute-force a login form")
    p.add_argument("--misconfig", action="store_true", help="Run misconfiguration scan only")

    p.add_argument("--exploit", action="store_true",
                    help="For --sqli: also run full exploitation (extract data), not just detection")

    # Targeting for single-parameter modes (sqli/xss/cmdi), sqlmap-style
    p.add_argument("--param", help="Parameter name to test (for --sqli/--xss/--cmdi on a specific URL)")
    p.add_argument("--method", default="get", choices=["get", "post"],
                    help="HTTP method for --param-targeted tests (default: get)")
    p.add_argument("--data", help="Extra POST data as key=val&key2=val2 (used with --method post)")

    # Login / brute-force fields
    p.add_argument("--login-url", help="Login page path, e.g. /login.php")
    p.add_argument("--user-field", default="username", help="Login form username field name")
    p.add_argument("--pass-field", default="password", help="Login form password field name")
    p.add_argument("-U", "--username", default="admin", help="Username for login/brute-force")
    p.add_argument("-P", "--password", default="password", help="Password for login")
    p.add_argument("-w", "--wordlist", help="Wordlist path for --brute (default: small built-in list)")
    p.add_argument("--success-text", help="Text that appears on a SUCCESSFUL login response "
                    "(for --brute) — required for accurate results on non-DVWA targets")

    # Crawl control
    p.add_argument("--depth", type=int, default=2, help="Discovery crawl depth (default: 2)")

    # Convenience
    p.add_argument("--dvwa", action="store_true",
                    help="Use known DVWA config (login path, field names, security level)")

    p.add_argument("-o", "--output", help="Save JSON report to this path")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print findings, suppress progress noise")

    return p


def build_config(args):
    if args.dvwa:
        cfg = DVWA_CONFIG
        cfg.base_url = args.url.rstrip("/")
        return cfg

    if args.login_url:
        return TargetConfig(
            name="CLI Target",
            base_url=args.url.rstrip("/"),
            login_url=args.login_url,
            username_field=args.user_field,
            password_field=args.pass_field,
            token_field=None,
            extra_login_fields={},
            login_success_check="text",
            login_failure_text="incorrect",
            security_level_url=None,
            crawl_mode="discover",
            discover_depth=args.depth,
        )

    cfg = generic_config(args.url.rstrip("/"))
    cfg.discover_depth = args.depth
    return cfg


def parse_target_url(url):
    """Split a URL like http://target/page.php?id=1 into base and params,
    the way sqlmap's -u flag works."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    return base, params


def parse_data_string(data_str):
    result = {}
    if not data_str:
        return result
    for pair in data_str.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k] = v
    return result


def run_recon(config, quiet):
    findings = []
    crawler = Crawler(config=config)

    if not quiet:
        print(f"{Fore.CYAN}[*] Recon: misconfiguration scan...")
    misconfig = MisconfigScanner(crawler.session, base_url=config.base_url)
    findings.extend(misconfig.scan())

    if not quiet:
        print(f"\n{Fore.CYAN}[*] Recon: discovery crawl (depth {config.discover_depth})...")
    crawler.crawl_discover(depth=config.discover_depth)

    return findings, crawler


def run_targeted_sqli(args):
    """sqlmap-style: test ONE url/param directly, no crawling needed."""
    import requests
    base_url, url_params = parse_target_url(args.url)
    extra_params = parse_data_string(args.data)

    all_params = {**url_params, **extra_params}
    param_name = args.param or (next(iter(url_params.keys()), None))

    if not param_name:
        print(f"{Fore.RED}[-] No parameter to test — pass ?param=value in -u, or use --param NAME --data \"param=value\"")
        return []

    if param_name not in all_params:
        all_params[param_name] = "1"

    session = requests.Session()
    form = {
        "action": base_url,
        "method": args.method,
        "inputs": [{"name": k, "type": "text", "value": v} for k, v in all_params.items()]
    }
    discovered_forms = {base_url: [form]}

    scanner = SQLiScanner(session)
    findings = scanner.scan_all(discovered_forms)

    if findings and args.exploit:
        print(f"\n{Fore.CYAN}[*] Running exploitation on confirmed SQLi...")
        exploiter = SQLiExploiter(session)
        for f in findings:
            exploiter.exploit(f["url"], f["parameter"], all_params)

    return findings


def run_targeted_xss(args):
    import requests
    base_url, url_params = parse_target_url(args.url)
    extra_params = parse_data_string(args.data)
    all_params = {**url_params, **extra_params}
    param_name = args.param or next(iter(url_params.keys()), None)

    if not param_name:
        print(f"{Fore.RED}[-] No parameter to test — pass ?param=value in -u, or use --param NAME --data \"param=value\"")
        return []

    if param_name not in all_params:
        all_params[param_name] = "test"

    session = requests.Session()
    form = {
        "action": base_url,
        "method": args.method,
        "inputs": [{"name": k, "type": "text", "value": v} for k, v in all_params.items()]
    }
    discovered_forms = {base_url: [form]}

    scanner = XSSScanner(session)
    return scanner.scan_all(discovered_forms)


def run_targeted_cmdi(args):
    import requests
    base_url, url_params = parse_target_url(args.url)
    extra_params = parse_data_string(args.data)
    all_params = {**url_params, **extra_params}
    param_name = args.param or next(iter(url_params.keys()), None)

    if not param_name:
        print(f"{Fore.RED}[-] No parameter to test — pass ?param=value in -u, or use --param NAME --data \"param=value\"")
        return []

    if param_name not in all_params:
        all_params[param_name] = "127.0.0.1"

    session = requests.Session()
    form = {
        "action": base_url,
        "method": args.method,
        "inputs": [{"name": k, "type": "text", "value": v} for k, v in all_params.items()]
    }
    discovered_forms = {base_url: [form]}

    scanner = CommandInjectionScanner(session)
    return scanner.scan_all(discovered_forms)


def run_brute(args, config):
    session_obj = Crawler(config=config).session
    scanner = BruteForceScanner(session_obj, base_url=config.base_url, config=config)

    # Override with CLI-provided field names/URL directly, sqlmap/hydra-style
    if args.login_url:
        scanner.brute_url = config.full_url(args.login_url)
    scanner.username_field = args.user_field
    scanner.password_field = args.pass_field

    if args.success_text:
        scanner.success_indicator = args.success_text
    elif not args.dvwa:
        print(f"{Fore.YELLOW}[!] No --success-text given for a non-DVWA target — "
              f"results will likely all show as 'Failed' even on a real success.")
        print(f"{Fore.YELLOW}    Check one real login response first, then pass e.g. "
              f"--success-text \"Welcome\"\n")

    return scanner.scan(username=args.username, wordlist_path=args.wordlist)


def compute_risk_score(findings):
    total = sum(SEVERITY_WEIGHT.get(f.get("severity", "LOW"), 1) for f in findings)
    return min(total, 100)


def print_summary(findings, quiet):
    if not findings:
        print(f"\n{Fore.YELLOW}[*] No findings.")
        return

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    risk = compute_risk_score(findings)
    color = Fore.RED if risk >= 50 else (Fore.YELLOW if risk >= 20 else Fore.GREEN)

    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Fore.WHITE}Total findings: {len(findings)}   Risk score: {color}{risk}/100")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_counts:
            print(f"{Fore.WHITE}  {sev:<10} {severity_counts[sev]}")
    print(f"{Fore.CYAN}{'='*50}")


def save_report(findings, path, target):
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "risk_score": compute_risk_score(findings),
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"{Fore.GREEN}[+] Report saved: {path}")


def main():
    args = build_parser().parse_args()
    all_findings = []

    any_specific_mode = any([args.sqli, args.xss, args.cmdi, args.csrf,
                              args.upload, args.idor, args.brute,
                              args.misconfig, args.full])

    config = build_config(args)

    # --- Targeted single-parameter modes (sqlmap-style, no crawl needed) ---
    if args.sqli and args.param or (args.sqli and "?" in args.url):
        all_findings.extend(run_targeted_sqli(args))
    elif args.sqli:
        # No specific param given and no query string — fall back to
        # crawling first, then scanning discovered forms
        findings, crawler = run_recon(config, args.quiet)
        all_findings.extend(findings)
        all_findings.extend(SQLiScanner(crawler.session).scan_all(crawler.discovered_forms))

    if args.xss and (args.param or "?" in args.url):
        all_findings.extend(run_targeted_xss(args))
    elif args.xss:
        findings, crawler = run_recon(config, args.quiet)
        all_findings.extend(findings)
        all_findings.extend(XSSScanner(crawler.session).scan_all(crawler.discovered_forms))

    if args.cmdi and (args.param or "?" in args.url):
        all_findings.extend(run_targeted_cmdi(args))
    elif args.cmdi:
        findings, crawler = run_recon(config, args.quiet)
        all_findings.extend(findings)
        all_findings.extend(CommandInjectionScanner(crawler.session).scan_all(crawler.discovered_forms))

    if args.brute:
        all_findings.extend(run_brute(args, config))

    if args.misconfig:
        import requests
        session = requests.Session()
        all_findings.extend(MisconfigScanner(session, base_url=config.base_url).scan())

    # --- Full mode: recon + login (if creds work) + every applicable module ---
    if args.full:
        findings, crawler = run_recon(config, args.quiet)
        all_findings.extend(findings)

        logged_in = False
        if args.login_url or args.dvwa:
            logged_in = crawler.login(username=args.username, password=args.password)
            if logged_in:
                if config.security_level_url:
                    crawler.set_security_level("low")
                crawler.crawl_all()

        forms = crawler.discovered_forms
        all_findings.extend(SQLiScanner(crawler.session).scan_all(forms))
        all_findings.extend(XSSScanner(crawler.session).scan_all(forms))
        all_findings.extend(CommandInjectionScanner(crawler.session).scan_all(forms))
        all_findings.extend(CSRFScanner(crawler.session, base_url=config.base_url).scan_all(forms))
        all_findings.extend(IDORScanner(crawler.session, base_url=config.base_url, config=config).scan_all(forms))

    # --- Default: plain recon if nothing else was specified ---
    if not any_specific_mode:
        findings, _ = run_recon(config, args.quiet)
        all_findings.extend(findings)

    print_summary(all_findings, args.quiet)

    if args.output:
        save_report(all_findings, args.output, config.base_url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted")
        sys.exit(0)
