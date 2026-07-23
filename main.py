#!/usr/bin/env python3
"""
SentinelX — Unified CLI

Guided workflow:
  1. Ask for target IP/URL (and optional login info if known)
  2. RECON PHASE (always runs, no setup needed):
       - misconfig_scanner  (headers, cookie flags, exposed paths)
       - crawler in discovery mode (follows links, finds forms)
     This works on ANY target the moment you give it an IP —
     THM, HTB, VulnHub, whatever.
  3. Shows what was found, so the choices in step 4 are informed
     by real recon instead of guessed blind.
  4. Module picker (arrow keys + spacebar) — pick which modules to
     run against the discovered forms.
  5. Manual or Automatic mode.
  6. Runs selected modules, aggregates findings, saves a report.

Run:  python3 main.py
"""

import sys
import json
import time
from datetime import datetime

import questionary
from questionary import Style
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
from modules.hash_cracker import HashCracker

colorama_init(autoreset=True)

BANNER = r"""
 ██████  ████████ ██    ██ ████████ ████ ██    ██ ████████ ██       ██     ██ 
██    ██ ██       ███   ██    ██     ██  ███   ██ ██       ██        ██   ██  
██       ██       ████  ██    ██     ██  ████  ██ ██       ██         ██ ██   
 ██████  ██████   ██ ██ ██    ██     ██  ██ ██ ██ ██████   ██          ███    
      ██ ██       ██  ████    ██     ██  ██  ████ ██       ██         ██ ██   
██    ██ ██       ██   ███    ██     ██  ██   ███ ██       ██        ██   ██  
 ██████  ████████ ██    ██    ██    ████ ██    ██ ████████ ████████ ██     ██ 
"""

QUESTIONARY_STYLE = Style([
    ('qmark', 'fg:#e3b341 bold'),
    ('question', 'bold'),
    ('pointer', 'fg:#3fb950 bold'),
    ('highlighted', 'fg:#3fb950 bold'),
    ('selected', 'fg:#58a6ff'),
    ('answer', 'fg:#3fb950 bold'),
])

# Modules that need an authenticated crawl+form set to operate on
MODULE_CHOICES = [
    {"name": "sqli",     "label": "SQL Injection",        "severity": "CRIT"},
    {"name": "xss",      "label": "XSS (Reflected)",      "severity": "CRIT"},
    {"name": "cmdi",     "label": "Command Injection",    "severity": "CRIT"},
    {"name": "csrf",     "label": "CSRF",                 "severity": "HIGH"},
    {"name": "upload",   "label": "File Upload",          "severity": "HIGH"},
    {"name": "idor",     "label": "IDOR",                 "severity": "HIGH"},
    {"name": "brute",    "label": "Brute Force Login",    "severity": "HIGH"},
]

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def print_banner():
    print(f"{Fore.RED}{BANNER}")
    print(f"{Fore.CYAN}   web application vulnerability scanner & exploitation framework{Fore.WHITE}   v2.0\n")


def print_status_bar(config, logged_in=False, form_count=0):
    bar_width = 66
    print(f"{Fore.WHITE}{'─'*bar_width}")
    status_line = (
        f"{Fore.WHITE}target {Fore.CYAN}{config.base_url:<28}"
        f"{Fore.WHITE} auth {(Fore.GREEN + '● active') if logged_in else (Fore.YELLOW + '○ none')}"
        f"{Fore.WHITE}   forms {Fore.YELLOW}{form_count}"
    )
    print(status_line)
    print(f"{Fore.WHITE}{'─'*bar_width}\n")


def section(title):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}   {title}")
    print(f"{Fore.CYAN}{'='*60}\n")


def ask_target():
    """Step 1 — get the target. Minimal friction: just an IP/URL
    is enough to start recon. Login info is optional and can be
    added later if the recon phase finds a login form."""
    print(f"{Fore.YELLOW}SentinelX works in two phases:")
    print(f"{Fore.YELLOW}  1) RECON  — needs only a target IP/URL. Works on any box.")
    print(f"{Fore.YELLOW}  2) DEEPER SCANNING/EXPLOITATION — some modules need to log in first.")
    print(f"{Fore.YELLOW}     If you don't know the target's login setup yet, skip it — you")
    print(f"{Fore.YELLOW}     can still run recon now and come back once you've found it.\n")

    target = questionary.text(
        "Target IP or URL (e.g. 10.10.11.23 or http://10.10.11.23):",
        style=QUESTIONARY_STYLE
    ).ask()

    if not target:
        print(f"{Fore.RED}[-] No target given — exiting")
        sys.exit(1)

    if not target.startswith("http"):
        target = f"http://{target}"

    is_dvwa = questionary.confirm(
        "Is this a DVWA instance? (uses known DVWA login/paths automatically)",
        default=False,
        style=QUESTIONARY_STYLE
    ).ask()

    if is_dvwa:
        cfg = DVWA_CONFIG
        cfg.base_url = target.rstrip("/")
        return cfg

    has_login = questionary.confirm(
        "Do you already know a login form/URL on this target?",
        default=False,
        style=QUESTIONARY_STYLE
    ).ask()

    if not has_login:
        return generic_config(target.rstrip("/"))

    login_path = questionary.text(
        "Login page path (e.g. /login.php or /admin/login):",
        style=QUESTIONARY_STYLE
    ).ask()
    user_field = questionary.text(
        "Username field name (check the form's HTML, e.g. 'username'):",
        default="username", style=QUESTIONARY_STYLE
    ).ask()
    pass_field = questionary.text(
        "Password field name (e.g. 'password'):",
        default="password", style=QUESTIONARY_STYLE
    ).ask()

    return TargetConfig(
        name="Custom Target",
        base_url=target.rstrip("/"),
        login_url=login_path,
        username_field=user_field,
        password_field=pass_field,
        token_field=None,
        extra_login_fields={},
        login_success_check="text",
        login_failure_text="incorrect",
        security_level_url=None,
        crawl_mode="discover",
        discover_depth=2,
    )


def run_recon(config):
    """Step 2 — always-works recon: misconfig scan + discovery crawl.
    Needs no login, no prior knowledge of the target's structure."""
    section("PHASE 1: RECON (no login required)")

    session_crawler = Crawler(config=config)
    session_crawler.session.headers.update({"User-Agent": "SentinelX/2.0"})

    print(f"{Fore.BLUE}[*] Running misconfiguration scan...")
    misconfig = MisconfigScanner(session_crawler.session, base_url=config.base_url)
    misconfig_findings = misconfig.scan()

    print(f"\n{Fore.BLUE}[*] Running discovery crawl (unauthenticated)...")
    unauth_forms = {}
    if config.crawl_mode == "discover":
        session_crawler.crawl_discover(depth=config.discover_depth)
        unauth_forms = session_crawler.discovered_forms

    return misconfig_findings, unauth_forms


def attempt_login(config):
    """Step 3 — try to log in if config has login info. Returns a
    logged-in Crawler, or None if login isn't configured/fails."""
    if config.login_url is None:
        print(f"{Fore.YELLOW}[*] No login configured for this target — "
              f"authenticated modules will be skipped")
        return None

    section("PHASE 2: AUTHENTICATION")

    username = questionary.text("Username to log in with:", default="admin",
                                 style=QUESTIONARY_STYLE).ask()
    password = questionary.text("Password to log in with:", default="password",
                                 style=QUESTIONARY_STYLE).ask()

    crawler = Crawler(config=config)
    if not crawler.login(username=username, password=password):
        print(f"{Fore.RED}[-] Login failed — authenticated modules will be skipped")
        print(f"{Fore.YELLOW}    (recon findings above are still valid and saved)")
        return None

    if config.security_level_url:
        crawler.set_security_level("low")

    crawler.crawl_all()
    return crawler


def pick_modules(available_findings_hint):
    """Step 4 — arrow-key + spacebar module picker."""
    section("PHASE 3: SELECT MODULES")

    choices = [
        questionary.Choice(
            title=f"{m['label']}  [{m['severity']}]",
            value=m["name"]
        )
        for m in MODULE_CHOICES
    ]

    selected = questionary.checkbox(
        "Select modules to run (space to toggle, enter to confirm):",
        choices=choices,
        style=QUESTIONARY_STYLE
    ).ask()

    return selected or []


def pick_mode():
    return questionary.select(
        "Run mode:",
        choices=[
            questionary.Choice(title="Automatic — run everything, no pauses", value="auto"),
            questionary.Choice(title="Manual — confirm before each real exploit action", value="manual"),
        ],
        style=QUESTIONARY_STYLE
    ).ask()


def confirm_exploit(description):
    """Used in manual mode before real exploit actions."""
    print(f"\n{Fore.YELLOW}[?] About to: {description}")
    return questionary.confirm("Proceed?", default=True, style=QUESTIONARY_STYLE).ask()


def run_selected_modules(crawler, selected, mode, config):
    """Step 5 — run each selected module against discovered forms.
    Findings are collected incrementally so a Ctrl+C mid-scan still
    returns everything found up to that point instead of losing the
    whole run."""
    all_findings = []
    forms = crawler.discovered_forms

    if not forms and any(m in selected for m in ["sqli", "xss", "cmdi", "csrf", "idor"]):
        print(f"{Fore.YELLOW}[!] No forms were discovered — form-based modules will find nothing")

    try:
        if "sqli" in selected:
            section("SQL INJECTION")
            scanner = SQLiScanner(crawler.session)
            findings = scanner.scan_all(forms)
            all_findings.extend(findings)  # captured immediately, survives interrupt in exploit step below

            for f in findings:
                if mode == "manual" and not confirm_exploit(
                    f"exploit confirmed SQLi at {f['url']} param='{f['parameter']}' "
                    f"(extract database contents)"
                ):
                    continue
                exploiter = SQLiExploiter(crawler.session)
                base_params = {i["name"]: i.get("value", "1") for form in forms.get(f["url"], [])
                                for i in form["inputs"]}
                exploiter.exploit(f["url"], f["parameter"], base_params)

        if "xss" in selected:
            section("XSS (REFLECTED)")
            scanner = XSSScanner(crawler.session)
            findings = scanner.scan_all(forms)
            all_findings.extend(findings)

            for f in findings:
                if mode == "manual" and not confirm_exploit(
                    f"demonstrate cookie theft via XSS at {f['url']} param='{f['parameter']}'"
                ):
                    continue
                theft = CookieTheftExploit()
                base_params = {i["name"]: i.get("value", "") for form in forms.get(f["url"], [])
                                for i in form["inputs"]}
                theft.demonstrate(f["url"], f["parameter"], base_params, method=f.get("method", "get"))

        if "cmdi" in selected:
            section("COMMAND INJECTION")
            scanner = CommandInjectionScanner(crawler.session)
            findings = scanner.scan_all(forms)
            all_findings.extend(findings)

        if "csrf" in selected:
            section("CSRF")
            scanner = CSRFScanner(crawler.session, base_url=config.base_url)
            findings = scanner.scan_all(forms)
            all_findings.extend(findings)

        if "upload" in selected:
            section("FILE UPLOAD")
            upload_forms = [url for url, fl in forms.items()
                             for f in fl
                             if any(i.get("type") == "file" for i in f["inputs"])]
            if not upload_forms:
                print(f"{Fore.YELLOW}[?] No file upload forms discovered")
            else:
                if mode == "manual" and not confirm_exploit(
                    f"attempt web shell upload at {upload_forms[0]}"
                ):
                    pass
                else:
                    scanner = FileUploadScanner(crawler.session, base_url=config.base_url)
                    findings = scanner.scan(upload_url=upload_forms[0])
                    if findings:
                        all_findings.extend(findings)

        if "idor" in selected:
            section("IDOR")
            scanner = IDORScanner(crawler.session, base_url=config.base_url, config=config)
            findings = scanner.scan_all(forms)
            all_findings.extend(findings)

        if "brute" in selected:
            section("BRUTE FORCE")
            wordlist_path = questionary.text(
                "Wordlist path (leave blank for built-in list):",
                style=QUESTIONARY_STYLE
            ).ask()
            scanner = BruteForceScanner(crawler.session, base_url=config.base_url, config=config)
            username = questionary.text("Username to brute-force:", default="admin",
                                         style=QUESTIONARY_STYLE).ask()
            findings = scanner.scan(username=username, wordlist_path=wordlist_path or None)
            all_findings.extend(findings)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted mid-scan — saving {len(all_findings)} "
              f"finding(s) collected so far instead of discarding them")

    return all_findings


def compute_risk_score(findings):
    """Simple weighted risk score, capped at 100 — gives the report
    a single headline number, similar to commercial scanners."""
    total = sum(SEVERITY_WEIGHT.get(f.get("severity", "LOW"), 1) for f in findings)
    return min(total, 100)


def save_report(config, misconfig_findings, exploit_findings):
    all_findings = misconfig_findings + exploit_findings
    risk_score = compute_risk_score(all_findings)

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report = {
        "target": config.base_url,
        "scan_time": datetime.now().isoformat(),
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "total_findings": len(all_findings),
        "findings": all_findings,
    }

    json_path = f"sentinelx_report_{timestamp}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    text_path = f"sentinelx_report_{timestamp}.txt"
    with open(text_path, "w") as f:
        f.write(f"SentinelX Vulnerability Report\n")
        f.write(f"{'='*60}\n")
        f.write(f"Target:     {config.base_url}\n")
        f.write(f"Scan time:  {report['scan_time']}\n")
        f.write(f"Risk score: {risk_score}/100\n\n")
        f.write(f"Findings by severity:\n")
        for sev, count in sorted(severity_counts.items(), key=lambda x: -SEVERITY_WEIGHT.get(x[0], 0)):
            f.write(f"  {sev:<10} {count}\n")
        f.write(f"\nTotal findings: {len(all_findings)}\n")
        f.write(f"{'='*60}\n\n")

        for i, finding in enumerate(all_findings, 1):
            f.write(f"[{i}] {finding.get('type', 'UNKNOWN')} — {finding.get('severity', 'UNKNOWN')}\n")
            f.write(f"    URL:       {finding.get('url', 'N/A')}\n")
            if finding.get('parameter'):
                f.write(f"    Parameter: {finding.get('parameter')}\n")

            # Different modules use different field names for their
            # detail — pull whichever ones this finding actually has
            # instead of only ever looking for 'evidence'
            if finding.get('header'):
                f.write(f"    Header:    {finding['header']} (missing)\n")
                f.write(f"    Impact:    {finding.get('impact', '')}\n")
            if finding.get('cookie'):
                f.write(f"    Cookie:    {finding['cookie']}\n")
                f.write(f"    Issue:     {finding.get('issue', '')}\n")
            if finding.get('status_code') is not None:
                f.write(f"    Status:    HTTP {finding['status_code']}\n")
                f.write(f"    Detail:    {finding.get('description', '')}\n")
            if finding.get('verified_user'):
                f.write(f"    Verified:  command execution as '{finding['verified_user']}'\n")
            if finding.get('shell_url'):
                f.write(f"    Shell:     {finding['shell_url']}\n")
            if finding.get('commands_executed'):
                f.write(f"    Commands executed: {len(finding['commands_executed'])} "
                         f"({', '.join(finding['commands_executed'].keys())})\n")
            if finding.get('form_action'):
                f.write(f"    Form:      {finding['form_action']} [{finding.get('method', '?')}]\n")
            if finding.get('exploitation'):
                exp = finding['exploitation']
                f.write(f"    Exploit:   forged request accepted "
                         f"(response changed {exp.get('length_diff', '?')} bytes)\n")
            elif 'exploitation' in finding:
                f.write(f"    Exploit:   sent, no clear success signal — verify manually\n")

            evidence = finding.get('evidence') or finding.get('techniques_confirmed') \
                or finding.get('variant_confirmed')
            if evidence:
                if isinstance(evidence, list):
                    evidence = "; ".join(str(e) for e in evidence)
                f.write(f"    Evidence:  {evidence}\n")

            f.write("\n")

    return json_path, text_path, risk_score, severity_counts


def print_final_summary(risk_score, severity_counts, all_findings, json_path, text_path):
    section("SCAN COMPLETE")

    print(f"{Fore.WHITE}Risk score: ", end="")
    color = Fore.RED if risk_score >= 50 else (Fore.YELLOW if risk_score >= 20 else Fore.GREEN)
    print(f"{color}{risk_score}/100\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in severity_counts:
            print(f"{Fore.WHITE}  {sev:<10} {severity_counts[sev]}")

    # Findings-by-type table — quick visual scan of what was actually found
    type_counts = {}
    for f in all_findings:
        t = f.get("type", "UNKNOWN")
        type_counts[t] = type_counts.get(t, 0) + 1

    if type_counts:
        print(f"\n{Fore.WHITE}{'─'*40}")
        print(f"{Fore.WHITE}{'FINDING TYPE':<28}{'COUNT'}")
        print(f"{Fore.WHITE}{'─'*40}")
        for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"{Fore.CYAN}  {t:<26}{Fore.YELLOW}{count}")
        print(f"{Fore.WHITE}{'─'*40}")

    print(f"\n{Fore.GREEN}[+] Report saved:")
    print(f"{Fore.GREEN}    {json_path}")
    print(f"{Fore.GREEN}    {text_path}")


def main():
    print_banner()

    config = ask_target()
    print_status_bar(config, logged_in=False, form_count=0)
    misconfig_findings, unauth_forms = run_recon(config)

    if unauth_forms:
        print(f"\n{Fore.GREEN}[+] Discovered {len(unauth_forms)} page(s) with forms "
              f"before login — these are available even if login fails")

    crawler = attempt_login(config)

    if crawler is not None:
        print_status_bar(config, logged_in=True, form_count=len(crawler.discovered_forms))

    if crawler is None:
        # No auth — offer to continue with unauthenticated forms only
        if not unauth_forms:
            print(f"{Fore.YELLOW}[!] No login and no forms found unauthenticated — "
                  f"nothing more to scan. Recon report will still be saved.")
            json_path, text_path, risk_score, sev_counts = save_report(
                config, misconfig_findings, []
            )
            print_final_summary(risk_score, sev_counts, misconfig_findings, json_path, text_path)
            return

        proceed = questionary.confirm(
            f"Continue with the {len(unauth_forms)} unauthenticated form(s) found?",
            default=True, style=QUESTIONARY_STYLE
        ).ask()
        if not proceed:
            json_path, text_path, risk_score, sev_counts = save_report(
                config, misconfig_findings, []
            )
            print_final_summary(risk_score, sev_counts, misconfig_findings, json_path, text_path)
            return

        crawler = Crawler(config=config)
        crawler.discovered_forms = unauth_forms
        crawler.logged_in = True  # allow scanners to proceed without a real session

    selected = pick_modules(crawler.discovered_forms)

    if not selected:
        print(f"{Fore.YELLOW}[!] No modules selected — saving recon-only report")
        json_path, text_path, risk_score, sev_counts = save_report(
            config, misconfig_findings, []
        )
        print_final_summary(risk_score, sev_counts, misconfig_findings, json_path, text_path)
        return

    mode = pick_mode()
    exploit_findings = run_selected_modules(crawler, selected, mode, config)

    json_path, text_path, risk_score, sev_counts = save_report(
        config, misconfig_findings, exploit_findings
    )
    print_final_summary(risk_score, sev_counts, misconfig_findings + exploit_findings, json_path, text_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Interrupted — exiting")
        sys.exit(0)
