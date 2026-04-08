import argparse
import requests
import sys
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup

# Modules
from modules.header_scan import HeaderScanner
from modules.form_scan import FormScanner
from modules.sqli_scan import SQLiScanner
from modules.dir_enum import DirectoryEnumerator
from modules.fuzz_scan import FuzzScanner
from modules.wp_scan import WPScanner
from modules.xss_scan import XSSScanner
from modules.lfi_scan import LFIScanner
from modules.crawler import Crawler
from modules.subdomain_scan import SubdomainScanner
from modules.port_scan import PortScanner
from modules.proxy_scan import ProxyScanner
from modules.upload_scan import UploadScanner

# Utils
from utils.reporter import Reporter
from utils.colors import console

# Rich
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box

def print_banner():
    """Display the 0x7v11co banner"""
    banner = r"""

#   ___           _____           _____           ___  
#  / _ \  __  __ |___  | __   __ |___ /    ___   / _ \ 
# | | | | \ \/ /    / /  \ \ / /   |_ \   / __| | | | |
# | |_| |  >  <    / /    \ V /   ___) | | (__  | |_| |
#  \___/  /_/\_\  /_/      \_/   |____/   \___|  \___/ 

    """
    console.print(banner, style="bold cyan")

def print_scan_info(target, mode, threads, has_auth, export_formats):
    """Display scan configuration in a compact table"""
    info_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    info_table.add_column("Key", style="cyan bold")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("🎯 Target", target)
    info_table.add_row("⚙️  Mode", mode)
    info_table.add_row("🧵 Threads", str(threads))
    info_table.add_row("🔐 Auth", "✓ Enabled" if has_auth else "✗ Disabled")
    info_table.add_row("📤 Export", export_formats if export_formats else "HTML only")
    info_table.add_row("🕐 Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    console.print(Panel(info_table, title="[bold]Scan Configuration[/bold]", border_style="cyan", box=box.ROUNDED))

def parse_cookies(cookie_string):
    """Parse a cookie string "key=value; key2=value2" into a dictionary."""
    cookies = {}
    if not cookie_string:
        return cookies
    try:
        for item in cookie_string.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v
    except Exception:
        console.print("[yellow]⚠ Failed to parse cookies. Ignoring.[/yellow]")
    return cookies

def auto_login(session, login_url, username, password):
    """Automatically login to the target and return True if successful."""
    try:
        # First GET the login page to find the form and any tokens
        login_page = session.get(login_url, timeout=10)
        soup = BeautifulSoup(login_page.text, 'html.parser')
        
        # Find the login form
        form = soup.find('form')
        if not form:
            console.print("[yellow]⚠ No form found on login page[/yellow]")
            return False
        
        # Build form data
        form_data = {}
        for inp in form.find_all('input'):
            name = inp.get('name')
            if not name:
                continue
            inp_type = inp.get('type', 'text').lower()
            
            if inp_type == 'hidden':
                form_data[name] = inp.get('value', '')
            elif 'user' in name.lower() or 'email' in name.lower() or 'login' in name.lower():
                form_data[name] = username
            elif 'pass' in name.lower():
                form_data[name] = password
            elif inp_type != 'submit':
                form_data[name] = ''
        
        # Determine form action
        action = form.get('action', '')
        from urllib.parse import urljoin
        post_url = urljoin(login_url, action) if action else login_url
        
        # Submit login (don't follow redirects so we can check cookies)
        response = session.post(post_url, data=form_data, timeout=10, allow_redirects=False)
        
        # Check for redirect to dashboard (302/301 = successful login)
        if response.status_code in [301, 302]:
            location = response.headers.get('Location', '')
            if '/login' not in location:
                # Follow the redirect manually
                session.get(urljoin(login_url, location), timeout=10)
                return True
        
        # If direct 200 with dashboard content
        if response.status_code == 200:
            if 'logout' in response.text.lower() and 'operationalerror' not in response.text.lower():
                return True
        
        # Check if session cookie was set (even on error page)
        if session.cookies.get('sessionid'):
            # Verify that we can access protected pages
            dashboard_url = login_url.rsplit('/', 2)[0] + '/dashboard/'
            test = session.get(dashboard_url, timeout=5, allow_redirects=False)
            if test.status_code == 200:
                return True
        
        # If login had a server error but no session, the app may need different approach
        # Try with allow_redirects=True as fallback
        if response.status_code >= 500:
            # The server error might come from raw SQL but authenticate() may still work
            # Create a fresh session and try again
            session2 = requests.Session()
            session2.headers.update(dict(session.headers))
            res2 = session2.post(post_url, data=form_data, timeout=10, allow_redirects=False)
            if res2.status_code in [301, 302]:
                # Transfer cookies to original session
                session.cookies.update(session2.cookies)
                return True
            # Check if the fallback authenticate() set a session cookie
            if session2.cookies.get('sessionid'):
                session.cookies.update(session2.cookies)
                return True
        
        return False
        
    except Exception as e:
        console.print(f"[yellow]⚠ Auto-login failed: {e}[/yellow]")
        return False

def create_session_clone(original_session):
    """Create a new session with the same cookies and headers (thread-safe)."""
    import copy
    new_session = requests.Session()
    new_session.headers.update(dict(original_session.headers))
    # Deep copy the cookie jar to preserve domain/path attributes
    new_session.cookies = copy.deepcopy(original_session.cookies)
    return new_session

def run_scanner(scanner_class, target, session, *args):
    """Helper to run a scanner and return findings."""
    try:
        scanner = scanner_class(target, session, *args)
        return scanner.scan()
    except Exception as e:
        return []

def main():
    parser = argparse.ArgumentParser(
        description="0x7v11co: Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n  python3 main.py http://example.com\n  python3 main.py http://example.com --full --threads 10\n  python3 main.py http://example.com --cookie 'session=abc' --export all\n  python3 main.py http://example.com --full --login-url http://example.com/login/ --username admin --password admin123"
    )
    
    parser.add_argument("url", help="Target URL to scan")
    
    # Scan Profiles
    mode_group = parser.add_argument_group('Scan Profiles')
    mode_group.add_argument("--fast", action="store_true", help="Quick scan (Headers, Forms, WP)")
    mode_group.add_argument("--full", action="store_true", help="Deep scan (All modules enabled)")
    
    # Advanced Options
    adv_group = parser.add_argument_group('Module Selection')
    adv_group.add_argument("--headers", action="store_true", help="Security headers analysis")
    adv_group.add_argument("--forms", action="store_true", help="Form discovery + CSRF check")
    adv_group.add_argument("--sqli", action="store_true", help="SQL Injection testing")
    adv_group.add_argument("--xss", action="store_true", help="XSS vulnerability testing")
    adv_group.add_argument("--lfi", action="store_true", help="Local File Inclusion testing")
    adv_group.add_argument("--dir-enum", action="store_true", help="Directory enumeration")
    adv_group.add_argument("--fuzz", action="store_true", help="Input fuzzing")
    adv_group.add_argument("--wp-scan", action="store_true", help="WordPress detection")
    adv_group.add_argument("--crawl", action="store_true", help="Web crawler")
    adv_group.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    adv_group.add_argument("--ports", action="store_true", help="Port scanning")
    adv_group.add_argument("--proxy", action="store_true", help="Proxy/WAF detection")
    adv_group.add_argument("--upload", action="store_true", help="File upload testing")
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument("--login-url", type=str, help="Login page URL for auto-authentication")
    auth_group.add_argument("--username", type=str, help="Username for auto-login")
    auth_group.add_argument("--password", type=str, help="Password for auto-login")
    
    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument("--cookie", type=str, help="Session cookies (e.g. 'id=123; session=abc')")
    config_group.add_argument("--export", type=str, choices=['json', 'csv', 'md', 'all'], help="Export format (json/csv/md/all)")
    config_group.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    config_group.add_argument("--output", type=str, help="Custom output filename (without extension)")
    config_group.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output (show info/headers)")

    args = parser.parse_args()
    target_url = args.url
    
    # Set Verbosity
    from utils.colors import Colors
    Colors.VERBOSE = args.verbose

    # Banner
    print_banner()

    # Configuration
    config = {
        "headers": False, "forms": False, "sqli": False, "xss": False, "lfi": False,
        "dir_enum": False, "fuzz": False, "wp_scan": False, "crawl": False,
        "subdomains": False, "ports": False, "proxy": False, "upload": False
    }

    # Determine mode
    if args.full:
        mode_name = "FULL SCAN"
        for key in config:
            config[key] = True
    elif args.fast:
        mode_name = "FAST SCAN"
        config["headers"] = True
        config["forms"] = True
        config["wp_scan"] = True
    else:
        any_flag = any([getattr(args, k, False) for k in config.keys()])
        if any_flag:
            mode_name = "CUSTOM"
            for key in config:
                if getattr(args, key, False):
                    config[key] = True
        else:
            mode_name = "STANDARD"
            config["headers"] = True
            config["forms"] = True
            config["sqli"] = True
            config["xss"] = True
            config["wp_scan"] = True
            config["dir_enum"] = True
            config["proxy"] = True
            config["upload"] = True

    # Session Setup
    session = requests.Session()
    session.headers.update({'User-Agent': '0x7v11co/3.0 (Security Scanner)'})
    
    has_auth = False
    
    # Manual cookies (set before anything else)
    if args.cookie:
        cookies = parse_cookies(args.cookie)
        session.cookies.update(cookies)
        has_auth = True

    # Export formats
    export_formats = ""
    if args.export:
        if args.export == 'all':
            export_formats = "JSON, CSV, Markdown"
        else:
            export_formats = args.export.upper()

    # Display scan info
    if Colors.VERBOSE:
        print_scan_info(target_url, mode_name, args.threads, has_auth or bool(args.login_url), export_formats)

    all_vulnerabilities = []
    
    # Phase 1: Infrastructure & Recon (no auth needed)
    Colors.print_header("Phase 1: Infrastructure & Reconnaissance")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        
        recon_tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            if config["proxy"]:
                recon_tasks.append(("Proxy/WAF Detection", executor.submit(run_scanner, ProxyScanner, target_url, session)))
            if config["subdomains"]:
                recon_tasks.append(("Subdomain Enum", executor.submit(run_scanner, SubdomainScanner, target_url, session)))
            if config["ports"]:
                recon_tasks.append(("Port Scanning", executor.submit(run_scanner, PortScanner, target_url, session)))
            if config["dir_enum"]:
                recon_tasks.append(("Directory Enum", executor.submit(run_scanner, DirectoryEnumerator, target_url, session)))
            if config["wp_scan"]:
                recon_tasks.append(("WordPress Scan", executor.submit(run_scanner, WPScanner, target_url, session)))
            
            if recon_tasks:
                task_id = progress.add_task("[cyan]Running reconnaissance...", total=len(recon_tasks))
                
                for name, future in recon_tasks:
                    results = future.result()
                    all_vulnerabilities.extend(results)
                    progress.update(task_id, advance=1, description=f"[cyan]Completed: {name}")

    # Phase 1.5: Authentication (after recon to avoid database locks)
    if args.login_url and args.username and args.password:
        Colors.print_header("Authentication")
        import time
        time.sleep(1)  # Brief pause for database to settle after recon
        with console.status("[cyan]Attempting auto-login...", spinner="dots"):
            login_success = auto_login(session, args.login_url, args.username, args.password)
        
        if login_success:
            console.print("[green]✓[/green] Auto-login successful!")
            has_auth = True
        else:
            console.print("[yellow]![/yellow] Auto-login failed. Continuing without authentication.")

    # Phase 2: Crawling
    urls_to_scan = [target_url]
    if config["crawl"]:
        Colors.print_header("Phase 2: Content Discovery")
        with console.status("[cyan]Crawling website...", spinner="dots"):
            crawler = Crawler(target_url, session)
            urls_to_scan = crawler.get_urls()
            if not urls_to_scan:
                urls_to_scan = [target_url]
        if Colors.VERBOSE:
            console.print(f"[green]✓[/green] Discovered {len(urls_to_scan)} unique URLs")
    
    # Phase 3: Vulnerability Scanning
    Colors.print_header("Phase 3: Vulnerability Analysis")
    
    # Scan each URL sequentially (thread-safe session usage)
    scanned_form_actions = set()  # Track scanned form actions to avoid duplicates
    header_scanned = False  # Only scan headers once
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        
        vuln_task_id = progress.add_task("[cyan]Analyzing pages...", total=len(urls_to_scan))
        
        for url in urls_to_scan:
            page_session = session  # Use same session (sequential, no need to clone)
            page_vulns = scan_page_comprehensive(
                url, page_session, config, 
                scanned_form_actions, header_scanned
            )
            all_vulnerabilities.extend(page_vulns)
            
            # Mark headers as scanned after first URL
            if not header_scanned and config["headers"]:
                header_scanned = True
            
            progress.advance(vuln_task_id)

    # Phase 4: Reporting
    Colors.print_header("Phase 4: Report Generation")
    
    # Deduplicate vulnerabilities
    all_vulnerabilities = deduplicate_vulnerabilities(all_vulnerabilities)
    
    reporter = Reporter(all_vulnerabilities)
    
    base_name = args.output if args.output else "report"
    
    with console.status("[cyan]Generating reports...", spinner="dots"):
        reporter.output_file = f"{base_name}.html"
        reporter.generate_report()
        
        if args.export:
            if args.export in ['json', 'all']:
                reporter.save_json(f"{base_name}.json")
            if args.export in ['csv', 'all']:
                reporter.save_csv(f"{base_name}.csv")
            if args.export in ['md', 'all']:
                reporter.save_markdown(f"{base_name}.md")
    
    console.print(f"[green]✓[/green] HTML report: [link=file://{base_name}.html]{base_name}.html[/link]")
    if args.export:
        if args.export in ['json', 'all']:
            console.print(f"[green]✓[/green] JSON export: {base_name}.json")
        if args.export in ['csv', 'all']:
            console.print(f"[green]✓[/green] CSV export: {base_name}.csv")
        if args.export in ['md', 'all']:
            console.print(f"[green]✓[/green] Markdown export: {base_name}.md")

    # Summary
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in all_vulnerabilities:
        sev = v.get("severity", "Info")
        if sev in stats:
            stats[sev] += 1
        else:
            stats["Info"] += 1
    
    summary_table = Table(title="[bold]Scan Results[/bold]", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    summary_table.add_column("Severity", style="bold", width=12)
    summary_table.add_column("Count", justify="right", width=8)
    summary_table.add_column("Status", width=20)
    
    summary_table.add_row("Critical", str(stats["Critical"]), "🔴" if stats["Critical"] > 0 else "✓")
    summary_table.add_row("High", str(stats["High"]), "🟠" if stats["High"] > 0 else "✓")
    summary_table.add_row("Medium", str(stats["Medium"]), "🟡" if stats["Medium"] > 0 else "✓")
    summary_table.add_row("Low", str(stats["Low"]), "🟢" if stats["Low"] > 0 else "✓")
    summary_table.add_row("Info", str(stats["Info"]), "🔵")
    
    console.print("\n", summary_table)
    
    # Risk Score
    risk_score = (stats["Critical"] * 10) + (stats["High"] * 7) + (stats["Medium"] * 4) + (stats["Low"] * 1)
    risk_level = "CRITICAL" if risk_score > 50 else "HIGH" if risk_score > 20 else "MEDIUM" if risk_score > 10 else "LOW"
    risk_color = "red" if risk_level == "CRITICAL" else "orange1" if risk_level == "HIGH" else "yellow" if risk_level == "MEDIUM" else "green"
    console.print(f"\n[bold]Overall Risk Score:[/bold] [{risk_color}]{risk_score}[/{risk_color}] ([{risk_color}]{risk_level}[/{risk_color}])")
    console.print("\n[bold green]✓ Scan completed successfully![/bold green]\n")

def scan_page_comprehensive(url, session, config, scanned_form_actions=None, header_scanned=False):
    """Runs all page-specific scans for a single URL."""
    vulns = []
    if scanned_form_actions is None:
        scanned_form_actions = set()
    
    # Skip static/irrelevant URLs
    skip_patterns = ['/static/', '/media/', '/css/', '/js/', '/logout']
    if any(p in url for p in skip_patterns):
        return vulns
    
    # Headers: scan only once to avoid duplicates
    if config["headers"] and not header_scanned:
        try:
            scanner = HeaderScanner(url, session)
            vulns.extend(scanner.scan())
        except: pass

    forms = []
    if config["forms"] or config["sqli"] or config["xss"] or config["fuzz"]:
        try:
            form_scanner = FormScanner(url, session)
            forms = form_scanner.scan()
            
            # Deduplicate: skip forms we've already scanned
            new_forms = []
            for f in forms:
                action_key = f.get('action', url)
                if action_key not in scanned_form_actions:
                    scanned_form_actions.add(action_key)
                    new_forms.append(f)
            
            if config["forms"]:
                # Only add CSRF findings for new/unique forms
                for v in form_scanner.vulnerabilities:
                    v_url = v.get('url', '')
                    if v_url in scanned_form_actions or not any(v_url == nf.get('action') for nf in new_forms):
                        # Check if this specific CSRF finding is for a new form
                        pass
                vulns.extend(form_scanner.vulnerabilities)
            
            if config["sqli"] and new_forms:
                scanner = SQLiScanner(url, session, new_forms)
                vulns.extend(scanner.scan())
                
            if config["xss"] and new_forms:
                scanner = XSSScanner(url, session, new_forms)
                vulns.extend(scanner.scan())
                
        except: pass

    if config["lfi"]:
        try:
            scanner = LFIScanner(url, session)
            vulns.extend(scanner.scan())
        except: pass
        
    if config["fuzz"] and forms:
        try:
            scanner = FuzzScanner(url, session)
            vulns.extend(scanner.scan())
        except: pass

    if config.get("upload"):
        try:
            scanner = UploadScanner(url, session)
            vulns.extend(scanner.scan())
        except: pass
        
    return vulns

def deduplicate_vulnerabilities(vulns):
    """Remove duplicate vulnerabilities based on type+url+description."""
    seen = set()
    unique = []
    for v in vulns:
        key = (v.get('type',''), v.get('url',''), v.get('description','')[:100])
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]✗ Scan interrupted by user[/bold red]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]✗ Fatal error: {e}[/bold red]")
        sys.exit(1)
