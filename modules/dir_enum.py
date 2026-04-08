import requests
from modules.base_scanner import VulnerabilityScanner
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning, Colors

class DirectoryEnumerator(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.wordlist = [
            # Common admin/auth paths
            "admin", "login", "logout", "dashboard", "admin-panel", "admin_panel",
            # User pages
            "profile", "settings", "user", "users", "account", "accounts",
            # Features
            "search", "transfer", "support", "documents", "upload", "uploads",
            # Static/assets
            "images", "css", "js", "static", "media",
            # Sensitive directories
            "backup", "backups", "config", "db", "database",
            "dev_logs", "dev-logs", "logs", "debug",
            "test", "dev", "staging",
            # API endpoints
            "api", "api/v1", "api/v2",
            "api/v1/internal/users", "api/v1/internal/accounts", "api/v1/internal/transactions",
            # Sensitive files
            ".env", ".env.example", ".env.backup", ".env.local",
            ".git", ".gitignore", ".htaccess",
            "robots.txt", "sitemap.xml",
            "database_schema.sql", "schema.sql", "dump.sql",
            "db_backup.json", "backup.sql",
            # CMS
            "wp-admin", "wp-content", "wp-includes", "wp-login.php",
            # Common frameworks
            "server-status", "server-info", "phpinfo.php", "info.php",
            "console", "debug", "trace",
        ]

    def scan(self):
        print_info(f"Starting Directory Enumeration...")
        found_dirs = []
        
        # Ensure URL ends with / for directory appending
        base_url = self.target_url if self.target_url.endswith('/') else self.target_url + '/'

        for word in self.wordlist:
            url = f"{base_url}{word}"
            try:
                response = self.session.get(url, allow_redirects=False, timeout=5)
                
                # Check for redirects to login pages (False Positives)
                if response.status_code in [301, 302]:
                    location = response.headers.get("Location", "").lower()
                    if any(x in location for x in ["login", "signin", "auth", "account"]):
                        # Skip reporting this as a finding
                        continue

                if response.status_code in [200, 301, 302, 403]:
                    severity = "Info"
                    is_interesting = False
                    
                    if word in [".env", ".git", "config", "backup", "db"]:
                        severity = "High"
                        is_interesting = True
                    elif response.status_code == 403:
                        severity = "Low"
                    
                    # Only print if interesting or verbose
                    if is_interesting:
                        print_warning(f"Found sensitive path: {url} [{response.status_code}]")
                    elif Colors.VERBOSE:
                        status_color = "[green]" if response.status_code == 200 else "[yellow]"
                        print_info(f"Found: {url} {status_color}[{response.status_code}][/]")
                    
                    found_dirs.append({
                        "type": "Directory Discovery",
                        "description": f"Found path: {word} (Status: {response.status_code})",
                        "severity": severity,
                        "url": url
                    })
            except requests.RequestException:
                pass
        
        return found_dirs
