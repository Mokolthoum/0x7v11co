import socket
from modules.base_scanner import VulnerabilityScanner
from utils.colors import Colors
from urllib.parse import urlparse

class SubdomainScanner(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.domain = urlparse(target_url).netloc
        # Remove www. if present to get base domain
        if self.domain.startswith("www."):
            self.domain = self.domain[4:]
            
        self.subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", 
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", 
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "email", 
            "ns3", "mail2", "ne1", "ir", "server", "ns4", "chat", "secure", "vpn", 
            "api", "mobile", "remote", "shop", "portal"
        ]

    def scan(self):
        print(f"{Colors.INFO} Starting Subdomain Enumeration for {self.domain}...")
        
        for sub in self.subdomains:
            hostname = f"{sub}.{self.domain}"
            try:
                ip_address = socket.gethostbyname(hostname)
                print(f"{Colors.PLUS} Found Subdomain: {hostname} ({ip_address})")
                
                self.add_finding(
                    "Subdomain Discovery",
                    f"Found active subdomain: {hostname} resolves to {ip_address}",
                    "Info"
                )
            except socket.gaierror:
                pass
            except Exception:
                pass

        return self.vulnerabilities
