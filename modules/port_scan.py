import socket
from modules.base_scanner import VulnerabilityScanner
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, Colors
from urllib.parse import urlparse

class PortScanner(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.hostname = urlparse(target_url).netloc
        self.ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
            1433, 3306, 3389, 5900, 8000, 8080, 8443, 8888
        ]

    def scan(self):
        print_info(f"Starting Port Scan on {self.hostname}...")
        
        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.hostname, port))
            if result == 0:
                print_success(f"Port {port} is OPEN")
                self.add_finding(
                    "Open Port",
                    f"Port {port} is open on {self.hostname}",
                    "Info"
                )
            sock.close()

        return self.vulnerabilities
