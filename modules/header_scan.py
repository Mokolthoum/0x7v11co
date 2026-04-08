from .base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning

class HeaderScanner(VulnerabilityScanner):
    """
    Scans for missing security headers and insecure cookie settings.
    """
    def scan(self):
        print_info(f"Starting Header Scan on {self.target_url}...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # 1. Check Security Headers
            security_headers = {
                "X-Frame-Options": "Medium",
                "Content-Security-Policy": "High",
                "Strict-Transport-Security": "High",
                "X-Content-Type-Options": "Low"
            }

            for header, severity in security_headers.items():
                if header not in headers:
                    print_info(f"Missing Header: {header}")
                    self.add_finding(
                        "Missing Security Header",
                        f"The header '{header}' is missing from the response.",
                        severity
                    )
                else:
                    print_info(f"Found Header: {header}")

            # 2. Check Cookie Security
            set_cookie_headers = response.headers.get('Set-Cookie', '')
            
            # Also check all cookies in the session
            for cookie in response.cookies:
                cookie_name = cookie.name
                cookie_attrs = {
                    'httponly': cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'),
                    'secure': cookie.secure,
                    'samesite': cookie.has_nonstandard_attr('SameSite') or cookie.has_nonstandard_attr('samesite'),
                }
                
                # Check HttpOnly
                if not cookie_attrs['httponly']:
                    print_info(f"Cookie '{cookie_name}' missing HttpOnly flag")
                    self.add_finding(
                        "Insecure Cookie",
                        f"Cookie '{cookie_name}' is missing the HttpOnly flag. JavaScript can access this cookie, enabling session hijacking via XSS.",
                        "Medium",
                        evidence=f"Set-Cookie: {cookie_name}=... (no HttpOnly)"
                    )
                
                # Check Secure flag
                if not cookie_attrs['secure']:
                    print_info(f"Cookie '{cookie_name}' missing Secure flag")
                    self.add_finding(
                        "Insecure Cookie",
                        f"Cookie '{cookie_name}' is missing the Secure flag. The cookie can be sent over unencrypted HTTP connections.",
                        "Low",
                        evidence=f"Set-Cookie: {cookie_name}=... (no Secure)"
                    )

        except Exception as e:
            print_warning(f"Header scan failed: {e}")

        return self.vulnerabilities
