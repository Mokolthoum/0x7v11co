import requests
from modules.base_scanner import VulnerabilityScanner
from utils.colors import Colors

class ProxyScanner(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "expect-ct"],
                "server": "cloudflare",
                "cookies": ["__cfduid", "__cf_bm"]
            },
            "AWS CloudFront": {
                "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cache"],
                "server": "cloudfront",
                "cookies": []
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "akamai-origin-hop"],
                "server": "akamai",
                "cookies": []
            },
            "Fastly": {
                "headers": ["x-fastly-request-id", "fastly-restarts"],
                "server": "fastly",
                "cookies": []
            },
            "Incapsula": {
                "headers": ["x-iinfo", "x-cdn"],
                "server": "incapsula",
                "cookies": ["visid_incap", "incap_ses"]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "server": "sucuri",
                "cookies": []
            },
            "Nginx": {
                "headers": [],
                "server": "nginx",
                "cookies": []
            },
            "Apache": {
                "headers": [],
                "server": "apache",
                "cookies": []
            }
        }

    def scan(self):
        print(f"{Colors.INFO} Checking for Reverse Proxies / WAFs...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            cookies = response.cookies.get_dict()
            server_header = headers.get("server", "").lower()
            
            detected = []

            for provider, sigs in self.signatures.items():
                is_detected = False
                
                # Check Server Header
                if sigs["server"] in server_header:
                    is_detected = True
                
                # Check Specific Headers
                for h in sigs["headers"]:
                    if h in headers:
                        is_detected = True
                        break
                
                # Check Cookies
                if not is_detected:
                    for c in sigs["cookies"]:
                        if any(c in cookie_name for cookie_name in cookies):
                            is_detected = True
                            break
                
                if is_detected:
                    detected.append(provider)
                    print(f"{Colors.PLUS} Detected: {provider}")
                    self.add_finding(
                        "Proxy/WAF Detection",
                        f"Target is using {provider} (Detected via headers/cookies).",
                        "Info"
                    )

            if not detected:
                # print(f"{Colors.INFO} No common proxy signatures found.")
                pass

        except requests.RequestException:
            pass

        return self.vulnerabilities
