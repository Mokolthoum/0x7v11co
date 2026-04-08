import requests
from modules.base_scanner import VulnerabilityScanner
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning, Colors

class WPScanner(VulnerabilityScanner):
    def scan(self):
        print_info(f"Starting WordPress Detection...")
        vulnerabilities = []
        
        # Check for common WP paths
        paths = ["wp-login.php", "wp-admin/", "wp-content/", "readme.html", "license.txt"]
        base_url = self.target_url if self.target_url.endswith('/') else self.target_url + '/'
        
        is_wp = False
        detected_version = None
        
        for path in paths:
            url = f"{base_url}{path}"
            try:
                response = self.session.get(url, allow_redirects=False, timeout=5)
                if response.status_code == 200:
                    is_wp = True
                    print_info(f"Found WordPress artifact: {path}")
                    
                    if "readme" in path:
                        # Attempt simple version extraction (very basic)
                        if "Version" in response.text:
                            # This is a naive check, real extraction would be more complex
                            pass
            except requests.RequestException:
                pass

        if is_wp:
            # Check for meta generator tag
            try:
                response = self.session.get(self.target_url)
                if 'name="generator" content="WordPress' in response.text:
                    print_info(f"WordPress Meta Generator tag found.")
                    # Extract version if possible
                    start = response.text.find('content="WordPress') + 19
                    end = response.text.find('"', start)
                    detected_version = response.text[start:end]
            except:
                pass

            desc = "WordPress installation detected."
            if detected_version:
                desc += f" Version: {detected_version}"
                
            vulnerabilities.append({
                "type": "Technology Detection",
                "description": desc,
                "severity": "Info",
                "url": self.target_url
            })
            
            # Check for user enumeration via REST API
            api_url = f"{base_url}wp-json/wp/v2/users"
            try:
                res = self.session.get(api_url)
                if res.status_code == 200 and "slug" in res.text:
                    vulnerabilities.append({
                        "type": "WordPress User Enumeration",
                        "description": "WordPress REST API allows user enumeration (wp-json/wp/v2/users).",
                        "severity": "Medium",
                        "url": api_url
                    })
                    print_warning(f"WordPress User Enumeration possible via REST API.")
            except:
                pass

        return vulnerabilities
