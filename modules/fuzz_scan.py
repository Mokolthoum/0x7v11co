import requests
from modules.base_scanner import VulnerabilityScanner
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_error, print_warning, Colors
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode

class FuzzScanner(VulnerabilityScanner):
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.payloads = [
            "'", "\"", "<script>", "../", "%00", "A" * 1000, 
            "{{7*7}}", "${7*7}", "1 OR 1=1"
        ]

    def scan(self):
        print_info(f"Starting Input Fuzzing...")
        
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            print_info(f"Found {len(forms)} forms to fuzz.")

            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                target_url = urljoin(self.target_url, action)
                inputs = form.find_all('input')
                
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        form_data[name] = "test"

                for payload in self.payloads:
                    # Test each input with payload
                    for input_name in form_data:
                        test_data = form_data.copy()
                        test_data[input_name] = payload
                        
                        poc = ""
                        try:
                            if method == 'post':
                                res = self.session.post(target_url, data=test_data)
                                poc = f"curl -X POST -d '{urlencode(test_data)}' '{target_url}'"
                            else:
                                res = self.session.get(target_url, params=test_data)
                                if '?' in target_url:
                                    poc = f"{target_url}&{urlencode(test_data)}"
                                else:
                                    poc = f"{target_url}?{urlencode(test_data)}"
                            
                            if res.status_code >= 500:
                                print_error(f"Potential Issue: Server Error (500) with payload '{payload}' in field '{input_name}'")
                                self.add_finding(
                                    "Input Fuzzing - Server Error",
                                    f"Server returned 500 error when fuzzing field '{input_name}'.",
                                    "Medium",
                                    url=target_url,
                                    payload=payload,
                                    evidence=f"Status Code: {res.status_code}",
                                    poc=poc
                                )
                            elif "syntax error" in res.text.lower() or "sql" in res.text.lower():
                                print_error(f"Potential Issue: Database Error leaked with payload '{payload}'")
                                self.add_finding(
                                    "Input Fuzzing - Information Leak",
                                    f"Database error message leaked when fuzzing field '{input_name}'.",
                                    "High",
                                    url=target_url,
                                    payload=payload,
                                    evidence="Database error in response body",
                                    poc=poc
                                )
                                
                        except requests.RequestException:
                            pass

        except Exception as e:
            print_warning(f"Error during fuzzing: {e}")

        return self.vulnerabilities
