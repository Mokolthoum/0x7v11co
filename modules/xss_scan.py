import requests
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning, print_error
from urllib.parse import urlencode

class XSSScanner(VulnerabilityScanner):
    def __init__(self, target_url, session, forms):
        super().__init__(target_url, session)
        self.forms = forms
        # Dictionary of context -> payloads
        self.payloads = {
            "Generic Reflection": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>"
            ],
            "Attribute Breakout": [
                "\"><script>alert('XSS')</script>",
                "' onmouseover='alert(1)",
                "\" onmouseover=\"alert(1)",
                "\" autofocus onfocus=alert(1)"
            ],
            "Script Context": [
                "'; alert(1); //",
                "\"; alert(1); //",
                "-alert(1)-"
            ]
        }

    def scan(self):
        print_info(f"Starting XSS Scan on {len(self.forms)} forms...")
        
        for form in self.forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.get('inputs', [])
            
            if not inputs:
                continue

            print_info(f"Testing form at {action}...")

            # Flatten payloads for iteration
            all_payloads = []
            for ctx, p_list in self.payloads.items():
                for p in p_list:
                    all_payloads.append((ctx, p))

            for ctx, payload in all_payloads:
                data = {}
                
                # Fill all fields with payload to maximize chance of reflection
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        data[name] = payload

                try:
                    if method == 'post':
                        response = self.session.post(action, data=data, timeout=5)
                    else:
                        response = self.session.get(action, params=data, timeout=5)

                    # Check for literal reflection of the payload
                    # If payload in response.text is True, it means it was NOT encoded (e.g. < was not &lt;)
                    if payload in response.text:
                        print_error(f"XSS Found ({ctx}) at {action}")
                        self.add_finding(
                            "Reflected XSS",
                            f"Payload was reflected in the response from {action}. Context: {ctx}",
                            "High",
                            url=action,
                            payload=payload,
                            evidence=f"Unencoded reflection of payload: {payload}",
                            poc=self._generate_poc(action, method, data)
                        )
                        # Break after finding one vulnerability per form to avoid spamming the report
                        break 
                        
                except requests.RequestException:
                    pass

        return self.vulnerabilities

    def _generate_poc(self, action, method, data):
        if method == "post":
             return f"curl -X POST -d '{urlencode(data)}' '{action}'"
        else:
             return f"{action}?{urlencode(data)}"
