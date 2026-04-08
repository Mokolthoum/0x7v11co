from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning

class FormScanner(VulnerabilityScanner):
    """
    Identifies and parses HTML forms. Detects missing CSRF protection.
    """
    def scan(self):
        print_info(f"Starting Form Scan on {self.target_url}...")
        forms_found = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")

            print_info(f"Found {len(forms)} forms.")

            for i, form in enumerate(forms):
                action = form.get("action")
                method = form.get("method", "get").lower()
                
                # Handle relative URLs
                action_url = urljoin(self.target_url, action) if action else self.target_url

                inputs = []
                has_csrf_token = False
                has_file_input = False
                
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    input_name = input_tag.get("name")
                    input_type = input_tag.get("type", "text")
                    
                    if input_name:
                        inputs.append({"name": input_name, "type": input_type})
                        
                        # Check for CSRF token
                        csrf_names = ["csrfmiddlewaretoken", "csrf_token", "_token", 
                                     "csrf", "authenticity_token", "__RequestVerificationToken"]
                        if input_name.lower() in [n.lower() for n in csrf_names]:
                            has_csrf_token = True
                        
                        # Check for file upload
                        if input_type == "file":
                            has_file_input = True

                form_details = {
                    "action": action_url,
                    "method": method,
                    "inputs": inputs,
                    "has_file_input": has_file_input,
                }
                forms_found.append(form_details)
                print_info(f"Form #{i+1}: {method.upper()} to {action_url} with {len(inputs)} inputs")

                # Report missing CSRF protection on POST forms
                if method == "post" and not has_csrf_token:
                    print_warning(f"Form #{i+1} at {action_url} has no CSRF protection!")
                    self.add_finding(
                        "CSRF Missing",
                        f"POST form at {action_url} does not have a CSRF protection token. This makes the form vulnerable to Cross-Site Request Forgery attacks.",
                        "Medium",
                        url=action_url,
                        evidence=f"Form method=POST, no CSRF token found among inputs: {[i['name'] for i in inputs]}"
                    )

        except Exception as e:
            print_warning(f"Form scan failed: {e}")

        return forms_found
