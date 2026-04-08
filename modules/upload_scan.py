import requests
import io
from modules.base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_error, print_warning, Colors
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class UploadScanner(VulnerabilityScanner):
    """
    Tests for unrestricted file upload vulnerabilities by attempting
    to upload files with dangerous extensions.
    """
    def __init__(self, target_url, session):
        super().__init__(target_url, session)
        self.test_files = [
            {
                "filename": "test_scan.php",
                "content": b"<?php echo 'UPLOAD_TEST'; ?>",
                "content_type": "application/x-php",
                "description": "PHP web shell"
            },
            {
                "filename": "test_scan.exe",
                "content": b"MZ_FAKE_EXE_TEST",
                "content_type": "application/x-msdownload",
                "description": "Executable file"
            },
            {
                "filename": "test_scan.html",
                "content": b"<script>alert('XSS')</script>",
                "content_type": "text/html",
                "description": "HTML file with JavaScript"
            },
        ]

    def scan(self):
        print_info("Starting File Upload Scan...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                file_inputs = form.find_all('input', {'type': 'file'})
                if not file_inputs:
                    continue
                
                action = form.get('action')
                target_url = urljoin(self.target_url, action) if action else self.target_url
                
                print_info(f"Found upload form at {target_url}")
                
                form_data = {}
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    inp_type = inp.get('type', 'text')
                    if name and inp_type != 'file':
                        form_data[name] = inp.get('value', 'test')
                
                for ta in form.find_all('textarea'):
                    name = ta.get('name')
                    if name:
                        form_data[name] = 'test description'
                
                file_input_name = file_inputs[0].get('name', 'file')
                
                for test_file in self.test_files:
                    try:
                        files = {
                            file_input_name: (
                                test_file["filename"],
                                io.BytesIO(test_file["content"]),
                                test_file["content_type"]
                            )
                        }
                        
                        res = self.session.post(target_url, data=form_data, files=files, timeout=10)
                        
                        if res.status_code in [200, 201, 301, 302]:
                            is_accepted = (
                                res.status_code in [301, 302] or
                                'success' in res.text.lower() or
                                'uploaded' in res.text.lower() or
                                test_file["filename"] in res.text
                            )
                            if is_accepted:
                                fname = test_file['filename']
                                print_error(f"Unrestricted Upload: {fname} accepted!")
                                self.add_finding(
                                    "Unrestricted File Upload",
                                    f"Server accepted upload of {test_file['description']} ({fname}). No file type validation detected.",
                                    "High",
                                    url=target_url,
                                    payload=f"Filename: {fname}, Content-Type: {test_file['content_type']}",
                                    evidence=f"Server responded with status {res.status_code}",
                                )
                                break
                                
                    except requests.RequestException:
                        pass
                        
        except Exception as e:
            print_warning(f"Upload scan failed: {e}")

        return self.vulnerabilities
