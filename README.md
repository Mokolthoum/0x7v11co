# 🛡️ AXON - Advanced Web Vulnerability Scanner

<div align="center">
  <h3>Next-Generation Web Vulnerability Scanner and Security Assessment Tool</h3>
  <p>Engineered for penetration testers, bug bounty hunters, and security researchers to detect critical vulnerabilities and generate automated, PDF-ready client reports.</p>
</div>

---

## 🌟 Core Features & Modules Overview

Our scanner is equipped with **12 independent, highly specialized scanning modules**:

| Module Name | Description | Flag |
|-------------|-------------|------|
| **SQLi Scanner** | Detects Error-based, Time-based, and Blind SQL Injections. | `--sqli` |
| **XSS Scanner** | Finds Reflected and Stored Cross-Site Scripting vulnerabilities via payloads. | `--xss` |
| **LFI Scanner** | Detects Local File Inclusion using dynamic path traversal vectors. | `--lfi` |
| **Command Injection** | Identifies OS Command Injection (RCE) flaws in exposed parameters. | `--rce` |
| **Admin Enum** | Brute-forces and discovers hidden administrative panels and directories. | `--admin` |
| **File Upload Scan** | Validates insecure file upload mechanisms preventing webshell execution. | `--upload` |
| **Subdomain Enum** | Discovers related subdomains for broader attack surface mapping. | `--subdomain` |
| **Header Scan** | Analyzes HTTP security headers and identifies misconfigurations. | `--headers` |
| **Form Analyzer** | Automatically crawls HTML forms and fuzzes them for weak validations. | `--forms` |
| **Proxy / WAF** | Detects Web Application Firewalls and attempts bypass techniques. | `--waf` |
| **WordPress Scan** | Enumerates plugins, themes, and known CVEs for WP instances. | `--wp` |
| **Port Scanner** | Identifies open ports and services running on the target server. | `--ports` |

---

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Mokolthoum/0x7v11co.git
   cd 0x7v11co
   ```
2. **Install Python dependencies:**
   Make sure you have Python 3.8+ installed. Run:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Advanced Usage & Examples

The tool is incredibly flexible. You can run individual modules to save time, or run everything at once for a deep security audit.

### 1️⃣ Full Deep Assessment (Comprehensive Scan)
To run all 12 modules and deeply crawl the website looking for hidden endpoints:
```bash
python3 main.py http://example.com --crawl --all
```

### 2️⃣ Targeted Scanning (Specific Vulnerabilities)
If you only want to focus on SQL Injections and XSS on a specific parameter:
```bash
python3 main.py http://example.com/page.php?id=1 --sqli --xss
```

### 3️⃣ Authenticated Scanning (Bypassing Login)
To scan pages behind a login screen (e.g., admin dashboards), pass your session cookie:
```bash
python3 main.py http://example.com/admin --cookie "PHPSESSID=your_session_hash_here; security=low" --all
```

### 4️⃣ Performance Tuning (Multi-threading)
Increase the speed of the scan by maximizing the worker threads (Default is 5):
```bash
python3 main.py http://example.com --threads 20 --admin --subdomain
```

---

## 📊 Automated Client Reporting 

One of the most powerful features of **AXON** is its enterprise-grade reporting engine. You can effortlessly generate reports ready to be delivered to developers or clients.

- **Generate HTML/PDF-ready Report (Highly Recommended):**
  This creates a visually stunning interactive dashboard that can be printed as a PDF.
  ```bash
  python3 main.py http://example.com --all --html
  ```
- **Export to JSON (For API Integration):**
  ```bash
  python3 main.py http://example.com --json
  ```
- **Export to CSV (For Excel Tracking):**
  ```bash
  python3 main.py http://example.com --csv
  ```

---

## 📂 Architecture Diagram
```text
AXON/
├── main.py                 # Core orchestrator and argument parser
├── modules/                # Directory containing the 12 scan engines
├── utils/                  # Reporting modules (reporter.py) and CLI styling
├── reports/                # Output directory for HTML/CSV deliverables
└── requirements.txt        # Third-party dependencies
```

---
**⚠️ Ethical Disclaimer:**
This security tool was designed strictly for offensive security professionals, pen-testers, and academic researchers. You must have explicit permission from the system owner before running this tool against any network. The creator assumes no liability for unauthorized usage.
