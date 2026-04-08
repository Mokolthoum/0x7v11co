# 🛡️ 0x7v11co - Advanced Web Vulnerability Scanner

<div align="center">
  <h3>Advanced Web Vulnerability Scanner and Security Assessment Tool</h3>
  <p>Developed and enhanced to deliver professional, comprehensive reports (PDF-ready/HTML) for penetration testers.</p>
</div>

---

## 🌟 Features
- **12 Dedicated Scanning Modules**: Includes SQLi, XSS, LFI, RCE, Admin Panel Enum, File Upload vulnerabilities, and more.
- **Professional Reporting**: Export beautifully formatted, PDF-ready HTML, CSV, or JSON reports.
- **Deep Web Crawler**: Extract hidden links, map directories, and build a complete site structure.
- **Multi-threading Engine**: Lightning-fast performance with customizable thread counts.
- **WAF Bypass Capabilities**: Intelligent mechanisms to evade and bypass Web Application Firewalls.
- **Authenticated Scanning**: Support for custom cookies and sessions to scan protected admin panels.

## 🛠️ Requirements
Ensure Python 3 and basic networking tools are installed. Install required dependencies before starting:
```bash
pip install -r requirements.txt
```

## 🚀 Installation
Clone this repository locally and start scanning immediately:
```bash
git clone https://github.com/Mokolthoum/0x7v11co.git
cd 0x7v11co
pip install -r requirements.txt
```

## 🎯 Usage

### 1️⃣ Comprehensive Scan
Scan the target using all available modules and the deep crawler:
```bash
python3 main.py http://example.com --crawl
```

### 2️⃣ Custom & Fast Scan
Select specific vulnerabilities to look for, speeding up the process:
```bash
python3 main.py http://example.com --sqli --xss
```

### 3️⃣ Generate Professional Reports
Export your scan results into an interactive HTML or JSON/CSV report ready for clients:
```bash
python3 main.py http://example.com --html --json
```

## 📂 Project Structure
```text
0x7v11co/
├── main.py                 # Initial entry point and engine orchestrator
├── modules/                # 12 Independent vulnerability scanning modules
├── utils/                  # Helper utilities (Reporter, Colors, etc.)
├── requirements.txt        # Python dependencies
└── reports/                # Generated reports directory (HTML, JSON, CSV) 
```

---
**Disclaimer:**
This tool is strictly intended for educational purposes and authorized security testing. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
