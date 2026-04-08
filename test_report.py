
from utils.reporter import Reporter
from datetime import datetime

# Dummy vulnerability data matching the scanner's format
dummy_vulns = [
    {
        "type": "SQL Injection",
        "severity": "High",
        "description": "Form at http://example.com/login returned SQL error.",
        "url": "http://example.com/login",
        "payload": "' OR '1'='1",
        "evidence": "you have an error in your sql syntax",
        "poc": "curl -X POST ..."
    },
    {
        "type": "Reflected XSS",
        "severity": "High",
        "description": "Payload reflected in response.",
        "url": "http://example.com/search?q=test",
        "payload": "<script>alert(1)</script>",
        "evidence": "<script>alert(1)</script>",
        "poc": "http://example.com/search?q=<script>alert(1)</script>"
    },
    {
        "type": "Missing Header",
        "severity": "Low",
        "description": "X-Frame-Options header is missing.",
        "url": "http://example.com",
        "payload": None,
        "evidence": "Header not present",
        "poc": None
    }
]

print("Generating test report...")
reporter = Reporter(dummy_vulns)
reporter.output_file = "test_report.html"
success = reporter.generate_report()

if success:
    print("Report generated successfully as test_report.html")
else:
    print("Failed to generate report")
