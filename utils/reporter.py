import os
import json
import csv
import re
import html
from datetime import datetime

class Reporter:
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.output_file = "report.html"
        self.owasp_mapping = {
            "SQL Injection": "A03:2021-Injection",
            "SQL Injection (Error-Based)": "A03:2021-Injection",
            "SQL Injection (Boolean-Blind)": "A03:2021-Injection",
            "Reflected XSS": "A03:2021-Injection",
            "Local File Inclusion (LFI)": "A01:2021-Broken Access Control",
            "Input Fuzzing - Server Error": "A05:2021-Security Misconfiguration",
            "Input Fuzzing - Information Leak": "A05:2021-Security Misconfiguration",
            "Directory Discovery": "A01:2021-Broken Access Control",
            "WordPress User Enumeration": "A01:2021-Broken Access Control",
            "Technology Detection": "Info",
            "Proxy/WAF Detection": "Info",
            "Insecure Header": "A05:2021-Security Misconfiguration",
            "Missing Header": "A05:2021-Security Misconfiguration",
            "Missing Security Header": "A05:2021-Security Misconfiguration",
            "Form Issue": "A04:2021-Insecure Design",
            "Forms Discovered": "Info",
            "Subdomain Discovery": "Info",
            "Open Port": "A05:2021-Security Misconfiguration",
            "CSRF Missing": "A01:2021-Broken Access Control",
            "Insecure Cookie": "A05:2021-Security Misconfiguration",
            "Unrestricted File Upload": "A04:2021-Insecure Design",
        }
        
        self.remediation_db = {
            "SQL Injection": "Use prepared statements or parameterized queries. Never concatenate user input into SQL queries. Use Django ORM instead of raw SQL.",
            "Reflected XSS": "Encode user input before rendering it in the browser. Use Content Security Policy (CSP). In Django, avoid using the |safe filter on user input.",
            "Local File Inclusion (LFI)": "Validate user input against a whitelist of allowed files. Avoid passing user input directly to filesystem APIs. Use os.path.basename() to strip path traversal.",
            "Missing Security Header": "Configure your web server to send security headers like X-Frame-Options, HSTS, CSP, and X-Content-Type-Options.",
            "Missing Header": "Configure your web server to send security headers like X-Frame-Options, HSTS, and CSP.",
            "Directory Discovery": "Disable directory listing on the web server. Restrict access to sensitive directories. Remove backup files and dev logs from production.",
            "Open Port": "Close unnecessary ports using a firewall. Ensure services running on open ports are patched and secure.",
            "Subdomain Discovery": "Review exposed subdomains. Ensure dev/test environments are not publicly accessible if not intended.",
            "Technology Detection": "Minimize information leakage by hiding version numbers (e.g., 'Server' header, meta tags).",
            "Proxy/WAF Detection": "This is informational. Ensure your WAF is properly configured to block attacks and not just present.",
            "CSRF Missing": "Add CSRF protection tokens to all POST forms. In Django, enable CsrfViewMiddleware and use {% csrf_token %} in templates.",
            "Insecure Cookie": "Set HttpOnly and Secure flags on session cookies. Configure SameSite attribute. In Django, set SESSION_COOKIE_HTTPONLY=True and SESSION_COOKIE_SECURE=True.",
            "Unrestricted File Upload": "Validate file extensions and MIME types on the server side. Use a whitelist of allowed file types. Store uploaded files outside the web root.",
        }

    def save_json(self, filename="report.json"):
        """Save vulnerabilities to a JSON file."""
        data = {
            "scan_date": datetime.now().isoformat(),
            "total_issues": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving JSON report: {e}")
            return False

    def save_csv(self, filename="report.csv"):
        """Save vulnerabilities to CSV format."""
        try:
            with open(filename, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "Severity", "Description", "URL", "Payload", "Evidence", "PoC"])
                for v in self.vulnerabilities:
                    writer.writerow([
                        v.get("type", ""),
                        v.get("severity", ""),
                        v.get("description", ""),
                        v.get("url", ""),
                        v.get("payload", ""),
                        v.get("evidence", ""),
                        v.get("poc", "")
                    ])
            return True
        except Exception as e:
            print(f"Error saving CSV report: {e}")
            return False

    def save_markdown(self, filename="report.md"):
        """Save vulnerabilities to Markdown format."""
        try:
            with open(filename, "w") as f:
                f.write(f"# 0x7v11co Security Assessment Report\n\n")
                f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Total Issues:** {len(self.vulnerabilities)}\n\n")
                
                grouped = {}
                for v in self.vulnerabilities:
                    vtype = v.get("type", "Unknown")
                    if vtype not in grouped:
                        grouped[vtype] = []
                    grouped[vtype].append(v)
                
                f.write("## Summary\n\n")
                for vtype, items in grouped.items():
                    f.write(f"- **{vtype}**: {len(items)} finding(s)\n")
                
                f.write("\n## Detailed Findings\n\n")
                for vtype, items in grouped.items():
                    f.write(f"### {vtype}\n\n")
                    for item in items:
                        f.write(f"**Severity:** {item.get('severity', 'N/A')}\n\n")
                        f.write(f"**Description:** {item.get('description', 'N/A')}\n\n")
                        f.write(f"**URL:** `{item.get('url', 'N/A')}`\n\n")
                        if item.get('poc'):
                            f.write(f"**PoC:** `{item.get('poc')}`\n\n")
                        f.write("---\n\n")
            return True
        except Exception as e:
            print(f"Error saving Markdown report: {e}")
            return False

    def generate_report(self):
        # Severity ranking for comparison (higher = more severe)
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

        # Group vulnerabilities
        grouped_vulns = {}
        stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        
        for v in self.vulnerabilities:
            v_type = v['type']
            severity = v.get("severity", "Info")
            
            if severity in stats:
                stats[severity] += 1
            else:
                stats["Info"] += 1
                
            if v_type not in grouped_vulns:
                grouped_vulns[v_type] = {
                    "severity": severity,
                    "count": 0,
                    "items": [],
                    "owasp": self.owasp_mapping.get(v_type, "Uncategorized"),
                    "remediation": self.remediation_db.get(v_type, "Review finding and apply best practices.")
                }
                if grouped_vulns[v_type]["remediation"] == "Review finding and apply best practices.":
                     for key in self.remediation_db:
                         if key in v_type:
                             grouped_vulns[v_type]["remediation"] = self.remediation_db[key]
                             break
            else:
                # Update group severity to the highest severity found
                current = grouped_vulns[v_type]["severity"]
                if severity_rank.get(severity, 0) > severity_rank.get(current, 0):
                    grouped_vulns[v_type]["severity"] = severity
            
            grouped_vulns[v_type]["count"] += 1
            grouped_vulns[v_type]["items"].append(v)

        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebRisk Analysis Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --bg-panel: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --primary: #6366f1;
            --accent: #38bdf8;
            --border: #334155;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #3b82f6;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
        }}
        
        /* Sidebar */
        .sidebar {{
            width: 280px;
            background-color: var(--bg-panel);
            border-right: 1px solid var(--border);
            padding: 2rem;
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            overflow-y: auto;
        }}
        
        .brand {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .brand span {{ color: var(--primary); }}
        
        .nav-item {{
            display: block;
            padding: 0.75rem 1rem;
            color: var(--text-secondary);
            text-decoration: none;
            border-radius: 8px;
            margin-bottom: 0.5rem;
            transition: all 0.2s;
            font-weight: 500;
        }}
        .nav-item:hover, .nav-item.active {{
            background-color: rgba(99, 102, 241, 0.1);
            color: var(--primary);
        }}
        
        /* Main Content */
        .main-content {{
            margin-left: 280px;
            padding: 2.5rem;
            /* Width defaults to auto, filling remaining space */
        }}
        
        .header-section {{
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            margin-bottom: 3rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        
        .page-title h1 {{ font-size: 2.25rem; margin-bottom: 0.5rem; }}
        .meta-text {{ color: var(--text-secondary); font-size: 0.9rem; }}
        
        /* Stats Cards */
        .stats-container {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}
        
        .stat-card {{
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-value {{ font-size: 2.5rem; font-weight: 700; margin: 0.5rem 0; }}
        .stat-label {{ color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        
        .stat-card.critical .stat-value {{ color: var(--critical); }}
        .stat-card.high .stat-value {{ color: var(--high); }}
        .stat-card.medium .stat-value {{ color: var(--medium); }}
        .stat-card.low .stat-value {{ color: var(--low); }}
        .stat-card.info .stat-value {{ color: var(--info); }}
        
        /* Summary Section (Text + Chart) */
        .summary-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 3rem;
        }}
        
        .card {{
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
        }}
        
        .section-title {{
            font-size: 1.25rem;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .executive-summary p {{
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.7;
        }}
        
        /* Findings List */
        .findings-section {{
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }}
        
        .finding-group {{
            background: var(--bg-panel);
            border-radius: 16px;
            border: 1px solid var(--border);
            overflow: hidden;
        }}
        
        .finding-group-header {{
            padding: 1.5rem 2rem;
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        
        .finding-title-group {{ display: flex; align-items: center; gap: 1rem; }}
        
        .badge {{
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge.Critical {{ background: rgba(239, 68, 68, 0.15); color: var(--critical); }}
        .badge.High {{ background: rgba(249, 115, 22, 0.15); color: var(--high); }}
        .badge.Medium {{ background: rgba(234, 179, 8, 0.15); color: var(--medium); }}
        .badge.Low {{ background: rgba(34, 197, 94, 0.15); color: var(--low); }}
        .badge.Info {{ background: rgba(59, 130, 246, 0.15); color: var(--info); }}
        
        .finding-name {{ font-size: 1.1rem; font-weight: 600; }}
        
        .finding-content {{
            padding: 2rem;
        }}
        
        .finding-item {{
            margin-bottom: 2rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }}
        .finding-item:last-child {{ border-bottom: none; padding-bottom: 0; margin-bottom: 0; }}
        
        .detail-row {{ margin-bottom: 1rem; }}
        .detail-label {{ 
            font-size: 0.85rem; 
            color: var(--text-secondary); 
            margin-bottom: 0.5rem; 
            font-weight: 500;
            display: block;
        }}
        
        .code-block {{
            background: #0f172a;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: #e2e8f0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .remediation-box {{
            background: rgba(56, 189, 248, 0.1);
            border-left: 4px solid var(--accent);
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 1.5rem;
        }}
        .remediation-box h4 {{ color: var(--accent); margin-bottom: 0.5rem; font-size: 0.95rem; }}
        .remediation-box p {{ color: var(--text-secondary); font-size: 0.95rem; }}

        /* Tab content handling */
        .tab-content {{ display: none; animation: fadeIn 0.3s ease; }}
        .tab-content.active {{ display: block; }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="brand">
             Assessment<span>Report</span>
        </div>
        <nav>
            <a href="javascript:void(0)" class="nav-item active" onclick="switchTab('dashboard', this)">Dashboard</a>
            <div style="margin: 1.5rem 0 0.5rem 1rem; font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px;">Findings</div>
            {self._generate_sidebar_links(grouped_vulns)}
        </nav>
    </div>

    <div class="main-content">
        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <div class="header-section">
                <div class="page-title">
                    <h1>Security Assessment</h1>
                    <div class="meta-text">Target: 0x7v11co Analysis Target • Date: {datetime.now().strftime("%Y-%m-%d")}</div>
                </div>
                <div class="meta-text">Generated by WebRisk Evaluator</div>
            </div>

            <div class="stats-container">
                <div class="stat-card critical">
                    <div class="stat-label">Critical</div>
                    <div class="stat-value">{stats['Critical']}</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-label">High</div>
                    <div class="stat-value">{stats['High']}</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-label">Medium</div>
                    <div class="stat-value">{stats['Medium']}</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-label">Low</div>
                    <div class="stat-value">{stats['Low']}</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-label">Info</div>
                    <div class="stat-value">{stats['Info']}</div>
                </div>
            </div>

            <div class="summary-grid">
                <div class="card">
                    <div class="section-title">
                        <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        Executive Summary
                    </div>
                    <div class="executive-summary">
                        <p>The automated security scan has completed. A total of <strong>{len(self.vulnerabilities)}</strong> issues were identified, ranging from informational findings to potential critical vulnerabilities.</p>
                        <p>Notable areas of concern include {', '.join([k for k,v in stats.items() if v > 0 and k in ['Critical', 'High']]) if (stats['Critical'] > 0 or stats['High'] > 0) else "no high-risk vulnerabilities"}.</p>
                        <p>It is recommended to review the detailed findings below and prioritize remediation for Critical and High severity issues to mitigate potential exploitation risks.</p>
                    </div>
                </div>
                <div class="card">
                    <div class="section-title">Severity Distribution</div>
                    <div style="height: 300px; position: relative;">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Findings Tabs -->
        {self._generate_findings_html(grouped_vulns)}
    </div>

    <script>
        function switchTab(tabId, element) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {{
                tab.classList.remove('active');
            }});
            
            // Show target tab
            const target = document.getElementById(tabId);
            if (target) {{
                target.classList.add('active');
                window.scrollTo(0,0);
            }}

            // Update nav active state
            if (element) {{
                document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                element.classList.add('active');
            }}
        }}

        // Chart
        try {{
            const ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{{
                        data: [{stats['Critical']}, {stats['High']}, {stats['Medium']}, {stats['Low']}, {stats['Info']}],
                        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ position: 'bottom', labels: {{ color: '#94a3b8', padding: 20 }} }}
                    }},
                    cutout: '70%'
                }}
            }});
        }} catch (e) {{
            console.warn("Chart.js failed to load or initialize:", e);
        }}
    </script>
</body>
</html>
"""
        
        try:
            with open(self.output_file, "w") as f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"Error writing report: {e}")
            return False

    def _generate_sidebar_links(self, grouped_vulns):
        links = []
        for name, data in grouped_vulns.items():
            # Sanitize ID: lowercase, replace spaces with hyphens, remove non-alphanumeric chars (except hyphens)
            safe_id = re.sub(r'[^a-z0-9\-]+', '', name.lower().replace(" ", "-"))
            links.append(f'<a href="javascript:void(0)" class="nav-item" onclick="switchTab(\'{safe_id}\', this)">{html.escape(name)} <span style="float:right; opacity:0.5">{data["count"]}</span></a>')
        return "\n".join(links)

    def _generate_findings_html(self, grouped_vulns):
        html_out = []
        for name, data in grouped_vulns.items():
            safe_id = re.sub(r'[^a-z0-9\-]+', '', name.lower().replace(" ", "-"))
            
            items_html = ""
            for item in data["items"]:
                
                # Metadata blocks with escaping
                meta = []
                if item.get("url"):
                    meta.append(f'<div class="detail-row"><span class="detail-label">Vulnerable URL</span><div class="code-block">{html.escape(str(item["url"]))}</div></div>')
                
                if item.get("payload"):
                    meta.append(f'<div class="detail-row"><span class="detail-label">Payload</span><div class="code-block">{html.escape(str(item["payload"]))}</div></div>')
                    
                if item.get("evidence"):
                    evidence_text = html.escape(str(item["evidence"]))
                    meta.append(f'<div class="detail-row"><span class="detail-label">Evidence / Response</span><div class="code-block">{evidence_text}</div></div>')

                if item.get("poc"):
                    meta.append(f'<div class="detail-row"><span class="detail-label">Proof of Concept (PoC)</span><div class="code-block">{html.escape(str(item["poc"]))}</div></div>')

                items_html += f"""
                <div class="finding-item">
                    <div style="margin-bottom: 1rem; color: #f8fafc; font-size: 1.05rem;">{html.escape(str(item.get('description', 'No description provided.')))}</div>
                    {''.join(meta)}
                </div>
                """

            group_html = f"""
            <div id="{safe_id}" class="tab-content">
                <div class="header-section">
                    <div class="page-title">
                        <div class="finding-title-group">
                            <h1>{html.escape(name)}</h1>
                            <span class="badge {data['severity']}">{data['severity']}</span>
                        </div>
                        <div class="meta-text" style="font-family: 'JetBrains Mono'">OWASP: {html.escape(str(data['owasp']))}</div>
                    </div>
                </div>

                <div class="remediation-box" style="margin-bottom: 2rem;">
                    <h4>🛡️ Remediation Advice</h4>
                    <p>{html.escape(str(data['remediation']))}</p>
                </div>

                <div class="findings-section">
                    {items_html}
                </div>
            </div>
            """
            html_out.append(group_html)
        return "\n".join(html_out)
