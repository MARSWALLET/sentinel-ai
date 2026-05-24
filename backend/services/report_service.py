# ============================================
# SentinelAI - Report Service
# ============================================
"""
Professional report generation service.
Generates JSON, HTML, and PDF reports from scan data.
HTML reports feature branded layout, severity badges, collapsible sections, and charts.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from jinja2 import Environment, select_autoescape
from config import settings

logger = logging.getLogger(__name__)


# HTML Report Template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAI Security Report - {{ scan.input_value }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border-bottom: 3px solid #3b82f6;
            padding: 40px;
            margin: -20px -20px 40px;
        }
        .header-content { display: flex; align-items: center; justify-content: space-between; }
        .logo { display: flex; align-items: center; gap: 15px; }
        .logo-icon { font-size: 36px; }
        .logo-text { font-size: 28px; font-weight: 700; color: #3b82f6; }
        .logo-subtitle { font-size: 14px; color: #94a3b8; }
        .meta { text-align: right; }
        .meta-item { font-size: 13px; color: #94a3b8; }
        .meta-value { color: #e2e8f0; font-weight: 500; }
        
        /* Grade Badge */
        .grade-section { text-align: center; padding: 30px; background: #1e293b; border-radius: 12px; margin-bottom: 30px; }
        .grade-label { font-size: 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
        .grade-value {
            font-size: 96px; font-weight: 800; line-height: 1;
            {% if grade == 'A' %}color: #22c55e;{% elif grade == 'B' %}color: #84cc16;{% elif grade == 'C' %}color: #eab308;{% elif grade == 'D' %}color: #f97316;{% else %}color: #ef4444;{% endif %}
        }
        .grade-score { font-size: 24px; color: #64748b; margin-top: 10px; }
        
        /* Stats Grid */
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .stat-card { background: #1e293b; border-radius: 10px; padding: 24px; text-align: center; border-top: 3px solid var(--border-color); }
        .stat-number { font-size: 36px; font-weight: 700; color: var(--text-color); }
        .stat-label { font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-top: 8px; }
        .severity-critical { --border-color: #ef4444; --text-color: #ef4444; }
        .severity-high { --border-color: #f97316; --text-color: #f97316; }
        .severity-medium { --border-color: #eab308; --text-color: #eab308; }
        .severity-low { --border-color: #3b82f6; --text-color: #3b82f6; }
        .severity-info { --border-color: #64748b; --text-color: #64748b; }
        
        /* Executive Summary */
        .section { background: #1e293b; border-radius: 12px; padding: 30px; margin-bottom: 30px; }
        .section-title { font-size: 20px; font-weight: 600; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
        .section-title .icon { font-size: 24px; }
        .executive-text { font-size: 15px; line-height: 1.8; color: #cbd5e1; }
        
        /* Findings */
        .finding { border: 1px solid #334155; border-radius: 10px; margin-bottom: 16px; overflow: hidden; }
        .finding-header {
            padding: 18px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            transition: background 0.2s;
        }
        .finding-header:hover { background: #263449; }
        .finding-title { font-weight: 600; font-size: 15px; flex: 1; }
        .finding-badges { display: flex; gap: 8px; }
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; }
        .badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; }
        .badge-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; }
        .badge-info { background: rgba(100, 116, 139, 0.15); color: #64748b; }
        .finding-body { padding: 24px; border-top: 1px solid #334155; display: none; }
        .finding-body.active { display: block; }
        .field { margin-bottom: 16px; }
        .field-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
        .field-value { font-size: 14px; color: #e2e8f0; }
        .code-block {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 13px;
            overflow-x: auto;
            color: #cbd5e1;
            margin: 10px 0;
        }
        .code-before { border-left: 3px solid #ef4444; }
        .code-after { border-left: 3px solid #22c55e; }
        
        /* Toggle */
        .toggle-btn {
            background: none;
            border: none;
            color: #94a3b8;
            font-size: 20px;
            cursor: pointer;
            transition: transform 0.2s;
            margin-left: 10px;
        }
        .toggle-btn.active { transform: rotate(180deg); }
        
        /* References */
        .reference-list { list-style: none; }
        .reference-list li { margin-bottom: 8px; }
        .reference-list a { color: #3b82f6; text-decoration: none; }
        .reference-list a:hover { text-decoration: underline; }
        
        /* Compliance */
        .compliance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
        .compliance-item { background: #0f172a; padding: 16px; border-radius: 8px; }
        .compliance-name { font-weight: 600; color: #3b82f6; margin-bottom: 8px; }
        .compliance-text { font-size: 13px; color: #94a3b8; }
        
        /* Attack Chains */
        .chain { background: #0f172a; border-radius: 8px; padding: 20px; margin-bottom: 16px; border-left: 4px solid #ef4444; }
        .chain-title { font-weight: 600; margin-bottom: 10px; }
        .chain-steps { list-style: none; counter-reset: steps; }
        .chain-steps li { padding: 8px 0; padding-left: 30px; position: relative; }
        .chain-steps li::before { counter-increment: steps; content: counter(steps); position: absolute; left: 0; top: 8px; width: 20px; height: 20px; background: #334155; border-radius: 50%; text-align: center; font-size: 12px; line-height: 20px; }
        
        /* Footer */
        .footer { text-align: center; padding: 40px; color: #64748b; font-size: 13px; border-top: 1px solid #334155; margin-top: 40px; }
        
        /* Print styles */
        @media print {
            body { background: white; color: black; }
            .header { background: #f1f5f9; }
            .section { background: #f8fafc; break-inside: avoid; }
            .finding-body { display: block !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <div class="logo-icon">🛡️</div>
                    <div>
                        <div class="logo-text">SentinelAI</div>
                        <div class="logo-subtitle">AI-Powered Security Assessment Report</div>
                    </div>
                </div>
                <div class="meta">
                    <div class="meta-item">Target: <span class="meta-value">{{ scan.input_value }}</span></div>
                    <div class="meta-item">Type: <span class="meta-value">{{ scan.input_type }}</span></div>
                    <div class="meta-item">Date: <span class="meta-value">{{ scan.started_at.strftime('%Y-%m-%d %H:%M UTC') if scan.started_at else 'N/A' }}</span></div>
                    <div class="meta-item">Duration: <span class="meta-value">{{ scan.duration_seconds // 60 }}m {{ scan.duration_seconds % 60 }}s</span></div>
                </div>
            </div>
        </div>
        
        <!-- Grade -->
        <div class="grade-section">
            <div class="grade-label">Security Grade</div>
            <div class="grade-value">{{ grade }}</div>
            <div class="grade-score">Risk Score: {{ risk_score }}/100</div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card severity-critical">
                <div class="stat-number">{{ stats.critical }}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card severity-high">
                <div class="stat-number">{{ stats.high }}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card severity-medium">
                <div class="stat-number">{{ stats.medium }}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card severity-low">
                <div class="stat-number">{{ stats.low }}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card severity-info">
                <div class="stat-number">{{ stats.info }}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        {% if executive_summary %}
        <div class="section">
            <div class="section-title"><span class="icon">📋</span> Executive Summary</div>
            <div class="executive-text">{{ executive_summary }}</div>
        </div>
        {% endif %}
        
        <!-- Attack Chains -->
        {% if attack_chains %}
        <div class="section">
            <div class="section-title"><span class="icon">🔗</span> Attack Chains</div>
            {% for chain in attack_chains %}
            <div class="chain">
                <div class="chain-title">{{ chain.name }} ({{ chain.combined_severity | upper }})</div>
                <div class="field-value" style="margin-bottom: 12px;">{{ chain.description }}</div>
                <ol class="chain-steps">
                    {% for step in chain.attack_steps %}
                    <li>{{ step }}</li>
                    {% endfor %}
                </ol>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <!-- Findings -->
        <div class="section">
            <div class="section-title"><span class="icon">🐛</span> Findings ({{ findings | length }})</div>
            {% for finding in findings %}
            <div class="finding">
                <div class="finding-header" onclick="toggleFinding(this)">
                    <span class="finding-title">[{{ finding.module }}] {{ finding.title }}</span>
                    <div style="display: flex; align-items: center;">
                        <div class="finding-badges">
                            <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
                            {% if finding.cvss_score %}
                            <span class="badge badge-info">CVSS {{ finding.cvss_score }}</span>
                            {% endif %}
                            {% if finding.cwe_id %}
                            <span class="badge badge-info">{{ finding.cwe_id }}</span>
                            {% endif %}
                        </div>
                        <button class="toggle-btn">▼</button>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="field">
                        <div class="field-label">Description</div>
                        <div class="field-value">{{ finding.description }}</div>
                    </div>
                    
                    {% if finding.file_path %}
                    <div class="field">
                        <div class="field-label">Location</div>
                        <div class="field-value">{{ finding.file_path }}{% if finding.line_number %}:{{ finding.line_number }}{% endif %}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.url %}
                    <div class="field">
                        <div class="field-label">URL</div>
                        <div class="field-value">{{ finding.url }}{% if finding.parameter %} (param: {{ finding.parameter }}){% endif %}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.code_snippet %}
                    <div class="field">
                        <div class="field-label">Code Snippet</div>
                        <div class="code-block">{{ finding.code_snippet | e }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.evidence %}
                    <div class="field">
                        <div class="field-label">Evidence</div>
                        <div class="code-block">{{ finding.evidence | tojson(indent=2) | e }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.remediation %}
                    <div class="field">
                        <div class="field-label">Remediation</div>
                        <div class="field-value">{{ finding.remediation }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.remediation_steps %}
                    <div class="field">
                        <div class="field-label">Steps to Fix</div>
                        <ol>
                            {% for step in finding.remediation_steps %}
                            <li>{{ step }}</li>
                            {% endfor %}
                        </ol>
                    </div>
                    {% endif %}
                    
                    {% if finding.code_fix_before %}
                    <div class="field">
                        <div class="field-label">Before (Vulnerable)</div>
                        <div class="code-block code-before">{{ finding.code_fix_before | e }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.code_fix_after %}
                    <div class="field">
                        <div class="field-label">After (Fixed)</div>
                        <div class="code-block code-after">{{ finding.code_fix_after | e }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.ai_explanation %}
                    <div class="field">
                        <div class="field-label">AI Analysis</div>
                        <div class="field-value">{{ finding.ai_explanation }}</div>
                    </div>
                    {% endif %}
                    
                    {% if finding.references %}
                    <div class="field">
                        <div class="field-label">References</div>
                        <ul class="reference-list">
                            {% for ref in finding.references %}
                            <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <!-- Compliance -->
        {% if compliance_notes %}
        <div class="section">
            <div class="section-title"><span class="icon">⚖️</span> Compliance Notes</div>
            <div class="compliance-grid">
                {% for framework, note in compliance_notes.items() %}
                <div class="compliance-item">
                    <div class="compliance-name">{{ framework | upper }}</div>
                    <div class="compliance-text">{{ note }}</div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by SentinelAI v{{ version }} on {{ generated_at }}</p>
            <p>This report is confidential and intended solely for the authorized recipient.</p>
        </div>
    </div>
    
    <script>
        function toggleFinding(header) {
            const body = header.nextElementSibling;
            const btn = header.querySelector('.toggle-btn');
            body.classList.toggle('active');
            btn.classList.toggle('active');
        }
    </script>
</body>
</html>
"""


class ReportService:
    """Service for generating professional security reports."""
    
    def __init__(self):
        # Bug #27 fixed: use a Jinja2 Environment with autoescaping enabled so
        # that finding titles, descriptions, and URLs that contain HTML/JS
        # tags are escaped rather than rendered raw (XSS in generated reports).
        env = Environment(
            autoescape=select_autoescape(enabled_extensions=("html",), default_for_string=True),
        )
        self.template = env.from_string(HTML_TEMPLATE)
    
    async def generate_html_report(self, scan_id: str, report_data: Dict[str, Any]) -> str:
        """
        Generate an HTML report for a scan.
        
        Args:
            scan_id: The scan ID
            report_data: Dict with 'scan' and 'findings' keys
            
        Returns:
            Path to generated HTML file
        """
        scan = report_data["scan"]
        findings = report_data["findings"]
        
        # Prepare template data
        stats = {
            "critical": scan.stats_critical,
            "high": scan.stats_high,
            "medium": scan.stats_medium,
            "low": scan.stats_low,
            "info": scan.stats_info,
        }
        
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.severity, 5), -(f.cvss_score or 0)))
        
        # Build finding dicts
        finding_dicts = []
        for f in sorted_findings:
            fd = f.to_dict()
            # Truncate evidence for display
            if fd.get("evidence") and isinstance(fd["evidence"], dict):
                for k, v in fd["evidence"].items():
                    if isinstance(v, str) and len(v) > 1000:
                        fd["evidence"][k] = v[:1000] + "... [truncated]"
            finding_dicts.append(fd)
        
        template_data = {
            "scan": scan,
            "grade": scan.grade or "N/A",
            "risk_score": scan.risk_score or 0,
            "stats": stats,
            "executive_summary": scan.executive_summary,
            "attack_chains": scan.attack_chains or [],
            "findings": finding_dicts,
            "compliance_notes": scan.compliance_notes or {},
            "version": settings.APP_VERSION,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }
        
        # Render HTML
        html_content = self.template.render(**template_data)
        
        # Save to file
        report_dir = f"{settings.REPORTS_DIR}/{scan_id}"
        os.makedirs(report_dir, exist_ok=True)
        report_path = f"{report_dir}/report.html"
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_path} ({len(findings)} findings)")
        return report_path
    
    async def generate_pdf_report(self, scan_id: str, report_data: Dict[str, Any]) -> str:
        """
        Generate a PDF report from HTML using WeasyPrint.
        
        Args:
            scan_id: The scan ID
            report_data: Dict with 'scan' and 'findings' keys
            
        Returns:
            Path to generated PDF file
        """
        try:
            import weasyprint
        except ImportError:
            logger.error("WeasyPrint not available, cannot generate PDF")
            raise RuntimeError("PDF generation requires WeasyPrint")
        
        # Generate HTML first
        html_path = await self.generate_html_report(scan_id, report_data)
        
        # Convert to PDF
        report_dir = f"{settings.REPORTS_DIR}/{scan_id}"
        pdf_path = f"{report_dir}/report.pdf"
        
        html_doc = weasyprint.HTML(filename=html_path)
        html_doc.write_pdf(pdf_path)
        
        logger.info(f"PDF report generated: {pdf_path}")
        return pdf_path
    
    @staticmethod
    def to_json_report(scan: Any, findings: List[Any], output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a JSON report structure.
        Optionally writes to output_path atomically to avoid concurrent-write races.

        Returns:
            Dict with full report data
        """
        data = {
            "scan_id": scan.id,
            "target": scan.input_value,
            "scan_type": scan.input_type,
            "scan_date": scan.started_at.isoformat() if scan.started_at else None,
            "duration_seconds": scan.duration_seconds,
            "risk_score": scan.risk_score,
            "grade": scan.grade,
            "executive_summary": scan.executive_summary,
            "compliance_notes": scan.compliance_notes,
            "statistics": {
                "critical": scan.stats_critical,
                "high": scan.stats_high,
                "medium": scan.stats_medium,
                "low": scan.stats_low,
                "info": scan.stats_info,
                "total": scan.stats_total,
            },
            "attack_chains": scan.attack_chains,
            "findings": [f.to_dict() for f in findings],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": f"{settings.APP_NAME} v{settings.APP_VERSION}",
        }
        # Bug #24 fixed: write to a temp file then rename atomically so concurrent
        # requests cannot produce a partially-written / corrupted report file.
        if output_path:
            import tempfile
            dir_name = os.path.dirname(output_path)
            os.makedirs(dir_name, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".json",
                dir=dir_name, delete=False
            ) as tmp:
                json.dump(data, tmp, indent=2)
                tmp_path = tmp.name
            os.replace(tmp_path, output_path)  # atomic on POSIX
        return data