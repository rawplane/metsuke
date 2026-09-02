"""
Report generator for penetration testing results.
Supports HTML, JSON, and TXT report formats.
"""

import json
import os
from datetime import datetime
from typing import Dict

from src.core.models import ScanResult
from src.core.logger import Logger


class ReportGenerator:
    """Generate penetration test reports in multiple formats."""

    SEVERITY_COLORS = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d",
    }

    def __init__(self, logger: Logger, output_dir: str = "output"):
        self.logger = logger
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, result: ScanResult, fmt: str = "all") -> Dict[str, str]:
        """
        Generate report in specified format.
        Returns dict of format -> file path.
        """
        result.end_time = datetime.now().isoformat()
        files = {}

        if fmt in ("all", "html"):
            files["html"] = self._generate_html(result)
        if fmt in ("all", "json"):
            files["json"] = self._generate_json(result)
        if fmt in ("all", "txt"):
            files["txt"] = self._generate_txt(result)

        self.logger.success(
            f"Report(s) generated: {', '.join(files.values())}"
        )
        return files

    def _generate_json(self, result: ScanResult) -> str:
        """Generate JSON report."""
        filepath = os.path.join(self.output_dir, "report.json")

        # Serialize recon_data, converting any Finding objects to dicts
        recon_data = {}
        for key, value in result.recon_data.items():
            if key == "findings" and isinstance(value, list):
                recon_data[key] = [
                    f.to_dict() if hasattr(f, "to_dict") else f
                    for f in value
                ]
            elif isinstance(value, list):
                recon_data[key] = [
                    f.to_dict() if hasattr(f, "to_dict") else f
                    for f in value
                ]
            else:
                recon_data[key] = value

        data = {
            "target": result.target_url,
            "scan_start": result.start_time,
            "scan_end": result.end_time,
            "summary": result.get_summary(),
            "tech_stack": result.tech_stack,
            "recon_data": recon_data,
            "stats": result.stats,
            "findings": [f.to_dict() for f in result.findings],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    def _generate_txt(self, result: ScanResult) -> str:
        """Generate plain text report."""
        filepath = os.path.join(self.output_dir, "report.txt")
        summary = result.get_summary()

        lines = []
        lines.append("=" * 70)
        lines.append("  PIPELINE PENETRATION TEST REPORT")
        lines.append("=" * 70)
        lines.append(f"  Target:      {result.target_url}")
        lines.append(f"  Start Time:  {result.start_time}")
        lines.append(f"  End Time:    {result.end_time}")
        lines.append("")
        lines.append("  FINDINGS SUMMARY:")
        lines.append(f"    Critical:  {summary['critical']}")
        lines.append(f"    High:      {summary['high']}")
        lines.append(f"    Medium:    {summary['medium']}")
        lines.append(f"    Low:       {summary['low']}")
        lines.append(f"    Info:      {summary['info']}")
        lines.append(f"    TOTAL:     {summary['total']}")
        lines.append("")
        if result.tech_stack:
            lines.append(f"  Technologies Detected: {', '.join(result.tech_stack)}")
            lines.append("")

        for finding in result.findings:
            lines.append("-" * 70)
            lines.append(f"  [{finding.severity.upper()}] {finding.title}")
            lines.append(f"  URL: {finding.url}")
            if finding.parameter:
                lines.append(f"  Parameter: {finding.parameter}")
            if finding.payload:
                lines.append(f"  Payload: {finding.payload}")
            lines.append(f"  Description: {finding.description}")
            if finding.evidence:
                lines.append(f"  Evidence: {finding.evidence[:200]}")
            if finding.cwe_id:
                lines.append(f"  CWE: {finding.cwe_id}")
            if finding.remediation:
                lines.append(f"  Remediation: {finding.remediation}")
            lines.append(f"  Timestamp: {finding.timestamp}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return filepath

    def _generate_html(self, result: ScanResult) -> str:
        """Generate HTML report."""
        filepath = os.path.join(self.output_dir, "report.html")
        summary = result.get_summary()

        findings_html = ""
        for finding in result.findings:
            color = self.SEVERITY_COLORS.get(finding.severity.lower(), "#6c757d")
            evidence_html = ""
            if finding.evidence:
                evidence_html = (
                    f'<div class="evidence"><strong>Evidence:</strong>'
                    f'<pre>{self._escape_html(finding.evidence[:500])}</pre></div>'
                )
            param_html = f"<tr><td>Parameter</td><td><code>{finding.parameter}</code></td></tr>" if finding.parameter else ""
            payload_html = f"<tr><td>Payload</td><td><code>{self._escape_html(finding.payload)}</code></td></tr>" if finding.payload else ""
            cwe_html = f"<tr><td>CWE</td><td>{finding.cwe_id}</td></tr>" if finding.cwe_id else ""
            remediation_html = f'<div class="remediation"><strong>Remediation:</strong> {self._escape_html(finding.remediation)}</div>' if finding.remediation else ""

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header" style="background-color: {color}20;">
                    <span class="severity-badge" style="background-color: {color};">{finding.severity.upper()}</span>
                    <span class="finding-title">{self._escape_html(finding.title)}</span>
                </div>
                <table class="finding-details">
                    <tr><td>URL</td><td><code>{self._escape_html(finding.url)}</code></td></tr>
                    {param_html}
                    {payload_html}
                    {cwe_html}
                </table>
                <p>{self._escape_html(finding.description)}</p>
                {evidence_html}
                {remediation_html}
                <div class="timestamp">Found: {finding.timestamp}</div>
            </div>
            """

        tech_html = ""
        if result.tech_stack:
            tech_html = '<div class="tech-stack"><h3>Technologies Detected</h3><ul>'
            for tech in result.tech_stack:
                tech_html += f"<li>{self._escape_html(tech)}</li>"
            tech_html += "</ul></div>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self._escape_html(result.target_url)}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px;
               background-color: #f8f9fa; color: #333; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e);
                  color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header .meta {{ margin-top: 10px; font-size: 14px; color: #aaa; }}
        .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .summary-card {{ flex: 1; min-width: 120px; padding: 20px; border-radius: 10px;
                        text-align: center; color: white; }}
        .summary-card .count {{ font-size: 32px; font-weight: bold; }}
        .summary-card .label {{ font-size: 12px; text-transform: uppercase; }}
        .finding {{ background: white; margin: 15px 0; border-radius: 8px;
                   overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .finding-header {{ padding: 12px 20px; display: flex; align-items: center; gap: 15px; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 4px; color: white;
                          font-size: 11px; font-weight: bold; }}
        .finding-title {{ font-weight: bold; font-size: 16px; }}
        .finding-details {{ width: 100%; border-collapse: collapse; }}
        .finding-details td {{ padding: 6px 20px; border-bottom: 1px solid #eee; font-size: 13px; }}
        .finding-details td:first-child {{ width: 120px; font-weight: bold; color: #666; }}
        .finding p {{ padding: 0 20px; font-size: 14px; }}
        .evidence {{ margin: 10px 20px; background: #1e1e1e; border-radius: 5px; }}
        .evidence pre {{ color: #d4d4d4; padding: 15px; margin: 0; overflow-x: auto;
                        font-size: 12px; }}
        .remediation {{ margin: 10px 20px; padding: 10px 15px; background: #e8f5e9;
                       border-radius: 5px; font-size: 14px; }}
        .timestamp {{ padding: 8px 20px; font-size: 11px; color: #999; }}
        .tech-stack {{ background: white; padding: 20px; border-radius: 8px;
                      margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .tech-stack ul {{ padding-left: 20px; }}
        .tech-stack li {{ margin: 5px 0; }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px;
                font-family: 'Fira Code', monospace; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Pipeline Penetration Test Report</h1>
        <div class="meta">
            Target: {self._escape_html(result.target_url)}<br>
            Scan Start: {result.start_time} | End: {result.end_time}
        </div>
    </div>

    <div class="summary">
        <div class="summary-card" style="background-color: {self.SEVERITY_COLORS['critical']};">
            <div class="count">{summary['critical']}</div><div class="label">Critical</div>
        </div>
        <div class="summary-card" style="background-color: {self.SEVERITY_COLORS['high']};">
            <div class="count">{summary['high']}</div><div class="label">High</div>
        </div>
        <div class="summary-card" style="background-color: {self.SEVERITY_COLORS['medium']};">
            <div class="count">{summary['medium']}</div><div class="label">Medium</div>
        </div>
        <div class="summary-card" style="background-color: {self.SEVERITY_COLORS['low']};">
            <div class="count">{summary['low']}</div><div class="label">Low</div>
        </div>
        <div class="summary-card" style="background-color: {self.SEVERITY_COLORS['info']};">
            <div class="count">{summary['info']}</div><div class="label">Info</div>
        </div>
    </div>

    {tech_html}

    <h2>Findings ({summary['total']} total)</h2>
    {findings_html if findings_html else '<p style="color: green; font-weight: bold;">No vulnerabilities found.</p>'}

    <div style="text-align: center; margin: 30px 0; color: #999; font-size: 12px;">
        Generated by Pipeline Penetration Tester v1.0
    </div>
</body>
</html>"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        text = str(text)
        return (text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#x39;"))
