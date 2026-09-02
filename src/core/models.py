"""
Data models for security findings discovered during penetration testing.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict


@dataclass
class Finding:
    """Represents a single security finding/vulnerability."""

    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    """Represents the complete result of a scan."""
    target_url: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    recon_data: Dict = field(default_factory=dict)
    tech_stack: List[str] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def has_critical(self) -> bool:
        """Check if any critical findings exist."""
        return len(self.get_findings_by_severity("critical")) > 0

    def get_summary(self) -> Dict:
        """Get a summary of findings by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            sev = finding.severity.lower()
            if sev in summary:
                summary[sev] += 1
        summary["total"] = len(self.findings)
        return summary
