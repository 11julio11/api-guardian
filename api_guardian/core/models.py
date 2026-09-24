"""Data models for API Guardian findings and audit reports."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def badge_color(self) -> str:
        colors = {
            "CRITICAL": "#b91c1c",  # Dark Red
            "HIGH": "#ea580c",      # Orange
            "MEDIUM": "#ca8a04",    # Amber/Yellow
            "LOW": "#2563eb",       # Blue
            "INFO": "#4b5563",      # Gray
        }
        return colors.get(self.value, "#4b5563")

    @property
    def emoji(self) -> str:
        emojis = {
            "CRITICAL": "🛑",
            "HIGH": "🔴",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "ℹ️",
        }
        return emojis.get(self.value, "ℹ️")


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    location: str
    description: str
    impact: str
    remediation: str
    evidence: Optional[str] = None
    cwe: Optional[str] = None
    owasp_api_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "location": self.location,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "owasp_api_id": self.owasp_api_id,
        }


@dataclass
class AuditReport:
    target: str
    mode: str
    findings: List[Finding] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def counts(self) -> Dict[str, int]:
        tally = {s.value: 0 for s in Severity}
        for f in self.findings:
            tally[f.severity.value] += 1
        return tally

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> Optional[Severity]:
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for s in order:
            if any(f.severity == s for f in self.findings):
                return s
        return None
