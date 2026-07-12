"""The Finding model — the single currency every rule produces and every output consumes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self.value)

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank > other.rank

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(raw.strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {raw!r} (expected one of: {valid})") from exc


# Human-readable names for the OWASP MCP Top 10, keyed by risk id. Findings carry the id;
# outputs render the title. Pinned to the MCP Top 10 version in OWASP_MCP_TOP10_VERSION.
OWASP_MCP_TOP10_VERSION = "0.1"

MCP_RISKS: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Supply Chain / Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit & Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}


@dataclass(frozen=True)
class Finding:
    """One vulnerability at one location.

    `rule_id` identifies the check that fired (stable, used for suppression and SARIF rule
    definitions); `mcp_id` identifies the OWASP risk class it maps to.
    """

    rule_id: str
    mcp_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    remediation: str
    line: int | None = None
    snippet: str | None = None
    cwe_id: str | None = None
    confidence: float = 1.0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def risk_name(self) -> str:
        return MCP_RISKS.get(self.mcp_id, "Unknown risk")

    @property
    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.mcp_id, self.file_path, self.line or 0, self.rule_id)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "mcp_id": self.mcp_id,
            "risk_name": self.risk_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line": self.line,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }
