"""The Finding model — the single currency every rule produces and every output consumes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .standards import MCP, RISK_NAMES, RISK_STANDARD

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


# Kept for callers that predate multi-standard scanning; see core/standards.py for the full set.
OWASP_MCP_TOP10_VERSION = MCP.version
MCP_RISKS: dict[str, str] = MCP.risks


@dataclass(frozen=True)
class Finding:
    """One vulnerability at one location.

    `rule_id` identifies the check that fired (stable, used for suppression and SARIF rule
    definitions); `mcp_id` identifies the OWASP risk class it maps to. The field keeps its original
    name but holds the risk id of whichever standard the rule belongs to (`MCP05`, `LLM01`, ...).
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
        return RISK_NAMES.get(self.mcp_id, "Unknown risk")

    @property
    def standard(self) -> str:
        return RISK_STANDARD.get(self.mcp_id, "mcp")

    @property
    def sort_key(self) -> tuple:
        return (-self.severity.rank, self.mcp_id, self.file_path, self.line or 0, self.rule_id)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "standard": self.standard,
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
