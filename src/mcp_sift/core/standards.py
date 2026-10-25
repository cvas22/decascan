"""The OWASP Top 10 lists the scanner can report against.

A *standard* is one Top 10 list. Every rule belongs to exactly one, and every finding carries the
standard it came from, so a single scan can report against several lists at once and group the
output by list and category.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Standard:
    id: str  # short CLI name: `mcp`, `llm`, `web`
    name: str
    version: str
    risks: dict[str, str]
    # Risks no static scan of source can establish (a design flaw, a process gap, a model property).
    # They stay in the catalogue so a coverage report can say "not statically detectable" rather
    # than silently pretending a clean scan means the category was checked.
    not_static: frozenset[str] = frozenset()


MCP = Standard(
    id="mcp",
    name="OWASP MCP Top 10",
    version="0.1",
    risks={
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
    },
)

LLM = Standard(
    id="llm",
    name="OWASP Top 10 for LLM Applications",
    version="2025",
    risks={
        "LLM01": "Prompt Injection",
        "LLM02": "Sensitive Information Disclosure",
        "LLM03": "Supply Chain",
        "LLM04": "Data and Model Poisoning",
        "LLM05": "Improper Output Handling",
        "LLM06": "Excessive Agency",
        "LLM07": "System Prompt Leakage",
        "LLM08": "Vector and Embedding Weaknesses",
        "LLM09": "Misinformation",
        "LLM10": "Unbounded Consumption",
    },
    not_static=frozenset({"LLM04", "LLM08", "LLM09"}),
)

WEB = Standard(
    id="web",
    name="OWASP Top 10 (Web Application Security Risks)",
    version="2021",
    risks={
        "WEB01": "A01 Broken Access Control",
        "WEB02": "A02 Cryptographic Failures",
        "WEB03": "A03 Injection",
        "WEB04": "A04 Insecure Design",
        "WEB05": "A05 Security Misconfiguration",
        "WEB06": "A06 Vulnerable and Outdated Components",
        "WEB07": "A07 Identification and Authentication Failures",
        "WEB08": "A08 Software and Data Integrity Failures",
        "WEB09": "A09 Security Logging and Monitoring Failures",
        "WEB10": "A10 Server-Side Request Forgery",
    },
    # A04 is a design property. A06 needs a vulnerability database; use pip-audit / osv-scanner.
    not_static=frozenset({"WEB04", "WEB06"}),
)

STANDARDS: dict[str, Standard] = {s.id: s for s in (MCP, LLM, WEB)}

# Rule and finding risk ids are globally unique across standards, so a risk id alone resolves.
RISK_NAMES: dict[str, str] = {rid: name for s in STANDARDS.values() for rid, name in s.risks.items()}
RISK_STANDARD: dict[str, str] = {rid: s.id for s in STANDARDS.values() for rid in s.risks}


def get_standard(standard_id: str) -> Standard:
    try:
        return STANDARDS[standard_id]
    except KeyError as exc:
        valid = ", ".join(sorted(STANDARDS))
        raise ValueError(f"unknown standard {standard_id!r} (expected one of: {valid})") from exc
