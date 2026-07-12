"""SARIF 2.1.0 — the format GitHub Code Scanning ingests."""

from __future__ import annotations

import hashlib
import json

from ..core.findings import MCP_RISKS, OWASP_MCP_TOP10_VERSION, Finding, Severity
from ..core.scanner import ScanResult
from ..rules import all_rules

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_URI = "https://github.com/cvas22/mcpcheck"

# SARIF only has error/warning/note; GitHub renders severity from `security-severity` (a CVSS-ish
# number), so we emit both.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _fingerprint(finding: Finding) -> str:
    payload = f"{finding.rule_id}|{finding.file_path}|{finding.line}|{finding.title}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _rule_descriptors(version: str) -> list[dict]:
    descriptors = []
    for rule in all_rules():
        descriptors.append(
            {
                "id": rule.id,
                "name": rule.name.replace(" ", ""),
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.description},
                "helpUri": f"{TOOL_URI}/blob/main/docs/rules.md#{rule.id.lower()}",
                "help": {
                    "text": rule.description,
                    "markdown": (
                        f"**{rule.name}**\n\n{rule.description}\n\n"
                        f"Maps to OWASP MCP Top 10 **{rule.mcp_id}: "
                        f"{MCP_RISKS.get(rule.mcp_id, '')}** (v{version})."
                    ),
                },
                "properties": {
                    "tags": ["security", "mcp", f"OWASP-MCP-{rule.mcp_id}"],
                    "mcpId": rule.mcp_id,
                },
            }
        )
    return descriptors


def to_sarif(result: ScanResult, version: str = "0.1.0") -> dict:
    results = []
    for finding in result.findings:
        location: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path, "uriBaseId": "%SRCROOT%"},
            }
        }
        if finding.line:
            region: dict = {"startLine": finding.line}
            if finding.snippet:
                region["snippet"] = {"text": finding.snippet}
            location["physicalLocation"]["region"] = region

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {
                    "text": f"{finding.title}. {finding.description} Remediation: {finding.remediation}"
                },
                "locations": [location],
                "partialFingerprints": {"mcpcheckFingerprint/v1": _fingerprint(finding)},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                    "mcpId": finding.mcp_id,
                    "owaspRisk": finding.risk_name,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe_id,
                },
            }
        )

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpcheck",
                        "version": version,
                        "informationUri": TOOL_URI,
                        "semanticVersion": version,
                        "rules": _rule_descriptors(OWASP_MCP_TOP10_VERSION),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": error}}
                            for error in result.errors
                        ],
                    }
                ],
            }
        ],
    }


def render(result: ScanResult, version: str = "0.1.0") -> str:
    return json.dumps(to_sarif(result, version), indent=2)
