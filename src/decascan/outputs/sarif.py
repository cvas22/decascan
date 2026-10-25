"""SARIF 2.1.0 — the format GitHub Code Scanning ingests."""

from __future__ import annotations

import hashlib
import json

from ..core.findings import Finding, Severity
from ..core.scanner import ScanResult
from ..core.standards import RISK_NAMES, STANDARDS
from ..rules import all_rules

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_URI = "https://github.com/cvas22/decascan"

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


def _rule_descriptors() -> list[dict]:
    descriptors = []
    for rule in all_rules():
        standard = STANDARDS[rule.standard]
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
                        f"Maps to {standard.name} **{rule.mcp_id}: "
                        f"{RISK_NAMES.get(rule.mcp_id, '')}** (v{standard.version})."
                    ),
                },
                "properties": {
                    "tags": ["security", rule.standard, f"OWASP-{rule.mcp_id}"],
                    "mcpId": rule.mcp_id,
                    "standard": rule.standard,
                },
            }
        )
    return descriptors


def to_sarif(result: ScanResult, version: str = "0.1.0") -> dict:
    results = []
    for finding in result.findings:
        location: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": result.repo_path(finding), "uriBaseId": "%SRCROOT%"},
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
                "partialFingerprints": {"decascanFingerprint/v1": _fingerprint(finding)},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                    "mcpId": finding.mcp_id,
                    "standard": finding.standard,
                    "alsoMapsTo": finding.metadata.get("also_maps_to"),
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
                        "name": "decascan",
                        "version": version,
                        "informationUri": TOOL_URI,
                        "semanticVersion": version,
                        "rules": _rule_descriptors(),
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
