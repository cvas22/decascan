"""Machine-readable JSON, for pipelines that want to make their own decisions."""

from __future__ import annotations

import json

from ..core.findings import OWASP_MCP_TOP10_VERSION
from ..core.scanner import ScanResult


def to_dict(result: ScanResult, version: str = "0.1.0") -> dict:
    return {
        "tool": "mcp-sift",
        "version": version,
        "owasp_mcp_top10_version": OWASP_MCP_TOP10_VERSION,
        "summary": {
            "files_scanned": result.files_scanned,
            "rules_run": result.rules_run,
            "findings": len(result.findings),
            "by_severity": result.counts_by_severity(),
            "duration_seconds": round(result.duration_seconds, 3),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }


def render(result: ScanResult, version: str = "0.1.0") -> str:
    return json.dumps(to_dict(result, version), indent=2)
