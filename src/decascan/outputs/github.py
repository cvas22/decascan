"""GitHub Actions workflow commands: findings show up as annotations on the PR diff and run page.

https://docs.github.com/actions/reference/workflow-commands-for-github-actions
"""

from __future__ import annotations

from ..core.findings import Finding, Severity
from ..core.scanner import ScanResult

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _escape_data(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _annotation(finding: Finding, file_path: str) -> str:
    props = [f"file={_escape_property(file_path)}"]
    if finding.line:
        props.append(f"line={finding.line}")
    props.append(f"title={_escape_property(f'{finding.rule_id} {finding.title}')}")
    message = f"{finding.description} Fix: {finding.remediation}"
    return f"::{_LEVEL[finding.severity]} {','.join(props)}::{_escape_data(message)}"


def render(result: ScanResult, version: str = "0.1.0") -> str:
    lines = [_annotation(f, result.repo_path(f)) for f in result.findings]
    for error in result.errors:
        lines.append(f"::warning title=decascan::{_escape_data(error)}")
    counts = result.counts_by_severity()
    summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n) or "no findings"
    lines.append(f"::notice title=decascan {version}::{result.files_scanned} files scanned: {summary}")
    return "\n".join(lines)
