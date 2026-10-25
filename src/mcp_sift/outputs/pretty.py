"""Human-readable terminal output. The format most people will ever see, so it does the work:
severity up front, the line that caused it, and how to fix it — no cross-referencing required.

Everything printed here is sanitized against the console's real encoding first. A legacy Windows
console is cp1252, and it cannot encode a box-drawing character — nor whatever happens to be in a
snippet pulled from someone else's source file. A scanner that dies with a UnicodeEncodeError
instead of reporting a critical finding is worse than useless.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.findings import Finding, Severity
from ..core.scanner import ScanResult

_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_LABEL_STYLE = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


# Typographic characters that carry meaning, with an ASCII spelling that keeps it. Falling straight
# through to `errors="replace"` would turn every em dash in a remediation into a `?`.
_TRANSLITERATIONS = {
    "—": "--",
    "–": "-",
    "…": "...",
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
    "→": "->",
    "×": "x",
    "·": "-",
    "│": "|",
}


class _Writer:
    """Prints Text, but never anything the target console can't encode."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.encoding = getattr(console.file, "encoding", None) or "utf-8"
        # Anything but UTF-8 gets ASCII punctuation. A legacy Windows console reports cp1252 while
        # actually rendering cp437, so a character being *encodable* is no promise it is legible --
        # the em dash survives encoding and comes out as mojibake. Only UTF-8 is trustworthy.
        self.ascii_only = "utf" not in self.encoding.lower().replace("-", "")
        self.bar = "|" if self.ascii_only else "│"
        self.dot = "-" if self.ascii_only else "·"

    def _encodable(self, text: str) -> bool:
        try:
            text.encode(self.encoding)
        except (UnicodeEncodeError, LookupError):
            return False
        return True

    def safe(self, text: str) -> str:
        if self.ascii_only:
            for char, replacement in _TRANSLITERATIONS.items():
                text = text.replace(char, replacement)
        if self._encodable(text):
            return text
        # Whatever is left is from the user's own source; mangle it rather than crash.
        return text.encode(self.encoding, errors="replace").decode(self.encoding, errors="replace")

    def line(self, text: str = "", style: str = "") -> None:
        self.console.print(Text(self.safe(text), style=style))

    def pair(self, label: str, label_style: str, body: str) -> None:
        self.console.print(
            Text(self.safe(label), style=label_style) + Text(self.safe(body))
        )


def render(result: ScanResult, console: Console | None = None, show_info: bool = True) -> None:
    console = console or Console()
    writer = _Writer(console)

    findings = [f for f in result.findings if show_info or f.severity != Severity.INFO]

    if not findings:
        console.print()
        console.print(
            Panel(
                Text(
                    writer.safe(
                        f"No findings. Scanned {result.files_scanned} files with "
                        f"{result.rules_run} rules in {result.duration_seconds:.2f}s."
                    ),
                    style="green",
                ),
                title="mcp-sift",
                border_style="green",
            )
        )
        _print_errors(result, writer)
        return

    _print_detection(result, writer)
    console.print()
    for finding in findings:
        _print_finding(finding, writer)

    _print_summary(result, findings, writer)
    _print_errors(result, writer)


def _print_finding(finding: Finding, writer: _Writer) -> None:
    header = Text()
    header.append(f" {finding.severity.value.upper()} ", style=_STYLE[finding.severity])
    header.append(f" {finding.mcp_id} ", style="bold")
    header.append(writer.safe(finding.risk_name), style="dim")
    header.append(f"  [{finding.rule_id}]", style="dim")
    writer.console.print(header)

    location = f"{finding.file_path}:{finding.line}" if finding.line else finding.file_path
    writer.line(f"  {finding.title}", style="bold")
    writer.line(f"  {location}", style="dim underline")

    if finding.snippet:
        writer.line(f"  {writer.bar} {finding.snippet}", style="dim")

    writer.line(f"  {finding.description}")
    writer.pair("  Fix: ", "bold green", finding.remediation)

    meta = []
    if finding.cwe_id:
        meta.append(finding.cwe_id)
    if finding.confidence < 1.0:
        meta.append(f"confidence {finding.confidence:.0%}")
    if meta:
        writer.line(f"  {f' {writer.dot} '.join(meta)}", style="dim")
    writer.console.print()


def _print_summary(result: ScanResult, shown: list[Finding], writer: _Writer) -> None:
    counts = result.counts_by_severity()
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Severity")
    table.add_column("Count", justify="right")

    for severity in Severity:
        count = counts[severity.value]
        if count:
            table.add_row(Text(severity.value.upper(), style=_LABEL_STYLE[severity]), str(count))

    writer.console.print(table)
    writer.line(
        f"\n{len(shown)} finding(s) across {result.files_scanned} files "
        f"({result.rules_run} rules, {result.duration_seconds:.2f}s)",
        style="dim",
    )


def _print_detection(result: ScanResult, writer: _Writer) -> None:
    if not result.detected:
        return
    parts = [f"{sid} ({', '.join(why)})" for sid, why in sorted(result.detected.items())]
    writer.line("Auto-detected: " + "; ".join(parts), style="dim")
    writer.line("Override with --standard mcp|llm|web|all.", style="dim")


def _print_errors(result: ScanResult, writer: _Writer) -> None:
    if not result.errors:
        return
    writer.console.print()
    for error in result.errors:
        writer.line(f"  warning: {error}", style="yellow")
