"""`mcpaudit` command line."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .core.config import ScanConfig
from .core.findings import MCP_RISKS, OWASP_MCP_TOP10_VERSION, Severity
from .core.scanner import scan
from .outputs import json_out, pretty, sarif
from .rules import all_rules

SEVERITIES = [s.value for s in Severity]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="mcpaudit")
def main() -> None:
    """Audit an MCP server against the OWASP MCP Top 10."""


@main.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["pretty", "json", "sarif"]),
    default="pretty",
    help="Output format. `sarif` uploads to GitHub Code Scanning.",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(path_type=Path),
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITIES),
    default="high",
    help="Exit non-zero when a finding at this severity or above is present. [default: high]",
)
@click.option(
    "--min-severity",
    type=click.Choice(SEVERITIES),
    default="info",
    help="Drop findings below this severity entirely.",
)
@click.option("--rule", "rules", multiple=True, help="Run only these rule ids (repeatable).")
@click.option("--disable", "disabled", multiple=True, help="Skip these rule ids (repeatable).")
@click.option(
    "--exclude",
    "excludes",
    multiple=True,
    help="Extra directory names to skip, on top of the defaults (node_modules, .venv, ...).",
)
@click.option("--no-fail", is_flag=True, help="Always exit 0, whatever is found.")
def scan_command(
    path: Path,
    output: str,
    output_file: Path | None,
    fail_on: str,
    min_severity: str,
    rules: tuple[str, ...],
    disabled: tuple[str, ...],
    excludes: tuple[str, ...],
    no_fail: bool,
) -> None:
    """Scan an MCP server directory (or a single file)."""
    config = ScanConfig(
        fail_on=Severity.parse(fail_on),
        min_severity=Severity.parse(min_severity),
        enabled_rules=frozenset(rules) if rules else None,
        disabled_rules=frozenset(disabled),
    )
    if excludes:
        config.excludes = config.excludes + tuple(excludes)

    unknown = (set(rules) | set(disabled)) - {r.id for r in all_rules()}
    if unknown:
        raise click.BadParameter(f"unknown rule id(s): {', '.join(sorted(unknown))}")

    result = scan(path, config)

    if output == "pretty":
        console = Console(file=output_file.open("w", encoding="utf-8") if output_file else None)
        pretty.render(result, console)
    else:
        renderer = json_out if output == "json" else sarif
        text = renderer.render(result, __version__)
        if output_file:
            output_file.write_text(text, encoding="utf-8")
        else:
            click.echo(text)

    if no_fail:
        sys.exit(EXIT_OK)
    sys.exit(EXIT_FINDINGS if result.should_fail(config.fail_on) else EXIT_OK)


@main.command("rules")
def rules_command() -> None:
    """List the built-in rules and the OWASP risks they map to."""
    console = Console()
    console.print(f"\n[bold]mcpaudit {__version__}[/bold] — OWASP MCP Top 10 v{OWASP_MCP_TOP10_VERSION}\n")

    current = None
    for rule in all_rules():
        if rule.mcp_id != current:
            current = rule.mcp_id
            console.print(f"[bold]{rule.mcp_id}[/bold] [dim]{MCP_RISKS[rule.mcp_id]}[/dim]")
        console.print(f"  [cyan]{rule.id}[/cyan]  {rule.name}")
        console.print(f"          [dim]{rule.description}[/dim]")
    console.print()


if __name__ == "__main__":
    main()
