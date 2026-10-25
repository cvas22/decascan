"""`mcp-sift` command line."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .catalog import build_catalog, export_catalog, load_cached_catalog
from .core.config import ScanConfig
from .core.findings import Severity
from .core.scanner import scan
from .core.standards import RISK_NAMES, STANDARDS
from .outputs import json_out, pretty, sarif
from .rules import all_rules

SEVERITIES = [s.value for s in Severity]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="mcp-sift")
def main() -> None:
    """Scan source against the OWASP Top 10 lists: MCP, LLM applications and web."""


def _resolve_standards(chosen: tuple[str, ...]) -> frozenset[str] | None:
    """None means auto-detect; otherwise the explicit set of lists."""
    if not chosen or chosen == ("auto",):
        return None
    if "auto" in chosen:
        raise click.BadParameter("`auto` cannot be combined with other lists", param_hint="--standard")
    if "all" in chosen:
        return frozenset(STANDARDS)
    return frozenset(chosen)


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
@click.option(
    "--standard",
    "-s",
    "standards",
    multiple=True,
    type=click.Choice(["auto", "all", *sorted(STANDARDS)]),
    help=(
        "Top 10 list(s) to scan against (repeatable). `auto` picks the lists that apply from the "
        "code's imports and dependencies; `all` runs every list. [default: auto]"
    ),
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
    standards: tuple[str, ...],
    rules: tuple[str, ...],
    disabled: tuple[str, ...],
    excludes: tuple[str, ...],
    no_fail: bool,
) -> None:
    """Scan a directory (or a single file)."""
    config = ScanConfig(
        fail_on=Severity.parse(fail_on),
        min_severity=Severity.parse(min_severity),
        standards=_resolve_standards(standards),
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
@click.option("--standard", "-s", "standard", type=click.Choice(sorted(STANDARDS)), help="Only this list.")
def rules_command(standard: str | None) -> None:
    """List the built-in rules and the OWASP risks they map to."""
    console = Console()
    console.print(f"\n[bold]mcp-sift {__version__}[/bold]\n")

    current = None
    for rule in all_rules():
        if standard and rule.standard != standard:
            continue
        if rule.mcp_id != current:
            current = rule.mcp_id
            console.print(
                f"[bold]{rule.mcp_id}[/bold] [dim]{RISK_NAMES[rule.mcp_id]}[/dim]"
            )
        console.print(f"  [cyan]{rule.id}[/cyan]  {rule.name}")
        console.print(f"          [dim]{rule.description}[/dim]")
    console.print()


@main.command("standards")
@click.option("--json", "as_json", is_flag=True, help="Print the catalog as JSON instead of a table.")
@click.option(
    "--cached",
    is_flag=True,
    help="With --json: print the snapshot shipped in the package rather than rebuilding it.",
)
@click.option(
    "--export",
    "export_path",
    type=click.Path(path_type=Path),
    help="Write the catalog snapshot to this file (used to refresh data/top10.json).",
)
def standards_command(as_json: bool, cached: bool, export_path: Path | None) -> None:
    """Show each Top 10 list and which of its categories have rules."""
    if export_path:
        export_catalog(export_path)
        click.echo(f"wrote {export_path}")
        return
    if as_json:
        click.echo(json.dumps(load_cached_catalog() if cached else build_catalog(), indent=2))
        return

    console = Console()
    catalog = build_catalog()
    for standard in STANDARDS.values():
        console.print(f"\n[bold]{standard.name}[/bold] [dim]({standard.id}, {standard.version})[/dim]")
        for risk in catalog["standards"][standard.id]["risks"]:
            if risk["status"] == "covered":
                status = f"[green]{len(risk['rules'])} rule(s)[/green]"
            elif risk["status"] == "not-static":
                status = "[dim]not static[/dim]"
            else:
                status = "[yellow]no rules yet[/yellow]"
            console.print(f"  {risk['id']:<7} {risk['name']:<50} {status}")
    console.print()


if __name__ == "__main__":
    main()
