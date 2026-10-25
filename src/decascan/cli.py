"""`decascan` command line."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .catalog import build_catalog, export_catalog, load_cached_catalog, load_cached_standard
from .core import log as logging_setup
from .core.config import ScanConfig
from .core.findings import Severity
from .core.scanner import scan
from .core.standards import RISK_NAMES, STANDARDS
from .outputs import github, json_out, pretty, sarif
from .rules import all_rules

SEVERITIES = [s.value for s in Severity]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="decascan")
@click.option(
    "-v",
    "--verbose",
    count=True,
    envvar=["DECASCAN_VERBOSE", "MCP_SIFT_VERBOSE"],  # the second is the pre-rename name
    help="Log diagnostics to stderr: -v for progress, -vv for per-rule timings and skipped files.",
)
@click.option(
    "--log-file",
    type=click.Path(path_type=Path),
    envvar=["DECASCAN_LOG_FILE", "MCP_SIFT_LOG_FILE"],  # the second is the pre-rename name
    help="Write the log to this file instead of stderr (implies -v when no -v is given).",
)
@click.option(
    "--log-format",
    type=click.Choice(list(logging_setup.FORMATS)),
    default="text",
    envvar=["DECASCAN_LOG_FORMAT", "MCP_SIFT_LOG_FORMAT"],  # the second is the pre-rename name
    show_default=True,
    help="`json` writes one JSON object per line. The report itself is unaffected.",
)
@click.pass_context
def main(ctx: click.Context, verbose: int, log_file: Path | None, log_format: str) -> None:
    """Scan source against the OWASP Top 10 lists: MCP, LLM applications and web."""
    # Logging is opt-in so a plain run prints only the report. Asking for a file or a format
    # without -v still has to produce a log, at progress level.
    explicit = verbose > 0 or log_file is not None or ctx.get_parameter_source("log_format").name != "DEFAULT"
    if explicit:
        logging_setup.configure(verbose or 1, log_file, log_format)
    else:
        logging_setup.disable()


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
    type=click.Choice(["pretty", "json", "sarif", "github"]),
    default="pretty",
    help="Output format. `sarif` uploads to GitHub Code Scanning; `github` prints PR annotations.",
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
@click.option(
    "--repo-root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    envvar=["DECASCAN_REPO_ROOT", "MCP_SIFT_REPO_ROOT"],  # the second is the pre-rename name
    help=(
        "Repository root, so SARIF and annotations carry repo-relative paths when PATH is a "
        "subdirectory. [default: $GITHUB_WORKSPACE, else the nearest .git]"
    ),
)
@click.option(
    "--keep-duplicates",
    is_flag=True,
    help="Report a defect once per Top 10 list instead of merging it into one finding.",
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
    repo_root: Path | None,
    keep_duplicates: bool,
    no_fail: bool,
) -> None:
    """Scan a directory (or a single file)."""
    log = logging_setup.get_logger("cli")
    log.debug(
        "environment",
        extra={
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
    )
    log.info(
        "scan requested",
        extra={
            "path": str(path),
            "output": output,
            "output_file": str(output_file) if output_file else "stdout",
            "fail_on": fail_on,
            "no_fail": no_fail,
            "standards": ",".join(standards) or "auto",
        },
    )
    config = ScanConfig(
        fail_on=Severity.parse(fail_on),
        min_severity=Severity.parse(min_severity),
        standards=_resolve_standards(standards),
        repo_root=repo_root,
        merge_duplicates=not keep_duplicates,
        enabled_rules=frozenset(rules) if rules else None,
        disabled_rules=frozenset(disabled),
    )
    if excludes:
        config.excludes = config.excludes + tuple(excludes)

    unknown = (set(rules) | set(disabled)) - {r.id for r in all_rules()}
    if unknown:
        raise click.BadParameter(f"unknown rule id(s): {', '.join(sorted(unknown))}")

    try:
        result = scan(path, config)
        _emit(result, output, output_file)
    except (OSError, MemoryError, RecursionError, ValueError, RuntimeError) as exc:
        # Exit 1 means "findings"; a crash must not be mistaken for it by a pipeline.
        log.exception("scan aborted")
        click.echo(f"error: scan aborted: {type(exc).__name__}: {exc}", err=True)
        log.info("exiting", extra={"code": EXIT_ERROR, "reason": "scan aborted"})
        sys.exit(EXIT_ERROR)

    if no_fail:
        log.info("exiting", extra={"code": EXIT_OK, "reason": "--no-fail"})
        sys.exit(EXIT_OK)
    failing = result.should_fail(config.fail_on)
    worst = result.worst_severity()
    log.info(
        "exiting",
        extra={
            "code": EXIT_FINDINGS if failing else EXIT_OK,
            "reason": (
                f"finding at or above {fail_on}" if failing
                else f"nothing at or above {fail_on}" + (f" (worst: {worst.value})" if worst else "")
            ),
        },
    )
    sys.exit(EXIT_FINDINGS if failing else EXIT_OK)


def _emit(result, output: str, output_file: Path | None) -> None:
    log = logging_setup.get_logger("cli")
    destination = str(output_file) if output_file else "stdout"
    if output == "pretty":
        if output_file:
            with output_file.open("w", encoding="utf-8") as handle:
                pretty.render(result, Console(file=handle))
            size = output_file.stat().st_size
        else:
            pretty.render(result, Console())
            size = None
    else:
        renderer = {"json": json_out, "sarif": sarif, "github": github}[output]
        text = renderer.render(result, __version__)
        if output_file:
            output_file.write_text(text, encoding="utf-8")
            size = output_file.stat().st_size  # what is on disk, which can differ by line endings
        else:
            # A legacy console codepage (cp1252 on Windows) cannot encode every character in a message.
            encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
            click.echo(text.encode(encoding, errors="replace").decode(encoding))
            size = len(text.encode("utf-8"))
    log.info(
        "report written",
        extra={
            "format": output,
            "destination": destination,
            "findings": len(result.findings),
            **({"bytes": size} if size is not None else {}),
        },
    )


@main.command("rules")
@click.option("--standard", "-s", "standard", type=click.Choice(sorted(STANDARDS)), help="Only this list.")
def rules_command(standard: str | None) -> None:
    """List the built-in rules and the OWASP risks they map to."""
    console = Console()
    console.print(f"\n[bold]decascan {__version__}[/bold]\n")

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
    "--standard",
    "-s",
    "only",
    type=click.Choice(sorted(STANDARDS)),
    help="Only this list (with --json: just that list's file from the snapshot).",
)
@click.option(
    "--export",
    "export_path",
    type=click.Path(path_type=Path),
    help=(
        "Write the snapshot: a directory gets index.json plus one file per list (used to refresh "
        "src/decascan/data/top10/); a path ending in .json gets one combined file."
    ),
)
def standards_command(as_json: bool, cached: bool, only: str | None, export_path: Path | None) -> None:
    """Show each Top 10 list and which of its categories have rules."""
    if export_path:
        for written in export_catalog(export_path):
            click.echo(f"wrote {written}")
        return
    if as_json:
        if only:
            body = load_cached_standard(only) if cached else build_catalog()["standards"][only]
        else:
            body = load_cached_catalog() if cached else build_catalog()
        click.echo(json.dumps(body, indent=2))
        return

    console = Console()
    catalog = build_catalog()
    for standard in STANDARDS.values():
        if only and standard.id != only:
            continue
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
