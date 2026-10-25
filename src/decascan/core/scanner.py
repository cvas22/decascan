"""Scanner — runs the rule registry over a ScanContext and returns sorted, de-duplicated findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ..rules import all_rules
from .config import DEFAULT_EXCLUDES, ScanConfig
from .context import ScanContext, build_context
from .detect import detect_standards
from .findings import Finding, Severity
from .log import get_logger
from .merge import merge_cross_list
from .paths import path_prefix, repo_path, resolve_repo_root
from .standards import STANDARDS

log = get_logger("scanner")

SLOW_RULE_SECONDS = 2.0

SUPPRESSION_MARKERS = (
    "decascan:ignore",
    "decascan: ignore",
    "nosec decascan",
    # the tool was called mcp-sift before it was renamed; markers already in code keep working
    "mcp-sift:ignore",
    "mcp-sift: ignore",
    "nosec mcp-sift",
)


@dataclass
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    rules_run: int
    duration_seconds: float
    errors: list[str]
    standards: tuple[str, ...] = ()
    # Why each list was selected when `standards` was auto-detected; empty for an explicit choice.
    detected: dict[str, list[str]] = field(default_factory=dict)
    # The scanned directory's position inside its repository ("" when it is the root, or unknown).
    # Finding paths stay relative to the scanned directory; SARIF and annotations add this prefix.
    path_prefix: str = ""

    def repo_path(self, finding: Finding) -> str:
        return repo_path(self.path_prefix, finding.file_path)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def worst_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def should_fail(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.findings)


def _is_suppressed(ctx: ScanContext, finding: Finding) -> bool:
    if finding.line is None:
        return False
    line = ctx.line(finding.file_path, finding.line)
    return any(marker in line for marker in SUPPRESSION_MARKERS)


def active_standards(ctx: ScanContext) -> tuple[frozenset[str], dict[str, list[str]]]:
    """The lists to run, and the evidence behind an auto-detected choice.

    An explicit choice is used as given. Otherwise the lists are detected from imports and
    dependencies; a codebase that matches none (a lone script, say) gets every list, because a
    scanner that silently checks nothing is worse than one that checks too much.
    """
    if ctx.config.standards is not None:
        return ctx.config.standards, {}
    detected = detect_standards(ctx)
    if not detected:
        return frozenset(STANDARDS), {}
    return frozenset(detected), detected


def scan(root: Path, config: ScanConfig | None = None) -> ScanResult:
    config = config or ScanConfig()
    started = time.perf_counter()

    log.info("scan started", extra={"path": str(root)})
    log.debug(
        "scan configuration",
        extra={
            "standards": "auto" if config.standards is None else ",".join(sorted(config.standards)),
            "min_severity": config.min_severity.value,
            "only_rules": ",".join(sorted(config.enabled_rules)) if config.enabled_rules else "",
            "disabled_rules": ",".join(sorted(config.disabled_rules)),
            "extra_excludes": ",".join(e for e in config.excludes if e not in DEFAULT_EXCLUDES),
            "merge_duplicates": config.merge_duplicates,
            "max_file_bytes": config.max_file_bytes,
            "repo_root": str(config.repo_root) if config.repo_root else "",
        },
    )
    ctx = build_context(root, config)
    context_seconds = time.perf_counter() - started
    findings: list[Finding] = []
    errors: list[str] = []
    active, detected = active_standards(ctx)

    every_rule = all_rules()
    rules = [r for r in every_rule if r.standard in active and config.rule_enabled(r.id)]
    other_lists = [r for r in every_rule if r.standard not in active]
    disabled = [r for r in every_rule if r.standard in active and not config.rule_enabled(r.id)]
    log.info(
        "lists selected",
        extra={
            "standards": ",".join(sorted(active)),
            "mode": "auto" if config.standards is None else "explicit",
            "detected": "; ".join(f"{sid}: {', '.join(why)}" for sid, why in sorted(detected.items())),
            "rules": len(rules),
            "rules_skipped_other_lists": len(other_lists),
            "rules_disabled": len(disabled),
        },
    )
    if disabled:
        log.debug("rules disabled by option", extra={"rules": ",".join(r.id for r in disabled)})

    rules_started = time.perf_counter()
    timings: list[tuple[str, float]] = []
    failed = 0
    for rule in rules:
        rule_started = time.perf_counter()
        try:
            produced = list(rule.fn(ctx))
        except Exception as exc:  # a broken rule must not take the whole scan down
            failed += 1
            errors.append(f"rule {rule.id} raised {type(exc).__name__}: {exc}")
            log.warning("rule failed", extra={"rule": rule.id, "error": f"{type(exc).__name__}: {exc}"})
            log.debug("rule failure traceback", exc_info=True, extra={"rule": rule.id})
            continue
        elapsed = time.perf_counter() - rule_started
        timings.append((rule.id, elapsed))
        findings.extend(produced)
        log.debug(
            "rule finished",
            extra={"rule": rule.id, "findings": len(produced), "ms": round(elapsed * 1000, 1)},
        )
        if elapsed > SLOW_RULE_SECONDS:
            log.warning("slow rule", extra={"rule": rule.id, "seconds": round(elapsed, 2)})
    rules_seconds = time.perf_counter() - rules_started
    slowest = sorted(timings, key=lambda item: item[1], reverse=True)[:3]
    log.info(
        "rules finished",
        extra={
            "rules": len(rules),
            "failed": failed,
            "raw_findings": len(findings),
            "seconds": round(rules_seconds, 3),
            "slowest": ", ".join(f"{rid}={seconds * 1000:.0f}ms" for rid, seconds in slowest),
        },
    )

    errors.extend(ctx.errors)
    for facts in ctx.source_facts.values():
        if facts.parse_error:
            errors.append(f"{facts.path}: {facts.parse_error}")
            log.warning("file could not be parsed", extra={"file": facts.path, "error": facts.parse_error})

    kept: list[Finding] = []
    seen: set[tuple] = set()
    below_minimum = suppressed = duplicates = 0
    for finding in findings:
        if finding.severity.rank < config.min_severity.rank:
            below_minimum += 1
            continue
        if _is_suppressed(ctx, finding):
            suppressed += 1
            log.debug(
                "finding suppressed inline",
                extra={"rule": finding.rule_id, "file": finding.file_path, "line": finding.line},
            )
            continue
        key = (finding.rule_id, finding.file_path, finding.line, finding.title)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        kept.append(finding)
    if below_minimum or suppressed or duplicates:
        log.info(
            "findings filtered",
            extra={
                "below_min_severity": below_minimum,
                "suppressed_inline": suppressed,
                "exact_duplicates": duplicates,
                "kept": len(kept),
            },
        )

    merged_away = 0
    if config.merge_duplicates:
        before = len(kept)
        kept = merge_cross_list(kept)
        merged_away = before - len(kept)
        if merged_away:
            log.info("cross-list duplicates merged", extra={"merged": merged_away})

    kept.sort(key=lambda f: f.sort_key)
    repo_root = resolve_repo_root(ctx.root, config.repo_root)
    prefix = path_prefix(ctx.root, repo_root)
    log.debug(
        "repository root resolved",
        extra={"repo_root": str(repo_root) if repo_root else "", "path_prefix": prefix},
    )

    duration = time.perf_counter() - started
    by_severity = {s.value: sum(1 for f in kept if f.severity == s) for s in Severity}
    log.info(
        "scan finished",
        extra={
            "files": len(ctx.files),
            "rules": len(rules),
            "findings": len(kept),
            "errors": len(errors),
            "seconds": round(duration, 3),
            "context_seconds": round(context_seconds, 3),
            "rules_seconds": round(rules_seconds, 3),
            **{f"severity_{name}": count for name, count in by_severity.items() if count},
        },
    )

    return ScanResult(
        findings=kept,
        files_scanned=len(ctx.files),
        rules_run=len(rules),
        duration_seconds=duration,
        errors=errors,
        standards=tuple(sorted(active)),
        detected=detected,
        path_prefix=prefix,
    )
