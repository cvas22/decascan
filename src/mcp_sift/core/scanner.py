"""Scanner — runs the rule registry over a ScanContext and returns sorted, de-duplicated findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ..rules import all_rules
from .config import ScanConfig
from .context import ScanContext, build_context
from .detect import detect_standards
from .findings import Finding, Severity
from .log import get_logger
from .standards import STANDARDS

log = get_logger("scanner")

SUPPRESSION_MARKERS = ("mcp-sift:ignore", "mcp-sift: ignore", "nosec mcp-sift")


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
    ctx = build_context(root, config)
    findings: list[Finding] = []
    errors: list[str] = []
    active, detected = active_standards(ctx)
    rules = [r for r in all_rules() if r.standard in active and config.rule_enabled(r.id)]
    log.info(
        "lists selected",
        extra={
            "standards": ",".join(sorted(active)),
            "mode": "auto" if config.standards is None else "explicit",
            "detected": "; ".join(f"{sid}: {', '.join(why)}" for sid, why in sorted(detected.items())),
            "rules": len(rules),
        },
    )

    for rule in rules:
        rule_started = time.perf_counter()
        try:
            produced = list(rule.fn(ctx))
        except Exception as exc:  # a broken rule must not take the whole scan down
            errors.append(f"rule {rule.id} raised {type(exc).__name__}: {exc}")
            log.warning("rule failed", extra={"rule": rule.id, "error": f"{type(exc).__name__}: {exc}"})
            log.debug("rule failure traceback", exc_info=True, extra={"rule": rule.id})
            continue
        findings.extend(produced)
        log.debug(
            "rule finished",
            extra={
                "rule": rule.id,
                "findings": len(produced),
                "ms": round((time.perf_counter() - rule_started) * 1000, 1),
            },
        )

    for facts in ctx.source_facts.values():
        if facts.parse_error:
            errors.append(f"{facts.path}: {facts.parse_error}")
            log.warning("file could not be parsed", extra={"file": facts.path, "error": facts.parse_error})

    kept: list[Finding] = []
    seen: set[tuple] = set()
    for finding in findings:
        if finding.severity.rank < config.min_severity.rank:
            continue
        if _is_suppressed(ctx, finding):
            log.debug(
                "finding suppressed inline",
                extra={"rule": finding.rule_id, "file": finding.file_path, "line": finding.line},
            )
            continue
        key = (finding.rule_id, finding.file_path, finding.line, finding.title)
        if key in seen:
            continue
        seen.add(key)
        kept.append(finding)

    kept.sort(key=lambda f: f.sort_key)
    duration = time.perf_counter() - started
    log.info(
        "scan finished",
        extra={
            "files": len(ctx.files),
            "rules": len(rules),
            "findings": len(kept),
            "errors": len(errors),
            "seconds": round(duration, 3),
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
    )
