"""Scanner configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .findings import Severity

DEFAULT_EXCLUDES = (
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "site-packages",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "coverage",
    ".tox",
)

SOURCE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs")
TEXT_SUFFIXES = (".json", ".yaml", ".yml", ".toml", ".env", ".sh", ".ini", ".cfg", ".md")

# Files whose whole purpose is to hold secrets in a *template* form, plus anything that looks like
# a fixture of fake credentials. Findings here are still reported but at reduced confidence.
PLACEHOLDER_FILE_HINTS = (".env.example", ".env.sample", ".env.template", "example", "sample")


@dataclass
class ScanConfig:
    fail_on: Severity = Severity.HIGH
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES
    # Which Top 10 lists to scan against. None = auto-detect from the codebase (see core/detect.py),
    # falling back to every list when nothing is recognised.
    standards: frozenset[str] | None = None
    # Repository root, for reporting repo-relative paths in SARIF and annotations. None = detect it
    # (GITHUB_WORKSPACE, then the nearest .git directory).
    repo_root: Path | None = None
    # Collapse one defect reported by several lists into a single finding (see core/merge.py).
    merge_duplicates: bool = True
    enabled_rules: frozenset[str] | None = None  # None = all
    disabled_rules: frozenset[str] = field(default_factory=frozenset)
    min_severity: Severity = Severity.INFO
    max_file_bytes: int = 2_000_000
    # Shannon-entropy floor for treating a bare string literal as a credential. 3.0 bits/char keeps
    # `password = "changeme"` out while catching real 32+ char tokens.
    min_entropy: float = 3.2

    def rule_enabled(self, rule_id: str) -> bool:
        if rule_id in self.disabled_rules:
            return False
        if self.enabled_rules is None:
            return True
        return rule_id in self.enabled_rules
