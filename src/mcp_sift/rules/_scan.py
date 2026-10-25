"""Shared plumbing for the pattern-based rules (the LLM and Web Top 10 rule sets).

These rules are deliberately lexical: a regex finds the sink, a balanced-paren walk reads its
arguments, and a one-hop taint pass says whether a request-derived value reaches it. That is
cheaper and broader than the AST analysis the MCP rules use, and honest about it -- every finding
carries a confidence below 1.0 unless the match is unambiguous.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from ..core.config import SOURCE_SUFFIXES
from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..core.lines import line_of, line_text
from ..core.log import get_logger

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "e2e", "testdata"}
_COMMENT_PREFIXES = ("#", "//", "*", "/*")
_MAX_ARG_CHARS = 4000

# Where untrusted data enters a web handler.
SOURCE_RE = re.compile(
    r"\brequest\.(?:args|form|values|json|get_json|GET|POST|data|files|cookies|headers|query_params|"
    r"path_params|body)\b|\breq\.(?:params|query|body|headers|cookies)\b|\bsys\.argv\b|\binput\("
)


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    is_js: bool

    @property
    def is_python(self) -> bool:
        return not self.is_js


def is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    name = parts[-1]
    return (
        any(part in _TEST_DIRS for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.js", ".spec.ts", ".spec.js"))
        or name == "conftest.py"
    )


# A line this long is minified or generated output, not code anyone reviews. The lexical rules skip
# such files: every match attempt on a megabyte-long line is slow, and none of the matches is useful.
MAX_LINE_CHARS = 5000

log = get_logger("rules")


def source_files(ctx: ScanContext) -> Iterator[SourceFile]:
    for rel in ctx.files:
        if not rel.lower().endswith(SOURCE_SUFFIXES) or is_test_path(rel):
            continue
        if ctx.is_minified(rel, MAX_LINE_CHARS):
            log.debug("file skipped by pattern rules: minified or generated", extra={"file": rel})
            continue
        yield SourceFile(rel, ctx.masked_text(rel), not rel.lower().endswith(".py"))


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(_COMMENT_PREFIXES)


def is_import(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("import ", "from ")) or "require(" in stripped


def call_args(text: str, open_paren_end: int) -> str:
    """The text between the parenthesis ending at `open_paren_end` and its match."""
    depth = 1
    quote = ""
    i = open_paren_end
    limit = min(len(text), open_paren_end + _MAX_ARG_CHARS)
    while i < limit:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_paren_end:i]
        i += 1
    return text[open_paren_end:limit]


def inside_string(line: str, column: int) -> bool:
    """Whether `column` falls inside a quoted literal, judged by quote parity on its own line.

    Good enough to stop `description="... eval(s) ..."` from reading as a call; it does not follow
    a string that spans lines, and an f-string's `{...}` expression counts as inside the string.
    """
    prefix = re.sub(r"\\.", "", line[:column])  # drop escaped characters
    return any(prefix.count(quote) % 2 for quote in ('"', "'"))


@dataclass(frozen=True)
class Call:
    line: int
    args: str
    source_line: str


def calls(src: SourceFile, pattern: re.Pattern[str]) -> Iterator[Call]:
    """Every call whose opening matches `pattern` (which must end at the `(`)."""
    for match in pattern.finditer(src.text):
        line_no = line_of(src.text, match.start())
        source_line = line_text(src.text, line_no)
        if is_comment(source_line) or is_import(source_line):
            continue
        line_start = src.text.rfind("\n", 0, match.start()) + 1
        if inside_string(source_line, match.start() - line_start):
            continue
        yield Call(line_no, call_args(src.text, match.end()), source_line)


_ASSIGN_RE = re.compile(r"^[ \t]*(?:const |let |var )?([A-Za-z_]\w*)\s*(?::[^=\n]+)?=(?!=)\s*(.+)$", re.M)


def tainted_names(text: str) -> set[str]:
    """Names assigned straight from a request-derived value. One hop, file-wide, no flow analysis."""
    names: set[str] = set()
    for match in _ASSIGN_RE.finditer(text):
        if SOURCE_RE.search(match.group(2)):
            names.add(match.group(1))
    return names


def is_tainted(args: str, names: set[str]) -> bool:
    if SOURCE_RE.search(args):
        return True
    return any(re.search(rf"\b{re.escape(name)}\b", args) for name in names)


_DYNAMIC_STRING = (
    re.compile(r"(?<![\w])f[\"']"),  # Python f-string
    re.compile(r"[\"']\s*%\s*[\(\w]"),  # "..." % x
    re.compile(r"\.format\("),
    re.compile(r"[\"']\s*\+\s*[A-Za-z_]"),  # "..." + x
    re.compile(r"[A-Za-z_\)\]]\s*\+\s*[\"']"),  # x + "..."
    re.compile(r"`[^`]*\$\{"),  # JS template literal with interpolation
)


def is_dynamic_string(args: str) -> bool:
    """Whether the arguments assemble a string at runtime rather than passing a plain literal."""
    return any(pattern.search(args) for pattern in _DYNAMIC_STRING)


def is_literal(args: str) -> bool:
    """Whether the first argument is one plain string literal -- the safe shape for a sink."""
    return bool(re.match(r"\s*(?:[rbu]|rb|br)?(\"[^\"\\\n]*\"|'[^'\\\n]*')\s*(?:,|$)", args))


def snippet_of(line: str, limit: int = 160) -> str:
    stripped = line.strip()
    return stripped if len(stripped) <= limit else stripped[: limit - 3] + "..."


def make_finding(
    *,
    rule_id: str,
    risk_id: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    path: str,
    line: int | None,
    source_line: str | None = None,
    cwe: str | None = None,
    confidence: float = 0.8,
    snippet: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        mcp_id=risk_id,
        severity=severity,
        title=title,
        description=description,
        file_path=path,
        remediation=remediation,
        line=line,
        snippet=snippet if snippet is not None else (snippet_of(source_line) if source_line else None),
        cwe_id=cwe,
        confidence=confidence,
    )
