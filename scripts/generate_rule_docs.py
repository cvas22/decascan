"""Regenerate the LLM and web sections of docs/rules.md from the rules and their test samples.

    python scripts/generate_rule_docs.py            # rewrite docs/rules.md
    python scripts/generate_rule_docs.py --check    # exit 1 if the file is out of date

Severity, CWE and confidence come from running every rule on its positive test samples, so the docs
cannot drift from what the scanner reports.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_sift.catalog import build_catalog  # noqa: E402
from mcp_sift.core.config import ScanConfig  # noqa: E402
from mcp_sift.core.scanner import scan  # noqa: E402

DOC = ROOT / "docs" / "rules.md"
MARKER = "<!-- generated: rules for the LLM and web Top 10 lists (scripts/generate_rule_docs.py) -->"
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _load_samples():
    spec = importlib.util.spec_from_file_location("rule_samples", ROOT / "tests" / "test_web_llm_rules.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.POSITIVE, module.NEGATIVE


def _run(source: str, name: str, rule_id: str):
    config = ScanConfig(standards=frozenset({"llm", "web"}), merge_duplicates=False)
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / name).write_text(source, encoding="utf-8")
        return [f for f in scan(Path(tmp), config).findings if f.rule_id == rule_id]


def _inline(source: str) -> str:
    return " ".join(line.strip() for line in source.strip().splitlines()).replace("`", "'")


def _range(values: list[str]) -> str:
    ordered = sorted(set(values), key=SEVERITY_ORDER.index)
    upper = [v.upper() for v in ordered]
    return upper[0] if len(upper) == 1 else f"{upper[0]} to {upper[-1]}"


def _rule_section(rule: dict, positives: list, negatives: list) -> list[str]:
    found = []
    for rule_id, name, source in positives:
        if rule_id == rule["id"]:
            found.extend(_run(source, name, rule_id))
    severities = [f.severity.value for f in found]
    confidences = [f.confidence for f in found]
    cwes = sorted({f.cwe_id for f in found if f.cwe_id})
    fires = [_inline(src) for rid, _name, src in positives if rid == rule["id"]][:2]
    quiet = [_inline(src) for rid, src in negatives if rid == rule["id"]][:2]

    severity = _range(severities)
    if len(set(severities)) > 1:
        severity += ", depending on context"
    low, high = min(confidences), max(confidences)
    confidence = f"{low:.2f}" if low == high else f"{low:.2f}-{high:.2f}"

    lines = [
        f"### {rule['id']} — {rule['name']}",
        f"**Severity:** {severity} · **CWE:** {', '.join(cwes) or 'n/a'} · **Confidence:** {confidence}",
        "",
        rule["description"],
        "",
        "**Fires on:** " + "; ".join(f"`{s}`" for s in fires),
    ]
    if quiet:
        lines.append("")
        lines.append("**Stays quiet on:** " + "; ".join(f"`{s}`" for s in quiet))
    lines.append("")
    lines.append(f"**Fix:** {found[0].remediation}")
    return lines


def generate() -> str:
    positives, negatives = _load_samples()
    catalog = build_catalog()["standards"]
    out = [MARKER]
    for sid in ("llm", "web"):
        std = catalog[sid]
        out += [
            "",
            "---",
            "",
            f"# {std['name']} ({std['version']})",
            "",
            "Pattern-based rules: a regex finds the sink, a balanced-parenthesis walk reads its",
            "arguments, and a one-hop pass marks request-derived names. Comments and docstrings are",
            "blanked first, and test directories are skipped. Confidence is below 1.0 throughout,",
            "and the examples below are the scanner's own test samples.",
        ]
        for risk in std["risks"]:
            out += ["", f"## {risk['id']} — {risk['name']}"]
            if risk["status"] == "not-static":
                out += [
                    "",
                    "Not statically detectable: this is a property of data, design or model behaviour, "
                    "not of a line of source. No rule is claimed for it.",
                ]
                if risk["id"] == "WEB06":
                    out.append("Use pip-audit or osv-scanner for known-vulnerable dependencies.")
            for rule in risk["rules"]:
                out += ["", *_rule_section(rule, positives, negatives)]
    return "\n".join(out) + "\n"


def current_prefix(text: str) -> str:
    """Everything in docs/rules.md before the generated block (the hand-written MCP part)."""
    if MARKER in text:
        return text[: text.index(MARKER)]
    # First run: the generated block starts at the first non-MCP heading, preceded by a rule line.
    cut = text.index("# OWASP Top 10 for LLM Applications")
    return text[:cut].rstrip("\n").removesuffix("---").rstrip("\n") + "\n\n"


def render_document(existing: str) -> str:
    return current_prefix(existing) + generate()


def main() -> int:
    existing = DOC.read_text(encoding="utf-8")
    updated = render_document(existing)
    if "--check" in sys.argv:
        if updated != existing:
            print("docs/rules.md is out of date: run python scripts/generate_rule_docs.py")
            return 1
        print("docs/rules.md is up to date")
        return 0
    DOC.write_text(updated, encoding="utf-8", newline="\n")
    print(f"wrote {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
