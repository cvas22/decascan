"""The generated sections of docs/rules.md must match what the scanner reports."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent


def load_generator():
    path = ROOT / "scripts" / "generate_rule_docs.py"
    spec = importlib.util.spec_from_file_location("generate_rule_docs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rule_docs_are_up_to_date():
    # Refresh with: python scripts/generate_rule_docs.py
    existing = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert load_generator().render_document(existing) == existing


def test_every_generated_rule_section_states_severity_cwe_and_a_fix():
    text = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    generated = text[text.index("<!-- generated:") :]
    sections = [s for s in generated.split("\n### ")[1:]]
    assert len(sections) >= 28
    for section in sections:
        assert "**Severity:**" in section and "**CWE:**" in section
        assert "**Fires on:**" in section and "**Fix:**" in section


def test_changelog_and_ci_docs_exist_and_mention_the_exit_code_contract():
    assert "Exit code `2`" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "When something goes wrong" in (ROOT / "docs" / "ci.md").read_text(encoding="utf-8")
