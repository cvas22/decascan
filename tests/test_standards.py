"""The LLM and Web Top 10 rule sets, and the multi-standard plumbing around them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_sift.cli import main
from mcp_sift.core.config import ScanConfig
from mcp_sift.core.scanner import scan
from mcp_sift.core.standards import STANDARDS
from mcp_sift.rules import all_rules

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_webllm"
CLEAN = FIXTURES / "clean_webllm"


def rule_ids(path: Path, **config) -> set[str]:
    result = scan(path, ScanConfig(**config))
    assert result.errors == []
    return {f.rule_id for f in result.findings}


def scan_source(tmp_path: Path, source: str, name: str = "app.py") -> set[str]:
    (tmp_path / name).write_text(source, encoding="utf-8")
    return rule_ids(tmp_path)


def test_every_rule_belongs_to_a_known_standard_and_risk():
    for rule in all_rules():
        assert rule.standard in STANDARDS
        assert rule.mcp_id in STANDARDS[rule.standard].risks
        assert rule.id.startswith(rule.mcp_id)


def test_rule_ids_are_unique():
    ids = [r.id for r in all_rules()]
    assert len(ids) == len(set(ids))


def test_vulnerable_fixture_trips_every_rule_it_was_built_for():
    expected = {
        "LLM01-001", "LLM03-001", "LLM03-002", "LLM03-003", "LLM05-001", "LLM06-001", "LLM10-001",
        "WEB01-001", "WEB02-001", "WEB02-002", "WEB02-004", "WEB03-001", "WEB03-002", "WEB03-003",
        "WEB05-001", "WEB07-002", "WEB08-001", "WEB09-001", "WEB09-002", "WEB10-001",
    }  # fmt: skip
    assert expected <= rule_ids(VULNERABLE)


def test_clean_fixture_produces_no_findings():
    assert rule_ids(CLEAN) == set()


def test_standard_filter_limits_the_rules_that_run():
    only_llm = rule_ids(VULNERABLE, standards=frozenset({"llm"}))
    assert only_llm and all(r.startswith("LLM") for r in only_llm)
    only_web = rule_ids(VULNERABLE, standards=frozenset({"web"}))
    assert only_web and all(r.startswith("WEB") for r in only_web)


def test_cli_standard_option_and_json_standard_field():
    result = CliRunner().invoke(
        main, ["scan", str(VULNERABLE), "-s", "llm", "-o", "json", "--no-fail"]
    )
    data = json.loads(result.output)
    assert set(data["standards"]) == {"llm"}
    assert {f["standard"] for f in data["findings"]} == {"llm"}


def test_standards_command_reports_coverage_gaps_honestly():
    out = CliRunner().invoke(main, ["standards"]).output
    assert "LLM04" in out and "not static" in out


@pytest.mark.parametrize(
    ("rule", "source"),
    [
        ("LLM02-001", 'prompt = f"use key {os.environ[\'KEY\']} now"\n'),
        ("LLM07-001", 'SYSTEM_PROMPT = "You are X. The admin password is Zk39fQ81xyz"\n'),
        ("WEB01-002", 'CORS(app, origins="*", supports_credentials=True)\n'),
        ("WEB01-003", "@csrf_exempt\ndef pay(request): ...\n"),
        ("WEB02-003", "cipher = AES.new(key, AES.MODE_ECB)\n"),
        ("WEB03-004", "el.innerHTML = userHtml\n"),
        ("WEB05-002", "ALLOWED_HOSTS = ['*']\n"),
        ("WEB07-001", "jwt.decode(t, key, options={'verify_signature': False})\n"),
    ],
)
def test_each_remaining_rule_fires(tmp_path, rule, source):
    assert rule in scan_source(tmp_path, source, "app.js" if "innerHTML" in source else "app.py")


@pytest.mark.parametrize(
    "source",
    [
        'cursor.execute("SELECT 1 WHERE a = %s", (a,))\n',
        'client.chat.completions.create(model="m", max_tokens=10, messages=m)\n',
        'hashlib.md5(data, usedforsecurity=False)\n',
        'SECRET_KEY = "changeme"\n',
        "el.textContent = userText\n",
        "try:\n    x()\nexcept ValueError:\n    pass\n",
    ],
)
def test_safe_shapes_stay_quiet(tmp_path, source):
    assert scan_source(tmp_path, source) == set()


def test_test_directories_are_not_scanned_by_the_pattern_rules(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text("eval(user_code)\npickle.loads(blob)\n", encoding="utf-8")
    assert rule_ids(tmp_path) == set()


def test_secret_values_are_redacted_in_snippets(tmp_path):
    (tmp_path / "app.py").write_text('SECRET_KEY = "Zk39fQ81-live-signing-key"\n', encoding="utf-8")
    findings = [f for f in scan(tmp_path).findings if f.rule_id == "WEB07-002"]
    assert findings and "live-signing-key" not in (findings[0].snippet or "")


def test_cached_catalog_matches_the_rules_in_code():
    # Refresh with: mcp-sift standards --export src/mcp_sift/data/top10.json
    from mcp_sift.catalog import build_catalog, load_cached_catalog

    assert load_cached_catalog() == build_catalog()


def test_cached_catalog_is_served_by_the_cli():
    out = CliRunner().invoke(main, ["standards", "--json", "--cached"]).output
    assert set(json.loads(out)["standards"]) == set(STANDARDS)


def test_every_rule_is_documented():
    docs = (Path(__file__).parent.parent / "docs" / "rules.md").read_text(encoding="utf-8")
    missing = [r.id for r in all_rules() if f"### {r.id}" not in docs]
    assert missing == []
