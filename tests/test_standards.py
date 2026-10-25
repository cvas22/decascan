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
    config.setdefault("merge_duplicates", False)  # which rules fire, not how duplicates are merged
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


def detected(tmp_path: Path, source: str, name: str = "app.py") -> dict[str, list[str]]:
    (tmp_path / name).write_text(source, encoding="utf-8")
    return scan(tmp_path).detected


def test_auto_detects_the_lists_a_codebase_uses(tmp_path):
    found = detected(tmp_path, "from flask import Flask\nimport openai\n")
    assert set(found) == {"web", "llm"}
    assert "imports flask" in found["web"]


def test_auto_runs_only_the_detected_lists(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\nDEBUG = True\n", encoding="utf-8")
    ids = rule_ids(tmp_path)
    assert "WEB05-001" in ids and not any(i.startswith("LLM") for i in ids)
    assert scan(tmp_path).standards == ("web",)


def test_auto_detects_mcp_servers(tmp_path):
    found = detected(tmp_path, "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n")
    assert "mcp" in found


def test_auto_reads_declared_dependencies(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.19.2"}}', encoding="utf-8")
    (tmp_path / "index.js").write_text("console.log('hi')\n", encoding="utf-8")
    assert "web" in scan(tmp_path).detected


def test_auto_falls_back_to_every_list_when_nothing_is_recognised(tmp_path):
    (tmp_path / "script.py").write_text("print('hello')\n", encoding="utf-8")
    result = scan(tmp_path)
    assert result.detected == {}
    assert set(result.standards) == set(STANDARDS)


def test_a_local_module_named_like_a_common_word_does_not_select_a_list(tmp_path):
    assert detected(tmp_path, "import ai\nfrom next import thing\n") == {}


def test_explicit_standard_overrides_detection(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\n", encoding="utf-8")
    result = scan(tmp_path, ScanConfig(standards=frozenset({"llm"})))
    assert result.standards == ("llm",) and result.detected == {}


def test_cli_all_runs_every_list_and_auto_cannot_be_mixed():
    runner = CliRunner()
    out = runner.invoke(main, ["scan", str(CLEAN), "-s", "all", "-o", "json", "--no-fail"]).output
    assert set(json.loads(out)["standards"]) == set(STANDARDS)
    bad = runner.invoke(main, ["scan", str(CLEAN), "-s", "auto", "-s", "web"])
    assert bad.exit_code == 2 and "cannot be combined" in bad.output


def test_pretty_output_says_what_was_auto_detected():
    out = CliRunner().invoke(main, ["scan", str(VULNERABLE), "--no-fail"]).output
    assert "Auto-detected:" in out and "Override with --standard" in out
