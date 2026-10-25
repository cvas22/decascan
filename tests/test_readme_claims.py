"""The README makes specific promises. Each one that can be checked is checked here, so it cannot rot."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_sift.cli import main
from mcp_sift.core.config import DEFAULT_EXCLUDES
from mcp_sift.rules import all_rules

ROOT = Path(__file__).parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
README = (ROOT / "README.md").read_text(encoding="utf-8")


def run(*args, env=None):
    return CliRunner().invoke(main, list(args), env=env)


def scan_json(path, *args):
    return json.loads(run("scan", str(path), "-o", "json", "--no-fail", *args).stdout)


# --- the rule tables ---------------------------------------------------------------------------


def test_every_rule_id_in_the_readme_exists_and_every_rule_is_listed():
    documented = set(re.findall(r"`((?:MCP|LLM|WEB)\d\d-\d{3})`", README))
    actual = {r.id for r in all_rules()}
    assert documented == actual


def test_coverage_table_matches_the_catalog():
    from mcp_sift.catalog import build_catalog

    cat = build_catalog()["standards"]
    covered = {k: sum(1 for r in v["risks"] if r["status"] == "covered") for k, v in cat.items()}
    assert covered == {"mcp": 10, "llm": 7, "web": 8}
    assert sum(len(r["rules"]) for r in cat["mcp"]["risks"]) == 26
    assert "all 10, 26 rules" in README and "7 of 10" in README and "8 of 10" in README


# --- the worked example ------------------------------------------------------------------------


def test_example_run_numbers_are_the_real_numbers():
    real = scan_json(FIXTURES / "vulnerable_ts")
    by_severity = real["summary"]["by_severity"]
    expected = (
        f"{real['summary']['findings']} finding(s) across {real['summary']['files_scanned']} files "
        f"({real['summary']['rules_run']} rules,"
    )
    assert expected in README
    for level in ("CRITICAL", "HIGH", "MEDIUM"):
        assert re.search(rf"^{level}\s+{by_severity[level.lower()]}$", README, re.M)


def test_example_run_shows_the_first_findings_in_their_real_order():
    block = README[README.index("$ mcp-sift scan tests/fixtures/vulnerable_ts") :]
    block = block[: block.index("```")]
    shown = re.findall(r"^\s*(CRITICAL|HIGH|MEDIUM)\s+MCP\d\d .*?\[(MCP\d\d-\d{3})\]", block, re.M)
    real = scan_json(FIXTURES / "vulnerable_ts")["findings"]
    assert [(s.lower(), rid) for s, rid in shown] == [(f["severity"], f["rule_id"]) for f in real[: len(shown)]]


def test_example_run_starts_with_what_the_tool_really_prints():
    out = run("scan", str(FIXTURES / "vulnerable_ts"), "--no-fail").output
    assert out.startswith("Auto-detected: mcp")
    assert "Auto-detected: mcp" in README and "Override with --standard mcp|llm|web|all." in README


def test_the_clean_fixtures_say_no_findings_and_exit_zero():
    for name in ("clean_python", "clean_webllm"):
        result = run("scan", str(FIXTURES / name))
        assert result.exit_code == 0 and "No findings" in result.output


# --- the CLI reference -------------------------------------------------------------------------


def test_every_documented_scan_option_exists():
    help_text = run("scan", "--help").output
    documented = re.findall(r"^\| `(-[\w-]+, )?(--[\w-]+)", README, re.M)
    options = {name for _, name in documented}
    assert {"--output", "--output-file", "--fail-on", "--min-severity", "--standard", "--rule", "--disable",
            "--exclude", "--repo-root", "--keep-duplicates", "--no-fail"} <= options
    for option in options - {"--log-file", "--log-format"}:
        assert option in help_text or option == "--verbose", option


def test_documented_defaults_are_the_real_defaults(tmp_path):
    (tmp_path / "a.py").write_text("DEBUG = True\n", encoding="utf-8")  # HIGH
    assert run("scan", str(tmp_path), "-s", "web").exit_code == 1  # --fail-on defaults to high
    assert run("scan", str(tmp_path), "-s", "web", "--fail-on", "critical").exit_code == 0
    assert "Auto-detected" not in run("scan", str(tmp_path), "-s", "web").output  # explicit list: no detection
    assert scan_json(tmp_path, "-s", "web")["summary"]["findings"] == 1  # --min-severity defaults to info


def test_documented_log_options_and_environment_variables_exist():
    help_text = run("--help").output
    for option in ("-v", "--log-file", "--log-format"):
        assert option in help_text
    source = (ROOT / "src" / "mcp_sift" / "cli.py").read_text(encoding="utf-8")
    for variable in ("MCP_SIFT_VERBOSE", "MCP_SIFT_LOG_FILE", "MCP_SIFT_LOG_FORMAT", "MCP_SIFT_REPO_ROOT"):
        assert variable in source and variable in README


def test_documented_default_excludes_are_really_excluded():
    for name in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "site-packages"):
        assert name in DEFAULT_EXCLUDES and f"`{name}`" in README


def test_exit_codes_table(tmp_path):
    clean, vulnerable = FIXTURES / "clean_python", FIXTURES / "vulnerable_ts"
    assert run("scan", str(clean)).exit_code == 0
    assert run("scan", str(vulnerable)).exit_code == 1
    assert run("scan", str(vulnerable), "--no-fail").exit_code == 0
    assert run("scan", str(clean), "--rule", "NOPE-1").exit_code == 2
    assert run("scan", str(tmp_path / "missing")).exit_code == 2
    unwritable = tmp_path / "no" / "such" / "dir" / "r.json"
    assert run("scan", str(clean), "-o", "json", "-f", str(unwritable)).exit_code == 2


def test_a_single_file_can_be_scanned():
    assert scan_json(FIXTURES / "vulnerable_python" / "server.py")["summary"]["findings"] > 0


@pytest.mark.parametrize("marker", ["mcp-sift:ignore", "mcp-sift: ignore", "nosec mcp-sift"])
def test_all_three_documented_suppression_markers_work(tmp_path, marker):
    (tmp_path / "a.py").write_text(f"DEBUG = True  # {marker}\n", encoding="utf-8")
    assert scan_json(tmp_path, "-s", "web")["summary"]["findings"] == 0


def test_gitignore_is_not_read_as_documented(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "a.py").write_text("DEBUG = True\n", encoding="utf-8")
    assert scan_json(tmp_path, "-s", "web")["summary"]["findings"] == 1


# --- auto-detection ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"a.py": "from flask import Flask\n"}, {"web"}),
        ({"a.js": "const express = require('express');\n"}, {"web"}),
        ({"a.py": "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"}, {"mcp"}),
        ({"a.py": "print(1)\n"}, {"mcp", "llm", "web"}),
    ],
)
def test_auto_detection_as_documented(tmp_path, files, expected):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    assert set(scan_json(tmp_path)["standards"]) == expected


def test_langchain_or_openai_selects_the_llm_list(tmp_path):
    (tmp_path / "a.py").write_text("import openai\nfrom langchain.chains import LLMChain\n", encoding="utf-8")
    assert "llm" in scan_json(tmp_path)["standards"]


def test_auto_cannot_be_combined(tmp_path):
    assert run("scan", str(tmp_path), "-s", "auto", "-s", "web").exit_code == 2


# --- claims inside the rule table --------------------------------------------------------------

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.mark.parametrize("output", ["pretty", "json", "sarif", "github"])
def test_secrets_are_redacted_in_every_output_format(tmp_path, output):
    (tmp_path / "server.py").write_text(f'GITHUB_TOKEN = "{SECRET}"\n', encoding="utf-8")
    result = run("scan", str(tmp_path), "-o", output, "--no-fail")
    assert SECRET not in result.output  # never in full
    if output != "github":  # annotations carry no snippet at all; the others show the redacted line
        assert "ghp_" in result.output


def test_secret_is_not_in_the_verbose_log_either(tmp_path):
    (tmp_path / "server.py").write_text(f'GITHUB_TOKEN = "{SECRET}"\n', encoding="utf-8")
    assert SECRET not in run("-vv", "scan", str(tmp_path), "--no-fail").stderr


def test_placeholders_do_not_fire_and_template_files_are_only_low(tmp_path):
    (tmp_path / "c.py").write_text('password = "changeme"\napi_key = "${API_KEY}"\n', encoding="utf-8")
    assert scan_json(tmp_path, "-s", "mcp")["summary"]["findings"] == 0
    (tmp_path / "c.py").unlink()
    (tmp_path / ".env.example").write_text(f"GITHUB_TOKEN={SECRET}\n", encoding="utf-8")
    findings = scan_json(tmp_path, "-s", "mcp")["findings"]
    assert [f["severity"] for f in findings] == ["low"]  # reported, but not at full severity


MCP_HEADER = "from mcp.server.fastmcp import FastMCP\nimport subprocess, shlex\nmcp = FastMCP('t')\n"


def mcp05(tmp_path, body):
    (tmp_path / "server.py").write_text(MCP_HEADER + body, encoding="utf-8")
    return [f for f in scan_json(tmp_path, "-s", "mcp")["findings"] if f["rule_id"] == "MCP05-001"]


def test_shlex_quote_clears_the_flow_whether_assigned_first_or_inline(tmp_path):
    assert mcp05(tmp_path, "@mcp.tool()\ndef f(c: str):\n    s = shlex.quote(c)\n    subprocess.run(f'echo {s}', shell=True)\n") == []
    assert mcp05(tmp_path, "@mcp.tool()\ndef f(c: str):\n    subprocess.run('echo ' + shlex.quote(c), shell=True)\n") == []


def test_quoting_one_value_does_not_hide_another_that_is_raw(tmp_path):
    body = "@mcp.tool()\ndef f(c: str, o: str):\n    subprocess.run('echo ' + shlex.quote(c) + o, shell=True)\n"
    assert len(mcp05(tmp_path, body)) == 1


def test_an_unquoted_parameter_reaching_a_shell_is_still_reported(tmp_path):
    assert len(mcp05(tmp_path, "@mcp.tool()\ndef f(c: str):\n    subprocess.run('echo ' + c, shell=True)\n")) == 1


def test_taint_through_a_helper_is_not_tracked_as_documented(tmp_path):
    body = "def helper(c):\n    subprocess.run(c, shell=True)\n\n@mcp.tool()\ndef f(c: str):\n    helper(c)\n"
    assert mcp05(tmp_path, body) == []


def test_stdio_servers_are_not_asked_for_authentication(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "python", "args": ["s.py"]}}}), encoding="utf-8"
    )
    (tmp_path / "server.py").write_text(MCP_HEADER, encoding="utf-8")
    assert "MCP07-001" not in {f["rule_id"] for f in scan_json(tmp_path, "-s", "mcp")["findings"]}


# --- statements about the project --------------------------------------------------------------


def test_the_two_official_servers_claim_has_its_caveat():
    # Verified by hand against the published mcp-server-fetch and mcp-server-time (0 findings, tools read);
    # kept honest here by requiring the README to say it is a sample, not a rate.
    assert "which is not a false-positive rate" in README


def test_requirements_stated_in_the_readme_match_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in pyproject and "Python 3.10 or newer" in README
    deps = re.search(r"dependencies = \[(.*?)\]", pyproject, re.S).group(1)
    assert sorted(re.findall(r'"([A-Za-z]+)', deps)) == ["PyYAML", "click", "rich"]
    assert "`click`, `rich`, `PyYAML`" in README


def test_the_scanner_makes_no_network_calls_and_runs_no_scanned_code():
    sources = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py"))
    assert not re.search(r"^\s*(import|from)\s+(requests|urllib|http\.client|socket|httpx|aiohttp)", sources, re.M)
    assert not re.search(r"^\s*(import|from)\s+(subprocess|runpy)\b", sources, re.M)
    assert "importlib.import_module" not in sources
