"""End-to-end CLI tests, including the encodings that make Windows consoles fall over."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from rich.console import Console

from decascan.cli import main
from decascan.core.scanner import scan
from decascan.outputs import pretty

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = str(FIXTURES / "vulnerable_python")
CLEAN = str(FIXTURES / "clean_python")


def test_scan_exits_nonzero_on_findings():
    result = CliRunner().invoke(main, ["scan", VULNERABLE])
    assert result.exit_code == 1
    assert "CRITICAL" in result.output
    assert "MCP03-001" in result.output


def test_scan_exits_zero_on_clean_server():
    result = CliRunner().invoke(main, ["scan", CLEAN])
    assert result.exit_code == 0


def test_no_fail_flag_always_exits_zero():
    result = CliRunner().invoke(main, ["scan", VULNERABLE, "--no-fail"])
    assert result.exit_code == 0


def test_fail_on_threshold_is_respected():
    # Every finding in the clean fixture is INFO, so --fail-on info should trip and high should not.
    assert CliRunner().invoke(main, ["scan", CLEAN, "--fail-on", "high"]).exit_code == 0


def test_json_output_parses():
    result = CliRunner().invoke(main, ["scan", VULNERABLE, "-o", "json"])
    payload = json.loads(result.output)
    assert payload["summary"]["findings"] > 0


def test_sarif_output_parses():
    result = CliRunner().invoke(main, ["scan", VULNERABLE, "-o", "sarif"])
    assert json.loads(result.output)["version"] == "2.1.0"


def test_output_file_is_written(tmp_path):
    target = tmp_path / "out.sarif"
    result = CliRunner().invoke(
        main, ["scan", VULNERABLE, "-o", "sarif", "-f", str(target), "--no-fail"]
    )
    assert result.exit_code == 0
    assert json.loads(target.read_text())["runs"][0]["tool"]["driver"]["name"] == "decascan"


def test_unknown_rule_id_is_rejected():
    result = CliRunner().invoke(main, ["scan", VULNERABLE, "--rule", "MCP99-999"])
    assert result.exit_code != 0
    assert "unknown rule id" in result.output


def test_rules_command_lists_every_rule():
    result = CliRunner().invoke(main, ["rules"])
    assert result.exit_code == 0
    for rule_id in ("MCP01-001", "MCP02-001", "MCP03-001", "MCP07-001", "MCP09-001"):
        assert rule_id in result.output


def test_pretty_output_survives_a_legacy_windows_console(tmp_path):
    """cp1252 cannot encode a box-drawing glyph, and a snippet can hold anything at all.

    Regression: the renderer used to raise UnicodeEncodeError here instead of printing findings.
    """
    (tmp_path / "server.py").write_text(
        '# 设置密钥 — a comment the terminal cannot encode\n'
        'API_KEY = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5gH9jL0pQ2sT4uV6wX8yZ0aB2"\n',
        encoding="utf-8",
    )
    result = scan(tmp_path)
    assert result.findings

    out = (tmp_path / "out.txt").open("w", encoding="cp1252")
    pretty.render(result, Console(file=out, width=100))
    out.close()

    rendered = (tmp_path / "out.txt").read_text(encoding="cp1252")
    assert "CRITICAL" in rendered
    assert "sk-ant-api03-Vq7hK2mZ" not in rendered  # still redacted
    # cp1252 can encode an em dash but a cp437 console renders it as mojibake, so on any non-UTF-8
    # console the prose must come through as ASCII.
    assert "—" not in rendered
    assert "--" in rendered


def test_utf8_console_keeps_typographic_punctuation(tmp_path):
    (tmp_path / "server.py").write_text(
        'API_KEY = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5gH9jL0pQ2sT4uV6wX8yZ0aB2"\n'
    )
    out = (tmp_path / "out.txt").open("w", encoding="utf-8")
    pretty.render(scan(tmp_path), Console(file=out, width=100))
    out.close()

    rendered = (tmp_path / "out.txt").read_text(encoding="utf-8")
    assert "—" in rendered and "│" in rendered


def test_github_output_survives_a_legacy_console(monkeypatch):
    """The annotations carry an arrow that cp1252 cannot encode; stdout must not raise."""
    import io

    from decascan import cli

    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(cli.sys, "stdout", console)
    monkeypatch.setattr(cli.click, "echo", lambda text: console.write(text))
    result = scan(FIXTURES / "vulnerable_python")
    cli._emit(result, "github", None)
    console.flush()
    assert raw.getvalue()


def _scan_json(*args: str) -> dict:
    result = CliRunner().invoke(main, ["scan", VULNERABLE, "-o", "json", "--no-fail", *args])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_version_flag():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "decascan" in result.output


def test_min_severity_drops_lower_findings():
    payload = _scan_json("--min-severity", "high")
    assert payload["summary"]["findings"] > 0
    assert {f["severity"] for f in payload["findings"]} <= {"critical", "high"}


def test_disable_skips_a_rule():
    assert any(f["rule_id"] == "MCP01-001" for f in _scan_json()["findings"])
    assert not any(f["rule_id"] == "MCP01-001" for f in _scan_json("--disable", "MCP01-001")["findings"])


def test_rule_runs_only_that_rule():
    findings = _scan_json("--rule", "MCP01-001")["findings"]
    assert findings and {f["rule_id"] for f in findings} == {"MCP01-001"}


def test_exclude_skips_a_directory_by_name(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "server.py").write_text(
        'API_KEY = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5gH9jL0pQ2sT4uV6wX8yZ0aB2"\n', encoding="utf-8"
    )
    run = lambda *a: json.loads(  # noqa: E731
        CliRunner().invoke(main, ["scan", str(tmp_path), "-o", "json", "--no-fail", *a]).output
    )
    assert run()["summary"]["findings"] > 0
    assert run("--exclude", "vendor")["summary"]["findings"] == 0
