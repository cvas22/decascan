"""The events a run logs: what each one says, at which level, and that nothing leaks into the report."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner

import decascan.core.context as context_module
import decascan.core.scanner as scanner_module
from decascan.cli import main
from decascan.core import log as logging_setup
from decascan.core.config import ScanConfig
from decascan.core.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = str(FIXTURES / "vulnerable_webllm")
CLEAN = str(FIXTURES / "clean_webllm")


@pytest.fixture(autouse=True)
def _reset_logging():
    yield
    logging_setup.disable()


class _Records:
    """caplog replaces its record list between test phases, so read it lazily."""

    def __init__(self, caplog):
        self._caplog = caplog

    def __iter__(self):
        return iter(self._caplog.records)


@pytest.fixture
def records(caplog):
    logging.getLogger("decascan").propagate = True
    caplog.set_level(logging.DEBUG, logger="decascan")
    return _Records(caplog)


def messages(records):
    return [r.getMessage() for r in records]


def first(records, message):
    return next(r for r in records if r.getMessage() == message)


def run_cli(*args):
    return CliRunner().invoke(main, list(args))


# --- CLI ---------------------------------------------------------------------------------------


def test_scan_requested_records_the_options():
    options = ["-o", "json", "--fail-on", "critical", "--no-fail", "-s", "web"]
    err = run_cli("-v", "scan", VULNERABLE, *options).stderr
    line = next(line for line in err.splitlines() if "scan requested" in line)
    expected = ("output=json", "fail_on=critical", "no_fail=True", "standards=web", "output_file=stdout")
    for fragment in expected:
        assert fragment in line


def test_environment_is_logged_at_debug_only():
    assert "environment version=" not in run_cli("-v", "scan", CLEAN).stderr
    debug = run_cli("-vv", "scan", CLEAN).stderr
    assert "environment version=" in debug and "python=" in debug and "platform=" in debug


def test_report_written_to_stdout_and_to_a_file(tmp_path):
    out = run_cli("-v", "scan", VULNERABLE, "-o", "json", "--no-fail")
    assert "report written format=json destination=stdout findings=" in out.stderr
    assert "bytes=" in out.stderr
    target = tmp_path / "r.sarif"
    err = run_cli("-v", "scan", VULNERABLE, "-o", "sarif", "-f", str(target), "--no-fail").stderr
    assert f"destination={target}" in err and f"bytes={target.stat().st_size}" in err


def test_pretty_report_to_a_file_logs_its_size(tmp_path):
    target = tmp_path / "r.txt"
    err = run_cli("-v", "scan", VULNERABLE, "-f", str(target), "--no-fail").stderr
    assert "report written format=pretty" in err and f"bytes={target.stat().st_size}" in err


@pytest.mark.parametrize(
    ("args", "code", "reason"),
    [
        ((VULNERABLE, "--no-fail"), 0, "--no-fail"),
        ((VULNERABLE,), 1, "finding at or above high"),
        ((CLEAN,), 0, "nothing at or above high"),
        ((VULNERABLE, "--fail-on", "critical"), 1, "finding at or above critical"),
    ],
)
def test_exit_decision_is_logged_with_its_reason(args, code, reason):
    result = run_cli("-v", "scan", *args)
    assert result.exit_code == code
    assert f"exiting code={code} reason={reason}" in result.stderr


def test_exit_reason_names_the_worst_severity_when_below_the_threshold(tmp_path):
    (tmp_path / "a.py").write_text("try:\n    x()\nexcept:\n    pass\n", encoding="utf-8")
    err = run_cli("-v", "scan", str(tmp_path)).stderr
    assert "nothing at or above high (worst: low)" in err


def test_an_aborted_scan_logs_the_failure_and_the_exit(monkeypatch, tmp_path):
    import decascan.cli as cli

    def boom(*_a, **_k):
        raise RuntimeError("internal failure")

    monkeypatch.setattr(cli, "scan", boom)
    err = run_cli("-v", "scan", str(tmp_path)).stderr
    assert "scan aborted" in err and "exiting code=2 reason=scan aborted" in err


# --- scan --------------------------------------------------------------------------------------


def test_scan_configuration_is_logged_at_debug(records):
    scan(Path(VULNERABLE), ScanConfig(disabled_rules=frozenset({"WEB05-001"}), excludes=("vendor",)))
    config = first(records, "scan configuration")
    assert config.levelno == logging.DEBUG
    assert config.disabled_rules == "WEB05-001" and config.extra_excludes == "vendor"
    assert config.standards == "auto" and config.merge_duplicates is True


def test_rule_selection_counts_skipped_and_disabled_rules(records):
    scan(Path(VULNERABLE), ScanConfig(standards=frozenset({"web"}), disabled_rules=frozenset({"WEB05-001"})))
    selected = first(records, "lists selected")
    assert selected.mode == "explicit" and selected.rules_disabled == 1
    assert selected.rules_skipped_other_lists > 0
    assert first(records, "rules disabled by option").rules == "WEB05-001"


def test_rules_finished_summary_names_the_slowest_rules(records):
    scan(Path(VULNERABLE), ScanConfig(standards=frozenset({"web"})))
    done = first(records, "rules finished")
    assert done.failed == 0 and done.raw_findings > 0
    assert done.slowest.count("ms") == 3 and "=" in done.slowest


def test_filtered_findings_are_counted(records, tmp_path):
    (tmp_path / "a.py").write_text(
        "DEBUG = True  # decascan:ignore\ntry:\n    x()\nexcept:\n    pass\n", encoding="utf-8"
    )
    scan(tmp_path, ScanConfig(standards=frozenset({"web"}), min_severity=scanner_module.Severity.MEDIUM))
    filtered = first(records, "findings filtered")
    assert filtered.suppressed_inline == 1 and filtered.below_min_severity == 1 and filtered.kept == 0


def test_no_filtered_event_when_nothing_was_filtered(records):
    scan(Path(CLEAN), ScanConfig())
    assert "findings filtered" not in messages(records)


def test_each_merged_duplicate_is_explained(records, tmp_path):
    (tmp_path / "app.py").write_text("import openai\neval(response)\n", encoding="utf-8")
    scan(tmp_path, ScanConfig(standards=frozenset({"llm", "web"})))
    merged = first(records, "merged duplicate")
    assert merged.cwe == "CWE-95" and merged.kept == "LLM05-001" and merged.also == "WEB03-003"
    assert first(records, "cross-list duplicates merged").merged == 1


def test_finish_event_has_timing_breakdown_and_severity_counts(records):
    scan(Path(VULNERABLE), ScanConfig())
    done = first(records, "scan finished")
    assert done.context_seconds >= 0 and done.rules_seconds >= 0 and done.seconds >= done.rules_seconds
    assert done.severity_high > 0 and done.severity_critical > 0
    assert not hasattr(done, "severity_info")  # zero counts are left out


def test_repository_root_resolution_is_logged(records, tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
    scan(tmp_path / "pkg", ScanConfig())
    resolved = first(records, "repository root resolved")
    assert resolved.path_prefix == "pkg" and resolved.repo_root.endswith(tmp_path.name)


# --- context -----------------------------------------------------------------------------------


def test_every_file_read_is_logged_with_kind_and_size(records, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("const x = 1;\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    read = {r.file: r for r in records if r.getMessage() == "file read"}
    assert read["a.py"].kind == "python" and read["b.js"].kind == "javascript"
    assert read["a.py"].bytes == (tmp_path / "a.py").stat().st_size  # CRLF on Windows, so not len()
    built = first(records, "context built")
    assert built.kinds == "javascript=1, python=1" and built.bytes == read["a.py"].bytes + read["b.js"].bytes
    assert built.seconds >= 0


def test_manifest_dependencies_and_lockfile_events(records, tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "a"}], "scopes": ["read:files"], "mcpServers": {"s": {"port": 80}}}),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask==2.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "node x.js"}}', encoding="utf-8")
    (tmp_path / "uv.lock").write_text("# lock\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    manifest = first(records, "manifest read")
    assert manifest.tools == 1 and manifest.scopes == 1 and manifest.network_exposed is True
    reads = {r.file: r for r in records if r.getMessage() == "dependencies read"}
    assert reads["requirements.txt"].dependencies == 1 and reads["package.json"].install_hooks == 1
    assert first(records, "lockfile found").file == "uv.lock"
    assert first(records, "context built").lockfiles == 1


def test_a_manifest_that_is_not_an_object_is_noted(records, tmp_path):
    (tmp_path / "mcp.json").write_text("[1, 2]", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    assert first(records, "manifest ignored: not a JSON/YAML object").file == "mcp.json"


def test_source_facts_summary_for_files_with_findings_inputs(records, tmp_path):
    (tmp_path / "s.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n"
        "@mcp.tool()\ndef f(c: str):\n    return c\n",
        encoding="utf-8",
    )
    scan(tmp_path, ScanConfig())
    facts = first(records, "source facts")
    assert facts.file == "s.py" and facts.tools == 1 and facts.servers == 1


def test_minified_file_is_logged_once_not_once_per_rule(records, tmp_path):
    (tmp_path / "bundle.js").write_text("var a=1;" * 2000 + "\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    skipped = [r for r in records if r.getMessage().startswith("file skipped by pattern rules")]
    assert len(skipped) == 1 and skipped[0].longest_line > skipped[0].limit


def test_masked_files_report_how_much_was_blanked(records, tmp_path):
    (tmp_path / "a.py").write_text('"""doc"""\n# comment\nx = 1\n', encoding="utf-8")
    scan(tmp_path, ScanConfig())
    masked = first(records, "comments and docstrings masked")
    assert masked.file == "a.py" and 0 < masked.chars_blanked < masked.chars


def test_files_without_comments_log_no_masking_event(records, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    assert "comments and docstrings masked" not in messages(records)


def test_import_of_a_generic_name_is_noted_but_does_not_select_a_list(records, tmp_path):
    (tmp_path / "a.py").write_text("import ai\n", encoding="utf-8")
    result = scan(tmp_path, ScanConfig())
    assert result.detected == {}
    assert first(records, "import ignored: name too generic").imported == "ai"
    assert "no list recognised from imports or dependencies" in messages(records)


# --- warnings ----------------------------------------------------------------------------------


def test_a_slow_file_is_a_warning(records, tmp_path, monkeypatch):
    monkeypatch.setattr(context_module, "SLOW_FILE_SECONDS", -1.0)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    slow = first(records, "slow file")
    assert slow.levelno == logging.WARNING and slow.file == "a.py" and slow.parser == "python parser"


def test_a_slow_rule_is_a_warning(records, tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module, "SLOW_RULE_SECONDS", -1.0)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    scan(tmp_path, ScanConfig(standards=frozenset({"web"})))
    assert any(r.getMessage() == "slow rule" and r.levelno == logging.WARNING for r in records)


def test_nothing_slow_means_no_slow_warnings(records, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    assert "slow file" not in messages(records) and "slow rule" not in messages(records)


# --- the report stays clean --------------------------------------------------------------------


def test_json_report_is_still_valid_with_maximum_logging():
    result = run_cli("-vv", "--log-format", "json", "scan", VULNERABLE, "-o", "json", "--no-fail")
    report = json.loads(result.stdout)
    assert report["summary"]["findings"] > 0
    for line in result.stderr.splitlines():
        json.loads(line)  # every log line is itself valid JSON


def test_every_json_log_line_carries_its_fields():
    err = run_cli("-vv", "--log-format", "json", "scan", VULNERABLE, "--no-fail").stderr
    events = [json.loads(line) for line in err.splitlines()]
    assert {"scan requested", "context built", "lists selected", "rules finished", "scan finished",
            "report written", "exiting"} <= {e["msg"] for e in events}
    finished = next(e for e in events if e["msg"] == "rules finished")
    assert finished["level"] == "info" and finished["logger"] == "decascan.scanner"
    assert all(e["ts"] and e["level"] in {"debug", "info", "warning", "error"} for e in events)


def test_no_logging_flags_means_no_log_lines_even_with_the_new_events():
    result = run_cli("scan", VULNERABLE, "--no-fail")
    for fragment in ("scan requested", "rules finished", "report written", "exiting code="):
        assert fragment not in result.output and fragment not in result.stderr


# --- a guard against the bug the first version of this feature had -----------------------------


def test_no_log_call_uses_a_key_that_logging_reserves():
    """`extra={"module": ...}` raises KeyError the moment DEBUG logging is on; catch it in review."""
    import ast

    reserved = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
    offenders = []
    for path in (Path(__file__).parent.parent / "src" / "decascan").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.keyword) and node.arg == "extra" and isinstance(node.value, ast.Dict):
                for key in node.value.keys:
                    if isinstance(key, ast.Constant) and key.value in reserved:
                        offenders.append(f"{path.name}:{node.value.lineno} {key.value!r}")
    assert offenders == []
