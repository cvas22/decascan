"""Logging: opt-in, never on stdout, structured when asked, and silent by default."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_sift.cli import main
from mcp_sift.core import log as logging_setup
from mcp_sift.core.config import ScanConfig
from mcp_sift.core.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = str(FIXTURES / "vulnerable_webllm")


@pytest.fixture(autouse=True)
def _reset_logging():
    yield
    logging_setup.disable()


def run(*args: str):
    return CliRunner().invoke(main, list(args))


def test_no_flags_means_no_log_output():
    result = run("scan", VULNERABLE, "--no-fail")
    assert result.exit_code == 0
    assert "scan started" not in result.output and "scan finished" not in result.output


def test_verbose_logs_progress_to_stderr_and_keeps_stdout_clean():
    result = run("-v", "scan", VULNERABLE, "-o", "json", "--no-fail")
    data = json.loads(result.stdout)  # would raise if a log line leaked into stdout
    assert data["summary"]["findings"] > 0
    for message in ("scan started", "context built", "lists selected", "scan finished"):
        assert message in result.stderr
        assert message not in result.stdout


def test_default_verbosity_hides_debug_and_double_v_shows_rule_timings():
    quiet = run("-v", "scan", VULNERABLE, "--no-fail").stderr
    assert "rule finished" not in quiet
    chatty = run("-vv", "scan", VULNERABLE, "--no-fail").stderr
    assert "rule finished" in chatty and "rule=WEB05-001" in chatty and "ms=" in chatty


def test_log_records_which_lists_were_auto_detected_and_why():
    stderr = run("-v", "scan", VULNERABLE, "--no-fail").stderr
    assert "mode=auto" in stderr and "imports flask" in stderr


def test_explicit_standard_is_logged_as_explicit():
    assert "mode=explicit" in run("-v", "scan", VULNERABLE, "-s", "web", "--no-fail").stderr


def test_json_log_format_is_one_object_per_line(tmp_path):
    log_file = tmp_path / "scan.log.jsonl"
    result = run("-vv", "--log-format", "json", "--log-file", str(log_file), "scan", VULNERABLE, "--no-fail")
    assert result.exit_code == 0
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert records and all({"ts", "level", "logger", "msg"} <= set(r) for r in records)
    finished = next(r for r in records if r["msg"] == "scan finished")
    assert finished["findings"] > 0 and finished["errors"] == 0 and finished["logger"] == "mcp_sift.scanner"
    assert "Auto-detected" not in log_file.read_text(encoding="utf-8")  # the report is not in the log


def test_log_file_alone_implies_progress_logging(tmp_path):
    log_file = tmp_path / "scan.log"
    run("--log-file", str(log_file), "scan", VULNERABLE, "--no-fail")
    text = log_file.read_text(encoding="utf-8")
    assert "scan finished" in text and "rule finished" not in text


def test_log_format_alone_turns_logging_on():
    stderr = run("--log-format", "json", "scan", VULNERABLE, "--no-fail").stderr
    assert json.loads(stderr.splitlines()[0])["msg"] == "scan started"


def test_environment_variables_configure_logging(tmp_path):
    log_file = tmp_path / "env.log"
    env = {"MCP_SIFT_LOG_FILE": str(log_file), "MCP_SIFT_LOG_FORMAT": "json", "MCP_SIFT_VERBOSE": "2"}
    CliRunner().invoke(main, ["scan", VULNERABLE, "--no-fail"], env=env)
    assert "rule finished" in log_file.read_text(encoding="utf-8")


def test_txt_is_a_plain_text_log_and_an_alias_for_text(tmp_path):
    txt, text = tmp_path / "a.txt", tmp_path / "b.log"
    run("--log-format", "txt", "--log-file", str(txt), "scan", VULNERABLE, "--no-fail")
    run("--log-format", "text", "--log-file", str(text), "scan", VULNERABLE, "--no-fail")
    lines = txt.read_text(encoding="utf-8").splitlines()
    assert lines and not lines[0].startswith("{")
    assert "INFO" in lines[0] and "scan started" in lines[0]

    def stable(path):  # drop the timestamp and the timing-dependent lines
        rows = path.read_text(encoding="utf-8").splitlines()
        return [row.split(" ", 1)[1] for row in rows if "seconds=" not in row]

    assert stable(txt) == stable(text)


def test_unknown_log_format_is_rejected():
    assert run("--log-format", "xml", "scan", VULNERABLE).exit_code == 2


def test_rule_failures_are_logged_with_the_rule_id(monkeypatch, tmp_path, caplog):
    import mcp_sift.rules as rules_pkg
    from mcp_sift.rules import base

    def boom(ctx):
        raise RuntimeError("kaput")

    broken = base.Rule("WEB05-999", "WEB05", "x", "x", boom)
    monkeypatch.setattr(rules_pkg, "REGISTRY", [*rules_pkg.REGISTRY, broken])
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    logger = logging.getLogger("mcp_sift")
    logger.propagate = True  # caplog listens on the root logger
    with caplog.at_level(logging.WARNING, logger="mcp_sift"):
        result = scan(tmp_path, ScanConfig())
    assert any("WEB05-999" in e for e in result.errors)
    record = next(r for r in caplog.records if r.getMessage() == "rule failed")
    assert record.rule == "WEB05-999" and "kaput" in record.error


def test_unparseable_files_are_logged(tmp_path, caplog):
    (tmp_path / "bad.py").write_text("def (:\n", encoding="utf-8")
    logging.getLogger("mcp_sift").propagate = True
    with caplog.at_level(logging.WARNING, logger="mcp_sift"):
        scan(tmp_path, ScanConfig())
    assert any(r.getMessage() == "file could not be parsed" and r.file == "bad.py" for r in caplog.records)


def test_skipped_files_are_counted_and_listed_at_debug(tmp_path, caplog):
    (tmp_path / "big.py").write_text("x = 1\n" * 10, encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("x\n", encoding="utf-8")
    logging.getLogger("mcp_sift").propagate = True
    with caplog.at_level(logging.DEBUG, logger="mcp_sift"):
        scan(tmp_path, ScanConfig(max_file_bytes=5))
    built = next(r for r in caplog.records if r.getMessage() == "context built")
    assert built.skipped_too_large == 1 and built.skipped_excluded == 1
    assert any(r.getMessage().startswith("file skipped: over size limit") for r in caplog.records)


def test_suppressed_findings_are_logged_at_debug(tmp_path, caplog):
    (tmp_path / "a.py").write_text("DEBUG = True  # mcp-sift:ignore\n", encoding="utf-8")
    logging.getLogger("mcp_sift").propagate = True
    with caplog.at_level(logging.DEBUG, logger="mcp_sift"):
        scan(tmp_path, ScanConfig(standards=frozenset({"web"})))
    suppressed = [r for r in caplog.records if r.getMessage() == "finding suppressed inline"]
    assert [r.rule for r in suppressed] == ["WEB05-001"]


def test_library_default_is_silent(tmp_path, capsys):
    logging_setup.disable()
    (tmp_path / "a.py").write_text("DEBUG = True\n", encoding="utf-8")
    scan(tmp_path, ScanConfig())
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_configure_is_idempotent_and_replaces_handlers(tmp_path):
    logger = logging.getLogger("mcp_sift")
    logging_setup.configure(1, None, "text")
    logging_setup.configure(2, tmp_path / "x.log", "json")
    assert len(logger.handlers) == 1 and isinstance(logger.handlers[0], logging.FileHandler)
    assert logger.level == logging.DEBUG


def test_configure_rejects_unknown_format():
    with pytest.raises(ValueError, match="unknown log format"):
        logging_setup.configure(1, None, "yaml")


@pytest.mark.parametrize(
    ("verbosity", "level"),
    [(0, logging.WARNING), (1, logging.INFO), (2, logging.DEBUG), (5, logging.DEBUG)],
)
def test_verbosity_maps_to_levels(verbosity, level):
    assert logging_setup.level_for(verbosity) == level


def test_text_formatter_appends_fields_as_key_value():
    record = logging.LogRecord("mcp_sift.x", logging.INFO, __file__, 1, "hello", None, None)
    record.files = 3
    line = logging_setup.TextFormatter().format(record)
    assert "INFO" in line and "hello" in line and line.endswith("files=3")


def test_json_formatter_includes_exception_text():
    try:
        raise ValueError("bad")
    except ValueError:
        import sys

        record = logging.LogRecord("mcp_sift.x", logging.ERROR, __file__, 1, "oops", None, sys.exc_info())
    payload = json.loads(logging_setup.JsonFormatter().format(record))
    assert payload["level"] == "error" and "ValueError: bad" in payload["exc"]
