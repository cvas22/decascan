"""Scan time must not blow up on large or hostile files, and line lookups must stay correct."""

from __future__ import annotations

import time

import pytest

from mcp_sift.core.config import ScanConfig
from mcp_sift.core.lines import line_of, line_starts, line_text
from mcp_sift.core.scanner import scan

# Generous bounds: these cases ran in well under 2 seconds when written, but before the fixes they
# ran for minutes, so a loose limit still catches a regression to quadratic behaviour.
LIMIT_SECONDS = 20


def timed_scan(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    started = time.perf_counter()
    result = scan(tmp_path, ScanConfig())
    return result, time.perf_counter() - started


def test_many_matches_in_one_file_scale_linearly(tmp_path):
    result, seconds = timed_scan(tmp_path, "gen.py", "x = eval(expr)\n" * 20_000)
    assert len([f for f in result.findings if f.rule_id == "WEB03-003"]) == 20_000
    assert seconds < LIMIT_SECONDS


@pytest.mark.parametrize(
    "text",
    [
        '"role": "system", "content": ' * 60_000,
        'x = f"{' * 200_000,
        "f(" * 700_000,
        'password = "' * 150_000,
        "'\"`" * 500_000,
    ],
    ids=["role-content", "fstring-brace", "open-parens", "password-quote", "mixed-quotes"],
)
def test_single_huge_line_does_not_stall_the_scan(tmp_path, text):
    result, seconds = timed_scan(tmp_path, "min.py", text)
    assert result.errors == [] or all("syntax" in e for e in result.errors)
    assert seconds < LIMIT_SECONDS


def test_minified_files_are_skipped_by_the_pattern_rules_only(tmp_path):
    line = "var a=eval(b);" * 1000  # 14k chars on one line
    (tmp_path / "bundle.js").write_text(line + "\n", encoding="utf-8")
    (tmp_path / "ok.js").write_text("const a = eval(b);\n", encoding="utf-8")
    flagged = {f.file_path for f in scan(tmp_path, ScanConfig()).findings if f.rule_id == "WEB03-003"}
    assert flagged == {"ok.js"}


# --- line helpers ------------------------------------------------------------------------------


def test_line_starts_and_lookups():
    text = "ab\ncd\n\nlast"
    assert line_starts(text) == (0, 3, 6, 7)
    assert [line_of(text, i) for i in (0, 2, 3, 5, 6, 7, 10)] == [1, 1, 2, 2, 3, 4, 4]
    assert [line_text(text, n) for n in (1, 2, 3, 4)] == ["ab", "cd", "", "last"]


def test_line_text_out_of_range_and_crlf():
    assert line_text("a\r\nb\r\n", 1) == "a"
    assert line_text("a\nb", 0) == "" and line_text("a\nb", 3) == ""
    assert line_text("", 1) == ""


def test_trailing_newline_gives_an_empty_final_line():
    assert line_text("a\n", 2) == ""
    assert line_of("a\n", 2) == 2
