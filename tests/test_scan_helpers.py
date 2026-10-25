"""Unit tests for the lexical helpers behind the LLM and web rules, and for list detection."""

from __future__ import annotations

import re

import pytest

from decascan.core.detect import _root_modules
from decascan.core.standards import RISK_NAMES, RISK_STANDARD, STANDARDS, get_standard
from decascan.rules._scan import (
    SourceFile,
    call_args,
    calls,
    inside_string,
    is_comment,
    is_dynamic_string,
    is_import,
    is_literal,
    is_tainted,
    is_test_path,
    line_of,
    line_text,
    snippet_of,
    tainted_names,
)

# --- call_args ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("f(a, b)", "a, b"),
        ("f(g(a), h(b, c))", "g(a), h(b, c)"),
        ('f("a)b", c)', '"a)b", c'),
        ("f('it\\'s )', 2)", "'it\\'s )', 2"),
        ("f(`x ${y(1)} )`)", "`x ${y(1)} )`"),
        ("f([1, (2, 3)], {'k': (4)})", "[1, (2, 3)], {'k': (4)}"),
        ("f()", ""),
    ],
)
def test_call_args_balances_parentheses_and_skips_quoted_text(text, expected):
    assert call_args(text, text.index("(") + 1) == expected


def test_call_args_gives_up_on_an_unterminated_call_instead_of_running_away():
    text = "f(" + "x" * 10_000
    assert len(call_args(text, 2)) <= 4000


# --- inside_string -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "needle", "expected"),
    [
        ('description="run eval(s) first"', "eval(", True),
        ("description='run eval(s) first'", "eval(", True),
        ("x = eval(s)", "eval(", False),
        ('msg = "a" + eval(s)', "eval(", False),
        ('msg = "say \\"hi\\" eval(s)"', "eval(", True),
    ],
)
def test_inside_string_uses_quote_parity(line, needle, expected):
    assert inside_string(line, line.index(needle)) is expected


# --- line helpers ------------------------------------------------------------------------------


def test_line_of_and_line_text_agree():
    text = "a\nbb\nccc\n"
    assert line_of(text, text.index("bb")) == 2
    assert line_text(text, 3) == "ccc"
    assert line_text(text, 0) == "" and line_text(text, 99) == ""


@pytest.mark.parametrize("line", ["# note", "  // note", " * doc", "/* x", "\t# indented"])
def test_is_comment_true(line):
    assert is_comment(line)


@pytest.mark.parametrize("line", ["x = 1  # trailing", "url = 'http://x'", "run()"])
def test_is_comment_false(line):
    assert not is_comment(line)


@pytest.mark.parametrize(
    "line", ["import os", "from x import y", "const a = require('b')", "  import z"]
)
def test_is_import_true(line):
    assert is_import(line)


def test_snippet_is_stripped_and_truncated():
    assert snippet_of("   x = 1   ") == "x = 1"
    long = snippet_of("y" * 500)
    assert len(long) == 160 and long.endswith("...")


# --- test path detection -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_app.py",
        "pkg/test_util.py",
        "src/util_test.py",
        "web/__tests__/a.ts",
        "web/a.test.ts",
        "web/a.spec.js",
        "conftest.py",
        "app/fixtures/data.py",
    ],
)
def test_test_paths_are_recognised(path):
    assert is_test_path(path)


@pytest.mark.parametrize("path", ["app.py", "src/contest.py", "src/latest/app.py", "server/handlers.ts"])
def test_non_test_paths_are_not(path):
    assert not is_test_path(path)


# --- taint -------------------------------------------------------------------------------------


def test_tainted_names_follow_one_assignment_hop():
    text = "uid = request.args['id']\nname = 'fixed'\nconst q = req.query.q\nx: str = request.json\n"
    assert tainted_names(text) == {"uid", "q", "x"}


def test_tainted_names_ignore_comparisons():
    assert tainted_names("same == request.args\n") == set()


def test_is_tainted_matches_whole_names_only():
    names = {"uid"}
    assert is_tainted("f'{uid}'", names)
    assert not is_tainted("f'{uidx}'", names)
    assert is_tainted("request.args['u']", set())
    assert not is_tainted("'static'", names)


# --- string shape ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        'f"SELECT {x}"',
        '"SELECT %s" % x',
        '"SELECT {}".format(x)',
        '"SELECT " + x',
        'x + " WHERE"',
        "`SELECT ${x}`",
    ],
)
def test_dynamic_strings(args):
    assert is_dynamic_string(args)


@pytest.mark.parametrize("args", ['"SELECT 1"', '"SELECT ?", (x,)', "'a'", "`plain`", "query"])
def test_static_strings_are_not_dynamic(args):
    assert not is_dynamic_string(args)


@pytest.mark.parametrize("args", ['"abc"', "'abc'", '"abc", 1', "r'abc'", '  "abc"  '])
def test_is_literal_true(args):
    assert is_literal(args)


@pytest.mark.parametrize("args", ["x", 'f"abc"', '"a" + x', '"a"b', ""])
def test_is_literal_false(args):
    assert not is_literal(args)


# --- calls -------------------------------------------------------------------------------------


def test_calls_yields_line_args_and_source_and_skips_noise():
    text = (
        "# run(commented)\n"
        "import run\n"
        'msg = "run(quoted)"\n'
        "run(1, (2))\n"
        "x = run(\n"
        "    'multi',\n"
        ")\n"
    )
    found = list(calls(SourceFile("a.py", text, False), re.compile(r"\brun\(")))
    assert [(c.line, c.args.strip()) for c in found] == [(4, "1, (2)"), (5, "'multi',")]
    assert found[0].source_line == "run(1, (2))"


# --- standards ---------------------------------------------------------------------------------


def test_risk_ids_are_unique_across_lists():
    all_ids = [rid for s in STANDARDS.values() for rid in s.risks]
    assert len(all_ids) == len(set(all_ids))


def test_lookup_tables_resolve_every_risk():
    for standard in STANDARDS.values():
        for risk_id, name in standard.risks.items():
            assert RISK_NAMES[risk_id] == name
            assert RISK_STANDARD[risk_id] == standard.id


def test_not_static_risks_exist_in_their_list():
    for standard in STANDARDS.values():
        assert standard.not_static <= set(standard.risks)


def test_get_standard_rejects_unknown_ids():
    assert get_standard("llm").id == "llm"
    with pytest.raises(ValueError, match="unknown standard"):
        get_standard("nope")


# --- detection helpers -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "expected"),
    [
        ("flask", {"flask"}),
        ("langchain_openai.chat_models", {"langchain-openai", "langchain", "langchain-openai.chat-models"}),
        ("@modelcontextprotocol/sdk/server/index.js", {"@modelcontextprotocol/sdk"}),
        ("express", {"express"}),
        ("google.generativeai", {"google", "google.generativeai"}),
    ],
)
def test_root_modules(module, expected):
    assert _root_modules(module) >= expected
