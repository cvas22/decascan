"""Comments and docstrings are not code: the pattern rules must not report what they mention."""

from __future__ import annotations

import pytest

from decascan.core.config import ScanConfig
from decascan.core.mask import mask_javascript, mask_python, mask_source
from decascan.core.scanner import scan

WEB = ScanConfig(standards=frozenset({"web"}), merge_duplicates=False)


def fires(tmp_path, source, name="app.py"):
    (tmp_path / name).write_text(source, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path, WEB).findings}


# --- the property that makes line numbers and snippets safe ---------------------------------------


@pytest.mark.parametrize(
    ("masker", "source"),
    [
        (mask_python, '"""Doc with eval(x)."""\n\n# comment eval(y)\nx = 1  # trailing\n'),
        (mask_javascript, "/* eval(x) */\nconst a = 1; // eval(y)\n/**\n * JSDoc eval(z)\n */\n"),
    ],
)
def test_masking_preserves_length_and_line_structure(masker, source):
    masked = masker(source)
    assert len(masked) == len(source)
    assert [i for i, c in enumerate(masked) if c == "\n"] == [i for i, c in enumerate(source) if c == "\n"]
    assert "eval" not in masked


# --- Python ------------------------------------------------------------------------------------


def test_module_function_and_class_docstrings_are_masked(tmp_path):
    source = (
        '"""Module: never os.system("ping " + host)."""\n'
        "class A:\n"
        '    """Class: eval(user)."""\n'
        "    def f(self):\n"
        '        """Function: DEBUG = True; subprocess.run(cmd, shell=True)."""\n'
        "        return 1\n"
    )
    assert fires(tmp_path, source) == set()


def test_multiline_docstring_is_masked_but_the_code_after_it_is_not(tmp_path):
    source = '"""\nExample:\n    eval(user_code)\n"""\nDEBUG = True\n'
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = scan(tmp_path, WEB).findings
    assert [(f.rule_id, f.line) for f in findings] == [("WEB05-001", 5)]


def test_trailing_and_full_line_comments_are_masked(tmp_path):
    assert fires(tmp_path, "x = 1  # eval(user) is dangerous\n# DEBUG = True\n") == set()


def test_a_bare_string_statement_and_implicit_concatenation_are_masked():
    masked = mask_python('"eval(x)" "os.system(y)"\nz = 1\n')
    assert "eval" not in masked and "os.system" not in masked and "z = 1" in masked


@pytest.mark.parametrize(
    "source",
    [
        'cur.execute(f"SELECT {x}")\n',
        'query = f"SELECT * FROM t WHERE id={i}"\ncur.execute(query)\n',
        'name = "eval(x)"\n',
        'messages = [{"role": "system", "content": f"hi {user}"}]\n',
        'x = ("part one "\n     "part two")\n',
    ],
)
def test_strings_that_are_values_are_left_alone(source):
    assert mask_python(source) == source


def test_real_code_after_a_docstring_still_fires(tmp_path):
    source = 'def run(cmd):\n    """Runs cmd."""\n    os.system("ping " + cmd)\n'
    assert "WEB03-002" in fires(tmp_path, source)


def test_code_that_mentions_a_pattern_in_a_value_string_still_fires(tmp_path):
    assert "WEB03-001" in fires(tmp_path, 'cur.execute(f"SELECT * FROM t WHERE id={i}")\n')


def test_a_string_that_is_an_argument_is_not_a_docstring():
    source = 'print("eval(x)")\nlog("DEBUG = True")\n'
    assert mask_python(source) == source


def test_unterminated_or_invalid_python_is_returned_unchanged():
    broken = 'x = """never closed\neval(y)\n'
    assert mask_python(broken) == broken
    assert mask_python("def (:\n") == "def (:\n"


def test_nested_function_docstrings_and_decorated_defs():
    source = '@decorator\ndef f():\n    def g():\n        """eval(x)"""\n    return g\n'
    assert "eval" not in mask_python(source)


def test_non_ascii_text_keeps_offsets_aligned():
    source = '"""é — eval(x)"""\nπ = 1  # ü eval\nDEBUG = True\n'
    masked = mask_python(source)
    assert len(masked) == len(source) and masked.splitlines()[2] == "DEBUG = True"


# --- JavaScript / TypeScript --------------------------------------------------------------------


def test_block_comments_jsdoc_and_line_comments_are_masked(tmp_path):
    source = "/** eval(x) */\n// document.write(y)\nconst a = 1; /* el.innerHTML = z */\n"
    assert fires(tmp_path, source, "a.js") == set()


def test_code_after_a_comment_on_the_same_line_still_fires(tmp_path):
    assert "WEB03-004" in fires(tmp_path, "/* note */ el.innerHTML = userHtml;\n", "a.js")


def test_double_slash_inside_a_string_is_not_a_comment():
    source = 'const u = "https://example.com/a"; const v = `http://x/${id}`;\n'
    assert mask_javascript(source) == source


def test_comment_markers_inside_strings_and_templates_survive():
    source = "const a = '// not a comment'; const b = `/* nor this */`;\n"
    assert mask_javascript(source) == source


def test_escaped_quotes_do_not_end_a_string_early():
    source = "const a = 'it\\'s // still a string'; // real comment\n"
    masked = mask_javascript(source)
    assert "still a string" in masked and "real comment" not in masked


def test_unterminated_block_comment_masks_to_the_end():
    assert mask_javascript("a = 1; /* never closed eval(x)\nmore\n").count("eval") == 0


def test_a_url_fetch_is_still_flagged_after_masking(tmp_path):
    assert "WEB10-001" in fires(tmp_path, 'const r = await fetch("http://x/" + req.query.u);\n', "a.js")


# --- dispatch ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a.py", "a.ts", "a.tsx", "a.js", "a.mjs", "a.cjs", "a.jsx", "a.mts"])
def test_source_files_are_masked(name):
    comment = "# eval(x)\n" if name.endswith(".py") else "// eval(x)\n"
    assert "eval" not in mask_source(name, comment)


@pytest.mark.parametrize("name", ["a.json", "a.yaml", "README.md", "a.sh", ".env"])
def test_other_files_are_left_alone(name):
    assert mask_source(name, "# eval(x)\n// eval(y)\n") == "# eval(x)\n// eval(y)\n"


# --- end to end ----------------------------------------------------------------------------------


def test_the_scanners_own_docstring_examples_no_longer_trip_it(tmp_path):
    source = (
        '"""Collapse duplicates.\n\n'
        '`os.system("ping " + host)` is command injection to the MCP list and the web list.\n"""\n'
        "def merge():\n"
        "    return 1\n"
    )
    assert fires(tmp_path, source) == set()


def test_inline_suppression_still_works_when_comments_are_masked(tmp_path):
    (tmp_path / "app.py").write_text("DEBUG = True  # decascan:ignore\n", encoding="utf-8")
    assert scan(tmp_path, WEB).findings == []


def test_masked_text_is_cached_per_file(tmp_path):
    from decascan.core.context import build_context

    (tmp_path / "a.py").write_text("# c\nx = 1\n", encoding="utf-8")
    ctx = build_context(tmp_path, ScanConfig())
    assert ctx.masked_text("a.py") is ctx.masked_text("a.py")


def test_blank_lines_above_a_match_do_not_shift_its_line_number(tmp_path):
    # `^\s*` used to swallow the newlines, so the finding was reported on the first blank line.
    (tmp_path / "app.py").write_text("\n\n\nDEBUG = True\n", encoding="utf-8")
    (finding,) = scan(tmp_path, WEB).findings
    assert finding.line == 4 and finding.snippet == "DEBUG = True"


def test_inline_suppression_works_after_blank_lines(tmp_path):
    (tmp_path / "app.py").write_text("\n\nDEBUG = True  # decascan:ignore\n", encoding="utf-8")
    assert scan(tmp_path, WEB).findings == []
