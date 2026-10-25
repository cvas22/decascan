"""Blank out the parts of source that are not code, so lexical rules only see code.

A docstring that shows `os.system("ping " + host)` as an example of what *not* to write, or a comment
that mentions `eval(`, is not a vulnerability. The pattern-based rules (LLM and web lists) run on
text, so they used to report both. `mask_source` replaces comments and docstring-style statements
with spaces, keeping every newline and every other character in place, so line numbers, columns and
snippets are unchanged.

What is masked:
  Python      `#` comments, and string statements on their own (docstrings and bare strings)
  JS / TS     `//` and `/* */` comments, including JSDoc
What is deliberately not masked: strings that are values -- an SQL f-string, a system prompt, a URL.
Rules read those on purpose.
"""

from __future__ import annotations

import io
import re
import tokenize

from .lines import line_starts

_NOT_NEWLINE = re.compile(r"[^\r\n]")
_SKIP = {tokenize.NL, tokenize.COMMENT, tokenize.ENCODING}
_STATEMENT_START = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    pieces: list[str] = []
    last = 0
    for start, end in sorted(spans):
        if start < last:
            continue
        pieces.append(text[last:start])
        pieces.append(_NOT_NEWLINE.sub(" ", text[start:end]))
        last = end
    pieces.append(text[last:])
    return "".join(pieces)


def mask_python(text: str) -> str:
    """Comments and standalone string statements -> spaces. Unchanged if the file will not tokenize."""
    starts = line_starts(text)

    def offset(position: tuple[int, int]) -> int:
        row, col = position
        return starts[row - 1] + col if 0 < row <= len(starts) else len(text)

    spans: list[tuple[int, int]] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return text

    at_start = True
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.type == tokenize.COMMENT:
            spans.append((offset(tok.start), offset(tok.end)))
        elif tok.type == tokenize.STRING and at_start:
            # A statement that is only string literals (implicit concatenation allowed) is a
            # docstring or a stray string: it has no effect, so nothing in it is code.
            j = i
            group = []
            while j < len(tokens) and (tokens[j].type == tokenize.STRING or tokens[j].type in _SKIP):
                if tokens[j].type == tokenize.STRING:
                    group.append(tokens[j])
                j += 1
            if j >= len(tokens) or tokens[j].type in (tokenize.NEWLINE, tokenize.ENDMARKER):
                spans.extend((offset(t.start), offset(t.end)) for t in group)
                i = j
                at_start = False
                continue
        if tok.type in _STATEMENT_START:
            at_start = True
        elif tok.type not in _SKIP:
            at_start = False
        i += 1
    return _blank(text, spans)


def mask_javascript(text: str) -> str:
    """`//` and `/* */` comments -> spaces, leaving strings and template literals alone."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                # A backslash escapes the next character; a newline ends a non-template string early.
                if text[i] == "\\":
                    i += 1
                elif text[i] == "\n" and quote != "`":
                    break
                i += 1
            i += 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            spans.append((i, end))
            i = end
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            spans.append((i, end))
            i = end
        else:
            i += 1
    return _blank(text, spans)


def mask_source(path: str, text: str) -> str:
    """The text of `path` with comments and docstrings blanked; line structure is unchanged."""
    lowered = path.lower()
    if lowered.endswith(".py"):
        return mask_python(text)
    if lowered.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs")):
        return mask_javascript(text)
    return text
