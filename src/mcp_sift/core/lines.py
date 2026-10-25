"""Line lookups that stay fast on large files.

Rules report a line for every match. Computing it with `text.count("\n", 0, index)` or by splitting
the file again costs O(file size) per match, so a generated file with tens of thousands of matches
made a scan quadratic. The line-start table is built once per text and searched by bisection.
"""

from __future__ import annotations

from bisect import bisect_right
from functools import lru_cache


@lru_cache(maxsize=512)
def line_starts(text: str) -> tuple[int, ...]:
    starts = [0]
    find = text.find
    pos = find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = find("\n", pos + 1)
    return tuple(starts)


def line_of(text: str, index: int) -> int:
    """1-based line number of the character at `index`."""
    return bisect_right(line_starts(text), index)


def line_text(text: str, line_no: int) -> str:
    """The text of 1-based line `line_no`, without its line ending ("" when out of range)."""
    starts = line_starts(text)
    if not 0 < line_no <= len(starts):
        return ""
    end = starts[line_no] - 1 if line_no < len(starts) else len(text)
    return text[starts[line_no - 1] : end].rstrip("\r")
