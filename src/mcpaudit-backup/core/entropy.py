"""Shannon entropy, used to separate real credentials from placeholders and English words."""

from __future__ import annotations

import math
from collections import Counter

_PLACEHOLDER_MARKERS = (
    "${",
    "{{",
    "<",
    "your",
    "xxx",
    "changeme",
    "change_me",
    "example",
    "placeholder",
    "redacted",
    "dummy",
    "fake",
    "insert",
    "todo",
    "replace",
    "os.environ",
    "os.getenv",
    "process.env",
    "n/a",
    "none",
    "null",
    "...",
)


def shannon_entropy(value: str) -> float:
    """Bits per character. Random 32-char base64 lands ~5.0; English prose ~3.0; 'changeme' ~2.5."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if len(set(lowered)) <= 2:  # "aaaaaaaa", "xxxxxxxx"
        return True
    return False


def redact(secret: str, keep: int = 4) -> str:
    """Never echo a live credential back into logs, CI output, or a SARIF file."""
    secret = secret.strip()
    if len(secret) <= keep:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * min(len(secret) - keep, 20)}"
