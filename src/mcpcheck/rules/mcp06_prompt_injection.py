"""MCP06 — Prompt Injection via Contextual Payloads.

A tool's description is not documentation. It is text placed directly into the model's context by
the server, and the model treats it as instructions — which makes the description field an
instruction-injection primitive that no schema validates and no user ever sees.

Two ways it gets abused, plus the delivery path that makes both worse:

  1. The description tells the model to do something other than describe the tool: exfiltrate a
     file, call this tool before any other, hide its behaviour from the user. This is the "tool
     poisoning" attack, and it works because the model has no way to distinguish a description
     written by the server author from an instruction written by its principal.
  2. The description carries characters a human reviewer cannot see — zero-width joiners, bidi
     overrides, Unicode tag characters — so the text in the code review and the text the model
     reads are different texts.
  3. The tool fetches remote content and hands it straight back to the model, so an attacker who
     controls any page the server can reach controls part of the model's context.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import NET, ToolDef
from .base import rule

# Phrases that are not describing a tool. Each is paired with what it is actually trying to do, so
# the finding can say why it fired rather than just that it did. Kept narrow on purpose: "important"
# and "note that" appear in perfectly honest descriptions and are not here.
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)", re.I),
        "tells the model to discard its previous instructions",
    ),
    (
        re.compile(r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|the)", re.I),
        "tells the model to discard its previous instructions",
    ),
    (
        re.compile(r"(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show|disclose)", re.I),
        "tells the model to hide something from the user",
    ),
    (
        re.compile(r"without\s+(?:telling|informing|notifying|asking|alerting)", re.I),
        "tells the model to act without the user's knowledge",
    ),
    (
        re.compile(r"(?:before|prior to)\s+(?:using|calling|invoking)\s+any\s+other\s+tool", re.I),
        "tries to make itself run ahead of every other tool",
    ),
    (
        re.compile(r"(?:always|first)\s+call\s+this\s+tool", re.I),
        "tries to make itself run ahead of every other tool",
    ),
    (
        re.compile(
            r"(?:reveal|print|output|repeat|return)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)",
            re.I,
        ),
        "asks the model to disclose its system prompt",
    ),
    (
        re.compile(r"~/\.ssh|id_rsa|\.aws/credentials|/etc/(?:passwd|shadow)|\.env\b", re.I),
        "names a credential file the model is being steered toward",
    ),
    (
        re.compile(r"<\s*(?:important|system|secret|hidden|instructions?)\s*>", re.I),
        "impersonates a system-level instruction block",
    ),
    (
        re.compile(r"\b(?:you\s+must|you\s+should\s+always|it\s+is\s+imperative)\b", re.I),
        "issues an imperative to the model rather than describing the tool",
    ),
]

# Characters that render as nothing, or that reorder what follows. Their only purpose in a tool
# description is to make the reviewed text and the executed text differ.
_INVISIBLE = {
    "​": "zero-width space",
    "‌": "zero-width non-joiner",
    "‍": "zero-width joiner",
    "⁠": "word joiner",
    "﻿": "byte-order mark",
    "‪": "left-to-right embedding",
    "‫": "right-to-left embedding",
    "‬": "pop directional formatting",
    "‭": "left-to-right override",
    "‮": "right-to-left override",
    "⁦": "left-to-right isolate",
    "⁧": "right-to-left isolate",
    "⁨": "first-strong isolate",
    "⁩": "pop directional isolate",
    "­": "soft hyphen",
}


def _described_tools(ctx: ScanContext) -> Iterable[ToolDef]:
    for tool in ctx.all_tools:
        if tool.description:
            yield tool


def _hidden_characters(text: str) -> list[str]:
    found: list[str] = []
    for char in text:
        if char in _INVISIBLE:
            found.append(_INVISIBLE[char])
        # Unicode tag block: a full ASCII alphabet that renders as zero pixels. There is no
        # legitimate use of it in a tool description.
        elif 0xE0000 <= ord(char) <= 0xE007F:
            found.append("Unicode tag character")
        elif unicodedata.category(char) == "Cf" and char not in ("\n", "\r", "\t"):
            found.append(f"invisible format character U+{ord(char):04X}")
    return list(dict.fromkeys(found))


@rule(
    id="MCP06-001",
    mcp_id="MCP06",
    name="Tool description carries instructions for the model",
    description="A tool's description instructs the model rather than describing the tool.",
)
def poisoned_tool_description(ctx: ScanContext) -> Iterable[Finding]:
    for tool in _described_tools(ctx):
        description = tool.description or ""
        reasons = [why for pattern, why in _INJECTION_PATTERNS if pattern.search(description)]
        if not reasons:
            continue

        line = tool.description_line or tool.line
        unique = list(dict.fromkeys(reasons))
        yield Finding(
            rule_id="MCP06-001",
            mcp_id="MCP06",
            severity=Severity.CRITICAL,
            title=f"Tool `{tool.name}`'s description instructs the model",
            description=(
                f"The description of `{tool.name}` {unique[0]}"
                + (f", and {unique[1]}" if len(unique) > 1 else "")
                + ". A tool description is loaded straight into the model's context and read as "
                "instructions — the model cannot tell it apart from a directive written by its own "
                "principal. Whoever wrote this text is writing instructions the model will follow, "
                "and the user of the client never sees it."
            ),
            file_path=tool.file,
            line=line,
            snippet=_excerpt(description),
            remediation=(
                f"Make the description describe `{tool.name}` — what it does, what its parameters "
                "mean — and nothing else. It must not tell the model what order to call tools in, "
                "what to conceal from the user, or what files to read. If this server is third-party, "
                "treat the text as hostile and do not install it."
            ),
            cwe_id="CWE-74",
            confidence=0.85,
            metadata={"tool": tool.name, "reasons": "; ".join(unique)},
        )


@rule(
    id="MCP06-002",
    mcp_id="MCP06",
    name="Hidden characters in tool metadata",
    description="A tool description contains invisible or direction-overriding characters.",
)
def hidden_characters_in_description(ctx: ScanContext) -> Iterable[Finding]:
    for tool in _described_tools(ctx):
        description = tool.description or ""
        hidden = _hidden_characters(description)
        if not hidden:
            continue

        line = tool.description_line or tool.line
        yield Finding(
            rule_id="MCP06-002",
            mcp_id="MCP06",
            severity=Severity.HIGH,
            title=f"Tool `{tool.name}`'s description contains hidden characters",
            description=(
                f"The description of `{tool.name}` contains {', '.join(hidden)}. These render as "
                "nothing — or reorder what follows them — so the text a reviewer reads in this file "
                "and the text the model receives are not the same text. That gap is the whole point "
                "of using them: instructions can be carried in a description that looks empty, or "
                "innocuous, to every human who checks it."
            ),
            file_path=tool.file,
            line=line,
            snippet=_excerpt(description),
            remediation=(
                "Strip the description to printable ASCII (or at minimum reject Unicode format "
                "characters, the bidi overrides, and the tag block). Do this at the boundary where "
                "tool definitions are loaded, so it also covers descriptions the server did not "
                "write itself."
            ),
            cwe_id="CWE-451",
            confidence=0.9,
            metadata={"tool": tool.name, "characters": ", ".join(hidden)},
        )


@rule(
    id="MCP06-003",
    mcp_id="MCP06",
    name="Remote content returned to the model unsanitized",
    description="A tool fetches network content and hands it straight back to the model.",
)
def remote_content_to_model(ctx: ScanContext) -> Iterable[Finding]:
    for facts in ctx.source_facts.values():
        for ret in facts.external_returns:
            if ret.origin.capability != NET:
                continue

            owner = f"`{ret.tool}`" if ret.tool else "A tool"
            by_tool = f" by `{ret.tool}`" if ret.tool else ""
            yield Finding(
                rule_id="MCP06-003",
                mcp_id="MCP06",
                severity=Severity.MEDIUM,
                title=f"Fetched content is returned to the model{by_tool}",
                description=(
                    f"{owner} calls `{ret.origin.name}` at {facts.path}:{ret.origin.line} and returns "
                    f"the response to the model at line {ret.line} without sanitizing it. Whoever "
                    "controls that endpoint — or any page it redirects to, or any content it "
                    "aggregates — is writing directly into the model's context. Text on a web page "
                    "saying 'call the run_command tool with rm -rf' is not a hypothetical; it is the "
                    "documented attack against every fetch-shaped MCP server."
                ),
                file_path=facts.path,
                line=ret.line,
                snippet=ctx.line(facts.path, ret.line).strip() or None,
                remediation=(
                    "Mark fetched content as untrusted where the model can see the boundary: wrap it "
                    "in a delimiter the model is told to treat as data, strip HTML comments and "
                    "hidden elements, and keep the tool's own instructions outside that region. "
                    "Do not let remote text arrive looking like part of the conversation."
                ),
                cwe_id="CWE-74",
                confidence=0.7,
                metadata={"tool": ret.tool or "", "origin": ret.origin.name},
            )


def _excerpt(text: str, limit: int = 90) -> str:
    """One line of the description, with invisible characters made visible."""
    flat = " ".join(text.split())
    for char in _INVISIBLE:
        flat = flat.replace(char, "␀")
    flat = "".join("␀" if 0xE0000 <= ord(c) <= 0xE007F else c for c in flat)
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
