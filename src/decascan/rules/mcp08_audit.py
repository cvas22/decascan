"""MCP08 — Lack of Audit & Telemetry.

Every other risk in this list is about preventing something. This one is about what happens after
prevention fails. An MCP server runs commands and writes files on a developer's machine at the
direction of a model that anything in its context can influence. When that goes wrong — and the
first nine risks are a list of ways it goes wrong — the only question that matters is: what did it
do, and can anyone reconstruct it?

A server that shells out and logs nothing cannot answer that. Neither can one that catches the
exception and moves on.

Scoped deliberately to the capabilities that *change something*: execution and filesystem writes.
A read-only server that doesn't log is untidy, not a security finding, and a rule that says
otherwise would fire on half the honest servers in the ecosystem.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import CAPABILITY_LABELS, EXEC, FS_WRITE, Call, SourceFacts
from .base import rule

_CONSEQUENTIAL = (EXEC, FS_WRITE)


def _consequential_calls(facts: SourceFacts) -> list[Call]:
    return [c for c in facts.calls if c.capability in _CONSEQUENTIAL]


@rule(
    id="MCP08-001",
    mcp_id="MCP08",
    name="Consequential actions are never logged",
    description="The server executes commands or writes files and calls no logging framework at all.",
)
def no_audit_trail(ctx: ScanContext) -> Iterable[Finding]:
    if not ctx.is_mcp_server:
        return  # a library that writes files is not a server with no audit trail
    if any(facts.log_calls for facts in ctx.source_facts.values()):
        return  # the server logs somewhere; whether it logs *enough* is not statically decidable

    acting = [
        (facts, call)
        for facts in ctx.source_facts.values()
        for call in _consequential_calls(facts)
    ]
    if not acting:
        return

    facts, first = acting[0]
    capabilities = sorted({CAPABILITY_LABELS[c.capability] for _, c in acting if c.capability})

    yield Finding(
        rule_id="MCP08-001",
        mcp_id="MCP08",
        severity=Severity.MEDIUM,
        title="The server can execute commands or write files, and logs nothing",
        description=(
            f"This server can {' and '.join(capabilities)} — {len(acting)} such call(s), the first at "
            f"{facts.path}:{first.line} — and there is no call to any logging framework anywhere in "
            "it. If a poisoned tool call gets through, there is no record of which tool ran, with "
            "what arguments, on whose behalf. The incident response for this server is reading the "
            "shell history of the developer who installed it and hoping."
        ),
        file_path=facts.path,
        line=first.line,
        snippet=first.raw or None,
        remediation=(
            "Log every tool invocation at the dispatch boundary — tool name, arguments, caller, "
            "outcome — before the handler runs, and log the result after. Send it somewhere the "
            "server itself cannot rewrite. Redact the arguments that carry secrets; the point is a "
            "reconstructable timeline, not a transcript."
        ),
        cwe_id="CWE-778",
        confidence=0.8,
        metadata={"calls": str(len(acting))},
    )


@rule(
    id="MCP08-002",
    mcp_id="MCP08",
    name="Exception swallowed silently",
    description="An error is caught and discarded in a file that executes commands or writes files.",
)
def swallowed_exception(ctx: ScanContext) -> Iterable[Finding]:
    if not ctx.is_mcp_server:
        return
    for facts in ctx.source_facts.values():
        if not _consequential_calls(facts):
            continue  # a discarded error in read-only code is a style problem, not a security one

        for line, exception in facts.swallowed_excepts:
            yield Finding(
                rule_id="MCP08-002",
                mcp_id="MCP08",
                severity=Severity.LOW,
                title=f"`{exception}` is caught and discarded",
                description=(
                    f"{facts.path}:{line} catches {exception} and does nothing with it, in a file "
                    "that executes commands or writes files. A failed command and a command that was "
                    "never attempted now look identical from the outside — and so does a command "
                    "that was blocked by a permission check versus one that ran and failed. That is "
                    "precisely the distinction an investigation needs."
                ),
                file_path=facts.path,
                line=line,
                snippet=ctx.line(facts.path, line).strip() or None,
                remediation=(
                    "Log the exception before continuing, or let it propagate so the caller sees the "
                    "failure. If it is genuinely expected and benign, catch the specific exception "
                    "and say in a comment why discarding it is safe."
                ),
                cwe_id="CWE-390",
                confidence=0.7,
                metadata={"exception": exception},
            )
