"""MCP03 — Tool Poisoning.

A tool is poisonable when the model can put arbitrary content into it. Three signals, ordered by
how much they actually mean:

  1. A free-form string parameter with a dangerous name (`command`, `path`, `query`) landing in a
     handler that shells out or evaluates code. This is the real finding.
  2. An open input schema (`additionalProperties` unset/true) — the model can smuggle fields the
     author never validated.
  3. A tool with no input schema at all.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import EXEC, Call, ToolDef
from .base import rule


def _dangerous_sinks(ctx: ScanContext, tool: ToolDef) -> list[Call]:
    """Exec/eval calls reachable from this tool's handler.

    Falls back to the generic `call_tool` dispatcher when a tool has no handler span of its own,
    since low-level SDK servers implement every tool inside one function.
    """
    facts = ctx.facts_for(tool.file)
    if not facts:
        return []
    scoped = [c for c in facts.calls_in_tool(tool) if c.capability == EXEC]
    if scoped:
        return scoped
    if tool.handler_start is None:
        return [c for c in facts.calls_in_dispatch() if c.capability == EXEC]
    return []


@rule(
    id="MCP03-001",
    mcp_id="MCP03",
    name="Unconstrained input reaches a dangerous sink",
    description="A free-form tool parameter flows into a handler that executes code or shells out.",
)
def unconstrained_input_to_sink(ctx: ScanContext) -> Iterable[Finding]:
    for tool in ctx.all_tools:
        if tool.origin == "manifest":
            continue  # manifest tools have no handler to inspect
        sinks = _dangerous_sinks(ctx, tool)
        if not sinks:
            continue

        shell = any(s.shell for s in sinks)
        evaluated = any(s.dynamic_eval for s in sinks)

        free_form = [p for p in tool.params if p.is_free_form_string]
        risky = [p for p in free_form if p.is_risky_name]

        # A shell or an evaluator turns *any* unconstrained string into an injection primitive --
        # `grep {pattern}` is as exploitable as `{command}`. The parameter's name only tells us how
        # confident to be, so it must not gate the finding. Argv-style exec (no shell) is far less
        # forgiving of a stray value, so there the name still carries the signal.
        interesting = free_form if (shell or evaluated) else risky
        if not interesting:
            continue

        sink = sinks[0]
        names = ", ".join(f"`{p.name}`" for p in interesting)

        yield Finding(
            rule_id="MCP03-001",
            mcp_id="MCP03",
            severity=Severity.CRITICAL if (shell or evaluated) else Severity.HIGH,
            title=f"Tool `{tool.name}` accepts unvalidated {names} and executes it",
            description=(
                f"`{tool.name}` declares {names} as an unconstrained string — no `enum`, no "
                f"`pattern`, no allowlist — and its handler calls `{sink.name}` at "
                f"{tool.file}:{sink.line}"
                + (" with `shell=True`" if shell else "")
                + ". Anything that can influence the model's tool call (a poisoned document, a web "
                "page, a hostile file in the workspace) can choose what gets executed."
            ),
            file_path=tool.file,
            line=sink.line,
            snippet=sink.raw or None,
            remediation=(
                f"Constrain {names} to an allowlist (`enum`, or a strict `pattern`) and pass "
                "arguments as a list rather than a shell string. If the tool genuinely needs to run "
                "arbitrary commands, that is a design decision the client must be able to see — say "
                "so in the tool description and require explicit approval."
            ),
            cwe_id="CWE-78" if shell else "CWE-94",
            confidence=0.9 if risky else 0.75,
            metadata={"tool": tool.name, "sink": sink.name},
        )


@rule(
    id="MCP03-002",
    mcp_id="MCP03",
    name="Open tool input schema",
    description="A tool's input schema permits additional, unvalidated properties.",
)
def open_input_schema(ctx: ScanContext) -> Iterable[Finding]:
    for tool in ctx.all_tools:
        if not tool.has_schema or not tool.additional_properties_open:
            continue
        yield Finding(
            rule_id="MCP03-002",
            mcp_id="MCP03",
            severity=Severity.MEDIUM,
            title=f"Tool `{tool.name}` accepts additional properties",
            description=(
                f"`{tool.name}`'s input schema does not set `additionalProperties: false`, so a "
                "caller can attach fields the handler never validates. Where those fields reach a "
                "dict/object that is later splatted into an API call or a subprocess, they become "
                "an injection point."
            ),
            file_path=tool.file,
            line=tool.line,
            snippet=ctx.line(tool.file, tool.line).strip() or None,
            remediation=(
                'Set `"additionalProperties": false` on the tool\'s input schema and list every '
                "field you accept in `required`."
            ),
            cwe_id="CWE-20",
            confidence=0.8,
            metadata={"tool": tool.name},
        )


@rule(
    id="MCP03-003",
    mcp_id="MCP03",
    name="Risky parameter without validation",
    description="A tool parameter with a dangerous name has no enum, pattern, or format constraint.",
)
def unvalidated_risky_parameter(ctx: ScanContext) -> Iterable[Finding]:
    for tool in ctx.all_tools:
        sinks = _dangerous_sinks(ctx, tool) if tool.origin != "manifest" else []
        if sinks:
            continue  # already reported, with more force, by MCP03-001

        for param in tool.params:
            if not (param.is_free_form_string and param.is_risky_name):
                continue
            yield Finding(
                rule_id="MCP03-003",
                mcp_id="MCP03",
                severity=Severity.MEDIUM,
                title=f"Tool `{tool.name}` takes `{param.name}` as an unconstrained string",
                description=(
                    f"`{param.name}` is declared as a plain string with no `enum`, `pattern`, or "
                    "`maxLength`. Parameters with this name usually end up in a path, a query, or a "
                    "URL, where an unvalidated value is a traversal or injection primitive."
                ),
                file_path=tool.file,
                line=param.line or tool.line,
                snippet=ctx.line(tool.file, param.line or tool.line).strip() or None,
                remediation=(
                    f"Constrain `{param.name}`: an `enum` if the set is known, a `pattern` if the "
                    "shape is known, and a `maxLength` regardless. Validate against a rooted "
                    "allowlist before use."
                ),
                cwe_id="CWE-20",
                confidence=0.65,
                metadata={"tool": tool.name, "param": param.name},
            )


@rule(
    id="MCP03-004",
    mcp_id="MCP03",
    name="Tool declared without an input schema",
    description="A tool exposes parameters to the model with no schema at all.",
)
def missing_input_schema(ctx: ScanContext) -> Iterable[Finding]:
    for tool in ctx.manifest_tools:
        if tool.has_schema:
            continue
        yield Finding(
            rule_id="MCP03-004",
            mcp_id="MCP03",
            severity=Severity.MEDIUM,
            title=f"Tool `{tool.name}` is declared with no input schema",
            description=(
                f"`{tool.name}` appears in `{tool.file}` without an `inputSchema`. The model is free "
                "to send any shape it likes, and the server has told no one what it expects."
            ),
            file_path=tool.file,
            line=tool.line,
            snippet=None,
            remediation=(
                "Declare an `inputSchema` with explicit `properties`, `required`, and "
                '`"additionalProperties": false`.'
            ),
            cwe_id="CWE-20",
            confidence=0.9,
            metadata={"tool": tool.name},
        )
