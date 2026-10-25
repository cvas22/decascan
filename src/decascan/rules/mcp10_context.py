"""MCP10 — Context Injection & Over-Sharing.

Everything an MCP server returns is copied into the model's context window, and from there into the
provider's logs, the client's transcript, and whatever the conversation gets pasted into next. A
value that reaches the model has, for practical purposes, left the building.

So the question here is not "can this data be read" — the server has the privileges to read it
either way — but "is this data being handed to a language model, and did anyone mean for that to
happen?" Three answers that are always no:

  1. The environment, returned wholesale. It is where the credentials live.
  2. A path into the user's private keys, cloud credentials, or shell history.
  3. A filesystem root so broad the tool's real scope is "everything the user owns".
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import ENV, FS_READ, FS_WRITE
from .base import rule


@rule(
    id="MCP10-001",
    mcp_id="MCP10",
    name="Environment returned to the model",
    description="A tool hands environment variables back to the model, where the secrets live.",
)
def environment_to_model(ctx: ScanContext) -> Iterable[Finding]:
    for facts in ctx.source_facts.values():
        for ret in facts.external_returns:
            if ret.origin.capability != ENV:
                continue

            owner = f"`{ret.tool}`" if ret.tool else "A tool"
            by_tool = f" by `{ret.tool}`" if ret.tool else ""
            yield Finding(
                rule_id="MCP10-001",
                mcp_id="MCP10",
                severity=Severity.HIGH,
                title=f"Environment variables are returned to the model{by_tool}",
                description=(
                    f"{owner} reads `{ret.origin.name}` at {facts.path}:{ret.origin.line} and returns "
                    f"it to the model at line {ret.line}. The environment of an MCP server is where "
                    "its API keys, database URLs, and cloud credentials live — that is the whole "
                    "reason they are in the environment rather than in the source. Returning it "
                    "copies every one of them into the model's context, the provider's request logs, "
                    "and the client's saved transcript. They are not recoverable from any of those."
                ),
                file_path=facts.path,
                line=ret.line,
                snippet=ctx.line(facts.path, ret.line).strip() or None,
                remediation=(
                    "Return only the specific variables the tool needs the model to see, by name, "
                    "and rotate anything that has already been through a context window. If the tool "
                    "exists to report configuration, return a hardcoded allowlist of non-secret keys "
                    "— never the mapping itself."
                ),
                cwe_id="CWE-200",
                confidence=0.9,
                metadata={"tool": ret.tool or ""},
            )


@rule(
    id="MCP10-002",
    mcp_id="MCP10",
    name="Credential file within reach of a tool",
    description="Code touches a path holding private keys, cloud credentials, or system accounts.",
)
def credential_path_access(ctx: ScanContext) -> Iterable[Finding]:
    for facts in ctx.source_facts.values():
        for call in facts.calls:
            if call.capability not in (FS_READ, FS_WRITE):
                continue
            markers = call.touches_sensitive_path
            if not markers:
                continue

            tool = next((t.name for t in facts.tools if t.spans(call.line)), None)
            owner = f"`{tool}`" if tool else "This server"
            yield Finding(
                rule_id="MCP10-002",
                mcp_id="MCP10",
                severity=Severity.HIGH,
                title=f"`{markers[0]}` is accessed at {facts.path}:{call.line}",
                description=(
                    f"{owner} calls `{call.name}` on a path containing `{markers[0]}`. That file "
                    "holds credentials for systems well outside this server's remit — an SSH private "
                    "key, a cloud credential, a system account list. Whatever the server does with "
                    "the contents, they are one tool response away from a model's context window, "
                    "and MCP servers do not get to assume their output stays local."
                ),
                file_path=facts.path,
                line=call.line,
                snippet=call.raw or None,
                remediation=(
                    "Remove the access. A server that needs to authenticate to something should hold "
                    "its own scoped credential in its own environment, not read the user's. If this "
                    "server is third-party and reads private keys, that is not a bug to file — do "
                    "not run it."
                ),
                cwe_id="CWE-538",
                confidence=0.85,
                metadata={"marker": markers[0], "tool": tool or ""},
            )


@rule(
    id="MCP10-003",
    mcp_id="MCP10",
    name="Tool operates on a filesystem root",
    description="A file operation is rooted at `/`, a home directory, or a drive root.",
)
def broad_filesystem_root(ctx: ScanContext) -> Iterable[Finding]:
    for facts in ctx.source_facts.values():
        for call in facts.calls:
            if call.capability not in (FS_READ, FS_WRITE):
                continue
            roots = call.touches_broad_root
            if not roots:
                continue

            tool = next((t.name for t in facts.tools if t.spans(call.line)), None)
            owner = f"`{tool}`" if tool else "This server"
            yield Finding(
                rule_id="MCP10-003",
                mcp_id="MCP10",
                severity=Severity.MEDIUM,
                title=f"File access rooted at `{roots[0]}`",
                description=(
                    f"{owner} calls `{call.name}` with `{roots[0]}` as its root. Whatever the tool's "
                    "description says it does, its actual scope is every file the user can reach — "
                    "their keys, their other repositories, their browser profile. The model decides "
                    "what to pull out of that, and the model is steerable by anything in its context."
                ),
                file_path=facts.path,
                line=call.line,
                snippet=call.raw or None,
                remediation=(
                    "Root the tool at the narrowest directory that lets it do its job, take that root "
                    "from configuration rather than the model, and confine every resolved path to it "
                    "(`resolved.is_relative_to(root)`). A tool that must see the whole filesystem "
                    "should say so in its description, so a client can decline it."
                ),
                cwe_id="CWE-668",
                confidence=0.7,
                metadata={"root": roots[0], "tool": tool or ""},
            )
