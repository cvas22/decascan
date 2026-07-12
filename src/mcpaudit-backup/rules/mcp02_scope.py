"""MCP02 — Privilege Escalation via Scope Creep.

The check: take the scopes a server (or tool) *declares* in its manifest, take the capabilities its
code actually exercises, and diff them. A tool that declares `read:files` but calls `fs.writeFile`
is a scope violation whether or not it is malicious — the client granted it on false pretenses.

Deliberately quiet: if a manifest declares no scopes at all there is nothing to diff, so this rule
emits a single INFO rather than guessing at intent.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import (
    CAPABILITY_LABELS,
    CAPABILITY_SCOPES,
    ENV,
    EXEC,
    FS_WRITE,
)
from .base import rule

# How bad it is to exceed a declared scope depends on what you exceeded it *with*.
_CAPABILITY_SEVERITY = {
    EXEC: Severity.CRITICAL,
    FS_WRITE: Severity.HIGH,
    ENV: Severity.MEDIUM,
}
_DEFAULT_SEVERITY = Severity.HIGH


def _granted_capabilities(scopes: Iterable[str]) -> set[str]:
    normalized = {s.strip().lower() for s in scopes}
    granted: set[str] = set()

    for capability, aliases in CAPABILITY_SCOPES.items():
        if normalized & aliases:
            granted.add(capability)
    # A wildcard scope grants everything; treat it as such rather than reporting ten violations.
    if normalized & {"*", "all", "admin", "full"}:
        granted.update(CAPABILITY_SCOPES)
    return granted


@rule(
    id="MCP02-001",
    mcp_id="MCP02",
    name="Capability exceeds declared scope",
    description="Code exercises a capability the manifest never declared a scope for.",
)
def capability_exceeds_scope(ctx: ScanContext) -> Iterable[Finding]:
    manifests = [m for m in ctx.manifests if m.declares_scopes]
    if not manifests:
        return

    for manifest in manifests:
        server_granted = _granted_capabilities(manifest.scopes)

        for path, facts in ctx.source_facts.items():
            for call in facts.calls:
                if not call.capability:
                    continue

                owning_tool = next((t for t in facts.tools if t.spans(call.line)), None)
                granted = set(server_granted)
                scope_source = f"server scopes {sorted(manifest.scopes)}"

                if owning_tool and owning_tool.name in manifest.tool_scopes:
                    tool_scopes = manifest.tool_scopes[owning_tool.name]
                    granted |= _granted_capabilities(tool_scopes)
                    scope_source = f"`{owning_tool.name}` scopes {sorted(tool_scopes)}"

                if call.capability in granted:
                    continue

                label = CAPABILITY_LABELS.get(call.capability, call.capability)
                where = f"Tool `{owning_tool.name}`" if owning_tool else f"`{path}`"
                yield Finding(
                    rule_id="MCP02-001",
                    mcp_id="MCP02",
                    severity=_CAPABILITY_SEVERITY.get(call.capability, _DEFAULT_SEVERITY),
                    title=(
                        f"{where} can {label}, which "
                        f"`{manifest.path}` does not grant"
                    ),
                    description=(
                        f"`{call.name}` at {path}:{call.line} exercises the "
                        f"`{call.capability}` capability, but the declared {scope_source} do not "
                        "cover it. The client authorized this server on the strength of those "
                        "scopes; the implementation quietly exceeds them."
                    ),
                    file_path=path,
                    line=call.line,
                    snippet=call.raw or None,
                    remediation=(
                        f"Either drop the `{call.capability}` operation, or declare the matching "
                        f"scope in `{manifest.path}` so the grant is honest — and expect clients to "
                        "review it."
                    ),
                    cwe_id="CWE-269",
                    confidence=0.85,
                    metadata={"capability": call.capability, "callee": call.name},
                )


@rule(
    id="MCP02-002",
    mcp_id="MCP02",
    name="No scopes declared",
    description="A manifest exposes tools without declaring any authorization scopes.",
)
def no_scopes_declared(ctx: ScanContext) -> Iterable[Finding]:
    for manifest in ctx.manifests:
        if manifest.declares_scopes or not manifest.tools:
            continue
        capabilities = {c for facts in ctx.source_facts.values() for c in facts.capabilities}
        if not capabilities:
            continue
        listed = ", ".join(sorted(CAPABILITY_LABELS[c] for c in capabilities if c in CAPABILITY_LABELS))
        yield Finding(
            rule_id="MCP02-002",
            mcp_id="MCP02",
            severity=Severity.INFO,
            title=f"`{manifest.path}` declares tools but no scopes",
            description=(
                f"The server's code can {listed}, but the manifest declares no scopes, so a client "
                "has no way to reason about what it is granting — and mcpaudit has nothing to diff "
                "the implementation against."
            ),
            file_path=manifest.path,
            line=1,
            snippet=None,
            remediation=(
                "Add a `scopes` list to the manifest naming only the capabilities the server "
                "actually needs (e.g. `[\"read:files\"]`). MCP02-001 will then verify the code "
                "stays inside them."
            ),
            cwe_id="CWE-1220",
            confidence=1.0,
        )
