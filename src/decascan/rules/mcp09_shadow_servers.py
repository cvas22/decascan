"""MCP09 — Shadow MCP Servers.

A shadow server is an MCP server the operator doesn't know is there: a second `Server(...)` in a
debug module, a listener on a port the manifest never mentions, a server file nobody's manifest
points at. Each one is an unreviewed, usually unauthenticated door into the same process privileges.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from .base import rule


def _primary_server(ctx: ScanContext, servers: list):
    """The server the operator actually configured — everything else is a shadow.

    Identified by name match against a manifest, then by manifest entrypoint. File order is the last
    resort and only a tiebreak; it must never be the thing that decides which server is legitimate.
    """
    manifest_names = {
        m.raw.get("name") for m in ctx.manifests if isinstance(m.raw.get("name"), str)
    }
    entrypoints = {s.entrypoint for m in ctx.manifests for s in m.servers if s.entrypoint}

    for server in servers:
        if server.name and server.name in manifest_names:
            return server
    for server in servers:
        if any(server.file.endswith(entry) for entry in entrypoints):
            return server
    return servers[0]


@rule(
    id="MCP09-001",
    mcp_id="MCP09",
    name="Multiple server instantiations",
    description="More than one MCP server is constructed in this codebase.",
)
def multiple_servers(ctx: ScanContext) -> Iterable[Finding]:
    servers = ctx.code_servers
    if len(servers) < 2:
        return

    primary = _primary_server(ctx, servers)
    locations = ", ".join(f"{s.file}:{s.line}" for s in servers)
    for server in servers:
        if server is primary:
            continue
        yield Finding(
            rule_id="MCP09-001",
            mcp_id="MCP09",
            severity=Severity.HIGH,
            title=f"Additional MCP server (`{server.kind}`) constructed at {server.file}:{server.line}",
            description=(
                f"This codebase constructs {len(servers)} MCP servers ({locations}). Only one is "
                "normally the server an operator has reviewed and configured; the others are "
                "reachable code paths that expose tools under the same privileges, typically "
                "without the auth, logging, or scope review the primary server got."
            ),
            file_path=server.file,
            line=server.line,
            snippet=ctx.line(server.file, server.line).strip() or None,
            remediation=(
                "Delete the extra server, or — if it is a deliberate second surface (a debug or "
                "admin endpoint) — declare it in the manifest and give it the same authentication "
                "and scope constraints as the primary one."
            ),
            cwe_id="CWE-1059",
            confidence=0.75,
            metadata={"kind": server.kind},
        )


@rule(
    id="MCP09-002",
    mcp_id="MCP09",
    name="Undeclared listening port",
    description="Code binds a port that no manifest declares.",
)
def undeclared_port(ctx: ScanContext) -> Iterable[Finding]:
    declared = {port for manifest in ctx.manifests for port in manifest.declared_ports}
    if not ctx.manifests:
        return

    for path, facts in ctx.source_facts.items():
        for line, port in facts.ports:
            if port in declared:
                continue
            yield Finding(
                rule_id="MCP09-002",
                mcp_id="MCP09",
                severity=Severity.HIGH,
                title=f"Port {port} is bound in code but declared in no manifest",
                description=(
                    f"`{path}` listens on port {port}, which appears in none of the "
                    f"{len(ctx.manifests)} manifest(s) scanned "
                    + (f"(declared: {sorted(declared)})" if declared else "(none declare a port)")
                    + ". An operator reading the manifest has no idea this listener exists, so it "
                    "will not be firewalled, monitored, or reviewed."
                ),
                file_path=path,
                line=line,
                snippet=ctx.line(path, line).strip() or None,
                remediation=(
                    f"Declare port {port} in the manifest, or remove the listener. If it is a "
                    "development-only endpoint, gate it behind an explicit environment flag that is "
                    "off by default."
                ),
                cwe_id="CWE-1059",
                confidence=0.7,
                metadata={"port": str(port)},
            )
