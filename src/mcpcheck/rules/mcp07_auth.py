"""MCP07 — Insufficient Authentication & Authorization.

The single most important thing this rule does is *not* fire on stdio servers. A stdio server is
spawned as a subprocess by its client and speaks over pipes — it has no socket, and demanding an
auth block there would make the tool unusable noise. Network-exposed servers (an HTTP/SSE transport,
or a bound port) are a different story: with no auth, anything that can reach the port can drive
every tool the server exposes.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.manifest import Manifest
from .base import rule

_WILDCARD_ORIGINS = {"*", "null"}

# CORS middleware configured to allow any origin, in either ecosystem.
_CORS_WILDCARD_CODE = re.compile(
    r"(?:allow_origins|allowOrigins?|origin)\s*[:=]\s*[\[\(]?\s*[\"'`]\*[\"'`]"
)
_ACAO_WILDCARD = re.compile(r"[\"']Access-Control-Allow-Origin[\"']\s*[:,]\s*[\"']\*[\"']")


def _network_evidence(ctx: ScanContext, manifest: Manifest) -> str | None:
    if manifest.declared_ports:
        return f"it declares port {sorted(manifest.declared_ports)[0]}"
    if manifest.transports:
        transport = sorted(manifest.transports)[0]
        if transport not in {"stdio", "pipe"}:
            return f"its transport is `{transport}`"
    ports = [(path, line, port) for path, facts in ctx.source_facts.items() for line, port in facts.ports]
    if ports:
        path, line, port = ports[0]
        return f"it binds port {port} at {path}:{line}"
    return None


@rule(
    id="MCP07-001",
    mcp_id="MCP07",
    name="Network-exposed server without authentication",
    description="An HTTP/SSE MCP server declares no authentication.",
)
def missing_authentication(ctx: ScanContext) -> Iterable[Finding]:
    for manifest in ctx.manifests:
        evidence = _network_evidence(ctx, manifest)
        if not evidence:
            continue  # stdio: the client owns the process, no socket to protect
        if not manifest.auth_is_absent:
            continue

        explicit = manifest.declares_auth_key  # e.g. "auth": null — someone turned it off
        yield Finding(
            rule_id="MCP07-001",
            mcp_id="MCP07",
            severity=Severity.CRITICAL,
            title=f"`{manifest.path}` exposes a network server with no authentication",
            description=(
                f"This server is reachable over the network ({evidence}) and "
                + (
                    "its `auth` key is explicitly empty."
                    if explicit
                    else "the manifest declares no authentication at all."
                )
                + " Any process that can reach the port — another container, a colleague on the "
                "VPN, a browser page via DNS rebinding — can call every tool it exposes, with the "
                "server's own filesystem and network privileges."
            ),
            file_path=manifest.path,
            line=1,
            snippet=None,
            remediation=(
                "Require a bearer token or mTLS on the transport, bind to `127.0.0.1` rather than "
                "`0.0.0.0` if the server is only for local clients, and validate the token on every "
                "request — not just at connection setup."
            ),
            cwe_id="CWE-306",
            confidence=0.9,
            metadata={"transport": ",".join(sorted(manifest.transports)) or "unknown"},
        )


@rule(
    id="MCP07-002",
    mcp_id="MCP07",
    name="Wildcard CORS origin",
    description="The server accepts cross-origin requests from any website.",
)
def wildcard_cors(ctx: ScanContext) -> Iterable[Finding]:
    for manifest in ctx.manifests:
        if not set(manifest.cors_origins) & _WILDCARD_ORIGINS:
            continue
        yield Finding(
            rule_id="MCP07-002",
            mcp_id="MCP07",
            severity=Severity.HIGH,
            title=f"`{manifest.path}` allows requests from any origin",
            description=(
                "CORS is configured with a wildcard origin, so any web page the user visits can "
                "issue requests to this MCP server from their browser and read the responses."
            ),
            file_path=manifest.path,
            line=1,
            snippet=None,
            remediation=(
                "Replace the wildcard with an explicit allowlist of origins that need access. For a "
                "local-only server, the correct answer is usually no CORS at all."
            ),
            cwe_id="CWE-942",
            confidence=0.95,
        )

    for path in ctx.files:
        if not path.endswith((".py", ".ts", ".js", ".mjs", ".tsx", ".jsx")):
            continue
        for line_no, line in enumerate(ctx.text(path).splitlines(), start=1):
            if not (_CORS_WILDCARD_CODE.search(line) or _ACAO_WILDCARD.search(line)):
                continue
            yield Finding(
                rule_id="MCP07-002",
                mcp_id="MCP07",
                severity=Severity.HIGH,
                title="CORS configured to allow any origin",
                description=(
                    f"`{path}` sets a wildcard CORS origin. Combined with a network transport, this "
                    "lets any website the user has open reach the MCP server from the browser."
                ),
                file_path=path,
                line=line_no,
                snippet=line.strip(),
                remediation="Allowlist the specific origins that need access; drop the wildcard.",
                cwe_id="CWE-942",
                confidence=0.85,
            )
