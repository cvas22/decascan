"""Discover and normalize MCP server manifests/configs.

There is no single manifest format in the wild — servers ship `.mcp.json`, `mcp.json`,
`server.json`, Claude-Desktop-style `mcpServers` maps, or a YAML equivalent. This module flattens
all of them into one Manifest shape so rules don't have to know the difference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .common import ToolDef
from .python_source import params_from_json_schema

MANIFEST_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "mcp-config.json",
    "server.json",
    "server_config.json",
    "mcp-server.json",
    "manifest.json",
    "claude_desktop_config.json",
    "mcp.yaml",
    "mcp.yml",
    ".mcp.yaml",
    ".mcp.yml",
}

# Keys that carry an authorization scope list. Deliberately excludes "capabilities", which in the
# MCP spec means protocol features (tools/resources/prompts), not permissions.
_SCOPE_KEYS = ("scopes", "permissions", "requiredScopes", "required_scopes", "grants")
_AUTH_KEYS = ("auth", "authentication", "authorization", "security")
_CORS_KEYS = ("cors", "corsOptions", "cors_options")
_ORIGIN_KEYS = (
    "allowOrigin",
    "allow_origin",
    "allowOrigins",
    "allow_origins",
    "allowedOrigins",
    "origins",
    "access_control_allow_origin",
)


@dataclass
class DeclaredServer:
    name: str
    port: int | None = None
    transport: str | None = None
    command: str | None = None
    entrypoint: str | None = None


@dataclass
class Manifest:
    path: str
    raw: dict[str, Any]
    servers: list[DeclaredServer] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    tool_scopes: dict[str, list[str]] = field(default_factory=dict)
    tools: list[ToolDef] = field(default_factory=list)
    auth: Any = None
    declares_auth_key: bool = False
    cors_origins: list[str] = field(default_factory=list)

    @property
    def declares_scopes(self) -> bool:
        return bool(self.scopes or self.tool_scopes)

    @property
    def declared_ports(self) -> set[int]:
        return {s.port for s in self.servers if s.port is not None}

    @property
    def transports(self) -> set[str]:
        return {s.transport for s in self.servers if s.transport}

    @property
    def is_network_exposed(self) -> bool:
        """stdio servers are spawned by the client and aren't listening on a socket; HTTP/SSE are.

        This distinction is what keeps MCP07 from firing on every local stdio server.
        """
        if self.declared_ports:
            return True
        network = {"http", "https", "sse", "streamable-http", "streamable_http", "websocket", "ws"}
        return bool(self.transports & network)

    @property
    def auth_is_absent(self) -> bool:
        return self.auth in (None, False, "none", "None", {}, [])


def _first(data: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _line_of_tool(text: str, name: str) -> int:
    """Where a tool is declared in the manifest, so findings don't all point at line 1."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        if f'"{name}"' in line or f"'{name}'" in line or f"{name}:" in line:
            return line_no
    return 1


def _tools_from(data: dict, path: str, text: str = "") -> tuple[list[ToolDef], dict[str, list[str]]]:
    tools: list[ToolDef] = []
    tool_scopes: dict[str, list[str]] = {}
    raw_tools = data.get("tools")

    entries: list[dict] = []
    if isinstance(raw_tools, list):
        entries = [t for t in raw_tools if isinstance(t, dict)]
    elif isinstance(raw_tools, dict):
        for name, spec in raw_tools.items():
            if isinstance(spec, dict):
                entries.append({**spec, "name": spec.get("name", name)})

    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        schema = entry.get("inputSchema") or entry.get("input_schema") or entry.get("parameters")
        line = _line_of_tool(text, name) if text else 1
        tool = ToolDef(name=name, file=path, line=line, origin="manifest")
        if isinstance(schema, dict):
            tool.schema = schema
            tool.has_schema = True
            tool.params = params_from_json_schema(schema, line)
            tool.additional_properties_open = schema.get("additionalProperties", True) is not False
        tools.append(tool)

        scopes = _as_str_list(_first(entry, _SCOPE_KEYS))
        if scopes:
            tool_scopes[name] = scopes

    return tools, tool_scopes


def _servers_from(data: dict) -> list[DeclaredServer]:
    servers: list[DeclaredServer] = []
    nested = data.get("mcpServers") or data.get("servers")

    if isinstance(nested, dict):
        for name, spec in nested.items():
            spec = spec if isinstance(spec, dict) else {}
            servers.append(_declared_server(name, spec))
        return servers
    if isinstance(nested, list):
        for spec in nested:
            if isinstance(spec, dict):
                servers.append(_declared_server(str(spec.get("name", "server")), spec))
        return servers

    return [_declared_server(str(data.get("name", "server")), data)]


def _declared_server(name: str, spec: dict) -> DeclaredServer:
    port = spec.get("port")
    transport = spec.get("transport") or spec.get("transportType") or spec.get("type")
    if not transport and spec.get("command"):
        transport = "stdio"
    if not transport and (spec.get("url") or port):
        transport = "http"
    return DeclaredServer(
        name=name,
        port=port if isinstance(port, int) else None,
        transport=str(transport).lower() if isinstance(transport, str) else None,
        command=spec.get("command") if isinstance(spec.get("command"), str) else None,
        entrypoint=_entrypoint(spec),
    )


def _entrypoint(spec: dict) -> str | None:
    args = spec.get("args")
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, str) and arg.endswith((".py", ".js", ".ts", ".mjs")):
                return arg
    main = spec.get("main") or spec.get("entrypoint")
    return main if isinstance(main, str) else None


def _cors_origins(data: dict) -> list[str]:
    origins = _as_str_list(_first(data, _ORIGIN_KEYS))
    cors = _first(data, _CORS_KEYS)
    if isinstance(cors, dict):
        origins += _as_str_list(_first(cors, _ORIGIN_KEYS))
    return origins


def load_manifest(path: Path, root: Path) -> Manifest | None:
    try:
        text = path.read_text(encoding="utf-8")
        data = (
            yaml.safe_load(text)
            if path.suffix in {".yaml", ".yml"}
            else json.loads(text)
        )
    except (OSError, ValueError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None

    rel = (path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path))
    tools, tool_scopes = _tools_from(data, rel, text)
    servers = _servers_from(data)

    # A per-server auth block counts as declared auth for the manifest as a whole.
    auth = _first(data, _AUTH_KEYS)
    declares_auth_key = any(key in data for key in _AUTH_KEYS)
    for spec in _nested_specs(data):
        if any(key in spec for key in _AUTH_KEYS):
            declares_auth_key = True
            auth = auth or _first(spec, _AUTH_KEYS)

    return Manifest(
        path=rel,
        raw=data,
        servers=servers,
        scopes=_as_str_list(_first(data, _SCOPE_KEYS)),
        tool_scopes=tool_scopes,
        tools=tools,
        auth=auth,
        declares_auth_key=declares_auth_key,
        cors_origins=_cors_origins(data),
    )


def _nested_specs(data: dict) -> list[dict]:
    nested = data.get("mcpServers") or data.get("servers")
    if isinstance(nested, dict):
        return [s for s in nested.values() if isinstance(s, dict)]
    if isinstance(nested, list):
        return [s for s in nested if isinstance(s, dict)]
    return []


def is_manifest_name(name: str) -> bool:
    return name in MANIFEST_NAMES
