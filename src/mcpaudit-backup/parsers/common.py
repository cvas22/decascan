"""Shared vocabulary for what the language parsers extract from an MCP server's source.

Every parser (Python AST, TS/JS) normalizes into these structures, so rules never care which
language a server is written in.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Capabilities a tool implementation can exercise. Rules compare these against the scopes a
# server *declares* in its manifest (MCP02).
FS_READ = "fs:read"
FS_WRITE = "fs:write"
NET = "net"
EXEC = "exec"
ENV = "env"

CAPABILITIES = (FS_READ, FS_WRITE, NET, EXEC, ENV)

CAPABILITY_LABELS = {
    FS_READ: "read files",
    FS_WRITE: "write/delete files",
    NET: "make outbound network calls",
    EXEC: "execute shell commands or evaluate code",
    ENV: "read environment variables",
}

# Scope strings (as they appear in manifests) that grant each capability. Matching is
# case-insensitive and tolerant of the several spellings in the wild.
CAPABILITY_SCOPES: dict[str, set[str]] = {
    FS_READ: {"read", "read:files", "files:read", "file:read", "fs:read", "filesystem:read"},
    FS_WRITE: {"write", "write:files", "files:write", "file:write", "fs:write", "filesystem:write"},
    NET: {"net", "network", "http", "fetch", "network:outbound", "outbound"},
    EXEC: {"exec", "execute", "shell", "execute:commands", "command:execute", "run:commands"},
    ENV: {"env", "environment", "read:env", "env:read"},
}

# Parameter names that make a free-form string dangerous: these flow into shells, files, and
# HTTP clients far more often than not.
RISKY_PARAM_NAMES = {
    "cmd",
    "command",
    "script",
    "shell",
    "exec",
    "code",
    "expr",
    "expression",
    "eval",
    "query",
    "sql",
    "path",
    "file",
    "filename",
    "filepath",
    "dir",
    "directory",
    "url",
    "uri",
    "endpoint",
    "host",
    "args",
    "argv",
}


@dataclass
class Call:
    """A function call we care about, with the capability it implies."""

    name: str  # dotted callee, e.g. "subprocess.run"
    line: int
    capability: str | None = None
    shell: bool = False  # subprocess(..., shell=True) / child_process.exec
    dynamic_eval: bool = False  # eval / exec / Function / vm.runInNewContext
    raw: str = ""


@dataclass
class ToolParam:
    name: str
    type: str | None = None
    required: bool = False
    constrained: bool = False  # has enum / pattern / const / maxLength / a bounded type
    line: int | None = None

    @property
    def is_free_form_string(self) -> bool:
        return (self.type in (None, "string", "any")) and not self.constrained

    @property
    def is_risky_name(self) -> bool:
        return self.name.lower().strip("_") in RISKY_PARAM_NAMES


@dataclass
class ToolDef:
    """A tool exposed to the LLM, wherever it was declared."""

    name: str
    file: str
    line: int
    origin: str  # "manifest" | "python" | "typescript"
    params: list[ToolParam] = field(default_factory=list)
    schema: dict | None = None  # raw JSON Schema, when one was declared
    additional_properties_open: bool = False
    has_schema: bool = False
    handler_start: int | None = None
    handler_end: int | None = None

    def spans(self, line: int) -> bool:
        if self.handler_start is None or self.handler_end is None:
            return False
        return self.handler_start <= line <= self.handler_end


@dataclass
class ServerDef:
    """An MCP server instantiated in code."""

    file: str
    line: int
    kind: str  # "FastMCP", "Server", "McpServer", ...
    name: str | None = None
    port: int | None = None
    transport: str | None = None


@dataclass
class SourceFacts:
    path: str
    language: str
    calls: list[Call] = field(default_factory=list)
    tools: list[ToolDef] = field(default_factory=list)
    servers: list[ServerDef] = field(default_factory=list)
    ports: list[tuple[int, int]] = field(default_factory=list)  # (line, port)
    # Spans of generic tool dispatchers (`@server.call_tool()`), which implement every tool in
    # one function. Sinks inside them can't be attributed to a single tool by span alone.
    dispatch_spans: list[tuple[int, int]] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def capabilities(self) -> set[str]:
        return {c.capability for c in self.calls if c.capability}

    def calls_in_tool(self, tool: ToolDef) -> list[Call]:
        return [c for c in self.calls if tool.spans(c.line)]

    def calls_in_dispatch(self) -> list[Call]:
        return [
            c
            for c in self.calls
            if any(start <= c.line <= end for start, end in self.dispatch_spans)
        ]
