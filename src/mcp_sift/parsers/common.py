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

# Paths that hold credentials or keys for the whole machine, not just this server. A tool that can
# read one of these can read the user's entire security posture into an LLM's context window.
SENSITIVE_PATH_MARKERS = (
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    ".aws/credentials",
    ".aws\\credentials",
    ".kube/config",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".bash_history",
    ".zsh_history",
    "/etc/shadow",
    "/etc/passwd",
    "credentials.json",
    "service-account",
)

# Filesystem roots so broad that granting a tool access to them grants access to everything the
# user owns. Matched against literal path arguments, not inferred.
BROAD_ROOTS = (
    "/",
    "/home",
    "/Users",
    "/etc",
    "/var",
    "C:\\",
    "C:/",
    "~",
    "~/",
)


@dataclass
class Call:
    """A function call we care about, with the capability it implies."""

    name: str  # dotted callee, e.g. "subprocess.run"
    line: int
    capability: str | None = None
    shell: bool = False  # subprocess(..., shell=True) / child_process.exec
    dynamic_eval: bool = False  # eval / exec / Function / vm.runInNewContext
    raw: str = ""
    # String literals passed as arguments. Lets a rule ask "what path does this actually touch?"
    # without re-parsing the call site.
    literal_args: list[str] = field(default_factory=list)

    @property
    def touches_sensitive_path(self) -> tuple[str, ...]:
        hits = []
        for arg in self.literal_args:
            lowered = arg.lower()
            hits.extend(m for m in SENSITIVE_PATH_MARKERS if m.lower() in lowered)
        return tuple(dict.fromkeys(hits))

    @property
    def touches_broad_root(self) -> tuple[str, ...]:
        return tuple(arg for arg in self.literal_args if arg.strip() in BROAD_ROOTS)


@dataclass
class TaintFlow:
    """A tool parameter that demonstrably reaches a dangerous sink.

    This is the fact that separates MCP05 from MCP03: MCP03-001 reports a risky parameter and a
    dangerous sink *in the same handler*; a TaintFlow means the value actually gets there.

    `proven` is True when a real AST tracked the assignments (Python) and False when a lexical
    parser matched the parameter's name inside the sink's arguments (TS/JS). Rules downgrade
    confidence accordingly rather than pretending the two are the same evidence.
    """

    source: str  # the tool parameter the value came from
    sink: Call
    tool: str
    steps: list[int] = field(default_factory=list)  # lines the value passed through, source first
    proven: bool = True
    sanitized: bool = False  # passed through a validator/allowlist on the way


@dataclass
class ExternalReturn:
    """Content from outside the server that is handed straight back to the model.

    Network responses and file contents are attacker-controllable; returning them to the LLM
    unsanitized is the prompt-injection delivery path (MCP06). The environment is not attacker-
    controllable but *is* secret, so returning it is over-sharing (MCP10). Same shape, two risks.
    """

    origin: Call  # the net / fs:read / env call whose value is returned
    line: int  # the `return` that hands it to the model
    tool: str | None = None


@dataclass
class Dependency:
    """A third-party package the server pulls in at install time."""

    name: str
    spec: str  # raw version specifier; "" when none was given
    file: str
    line: int
    ecosystem: str  # "pypi" | "npm"
    source: str = "registry"  # "registry" | "vcs" | "url" | "path"
    pinned: bool = False


@dataclass
class InstallScript:
    """An npm lifecycle script — code that runs on `npm install`, before anyone reviews it."""

    name: str  # preinstall | install | postinstall | prepare
    command: str
    file: str
    line: int


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
    # The text the model reads to decide whether and how to call this tool. It is the tool's real
    # attack surface for MCP06: whoever writes it is writing instructions the model will follow.
    description: str | None = None
    description_line: int | None = None

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
    taint_flows: list[TaintFlow] = field(default_factory=list)
    external_returns: list[ExternalReturn] = field(default_factory=list)
    # Calls to a logging framework. Their *absence* in a server that shells out is the MCP08
    # finding, so this has to be collected even though no capability attaches to it.
    log_calls: list[Call] = field(default_factory=list)
    # `except: pass` — an error that happened and left no trace. (line, exception name)
    swallowed_excepts: list[tuple[int, str]] = field(default_factory=list)
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

    def flows_in_tool(self, tool: ToolDef) -> list[TaintFlow]:
        return [f for f in self.taint_flows if f.tool == tool.name]
