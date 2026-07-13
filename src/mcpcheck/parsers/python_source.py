"""Extract capability facts, tool definitions and server instantiations from Python MCP servers.

Real AST, not regex: we resolve dotted callees through import aliases so `import subprocess as sp;
sp.run(...)` and `from subprocess import run; run(...)` both land on the same capability.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .common import (
    ENV,
    EXEC,
    FS_READ,
    FS_WRITE,
    NET,
    Call,
    ExternalReturn,
    ServerDef,
    SourceFacts,
    TaintFlow,
    ToolDef,
    ToolParam,
)

# Dotted callees (or bare attribute names, matched on the last segment) -> capability.
_EXEC_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.spawnl",
    "os.spawnv",
    "pty.spawn",
    "commands.getoutput",
}
_DYNAMIC_EVAL = {"eval", "exec", "compile", "__import__"}

_FS_WRITE_CALLS = {
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.mkdir",
    "os.makedirs",
    "os.rename",
    "os.replace",
    "os.chmod",
    "os.chown",
    "os.truncate",
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
}
_FS_WRITE_METHODS = {"write_text", "write_bytes", "writelines", "unlink", "touch", "mkdir", "rmdir"}

_FS_READ_CALLS = {
    "os.listdir",
    "os.walk",
    "os.scandir",
    "os.stat",
    "glob.glob",
    "glob.iglob",
}
_FS_READ_METHODS = {"read_text", "read_bytes", "iterdir", "rglob", "glob"}

# Root modules whose calls are outbound network I/O.
_NET_ROOTS = {
    "requests",
    "httpx",
    "urllib",
    "urllib3",
    "aiohttp",
    "socket",
    "http",
    "websockets",
    "boto3",
    "smtplib",
    "ftplib",
    "paramiko",
}
_NET_METHODS = {"urlopen", "create_connection"}

_SERVER_CTORS = {"FastMCP", "Server", "MCPServer", "McpServer", "LowLevelServer"}
_TOOL_DECORATORS = {"tool", "add_tool"}
_DISPATCH_DECORATORS = {"call_tool", "list_tools"}

# Logging frameworks. A server that shells out and calls none of these leaves no audit trail.
_LOG_ROOTS = {"logging", "logger", "log", "structlog", "loguru", "_logger", "_log", "audit"}
_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}

# Calls that genuinely neutralize a tainted value. Only shell quoting qualifies: `os.path.realpath`
# and friends normalize a path but do not confine it, so `../../etc/shadow` survives them intact —
# treating them as sanitizers would hide real traversal.
_SANITIZERS = {"shlex.quote", "pipes.quote"}

# Annotations that constrain a value enough that it is not free-form.
_CONSTRAINED_ANNOTATION_MARKERS = (
    "Literal",
    "Enum",
    "pattern",
    "regex",
    "max_length",
    "maxLength",
    "constr",
    "conint",
    "Annotated",
)


def _dotted(node: ast.AST) -> str:
    """Render `a.b.c` from an attribute/name chain; '' for anything else."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        parts.append("()")
    else:
        return ""
    return ".".join(reversed(parts))


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _literal(node: ast.expr | None):
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        return None


@dataclass
class _PydanticModel:
    """A BaseModel used as a tool's input schema via `Model.model_json_schema()`.

    The official MCP servers declare tools this way, so a scanner that can't read a pydantic model
    is blind on exactly the servers people copy from.
    """

    name: str
    line: int
    params: list[ToolParam]
    extra_allowed: bool


def _collect_pydantic_models(tree: ast.AST) -> dict[str, _PydanticModel]:
    models: dict[str, _PydanticModel] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {_dotted(base).rsplit(".", 1)[-1] for base in node.bases}
        if "BaseModel" not in bases:
            continue

        params: list[ToolParam] = []
        extra_allowed = False

        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and _model_config_allows_extra(stmt):
                extra_allowed = True
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                continue

            annotation = ast.unparse(stmt.annotation)
            params.append(
                ToolParam(
                    name=stmt.target.id,
                    type=_python_type_to_schema_type(_inner_type(annotation)),
                    required=_is_required_field(stmt.value),
                    constrained=any(m in annotation for m in _CONSTRAINED_ANNOTATION_MARKERS),
                    line=stmt.lineno,
                )
            )

        models[node.name] = _PydanticModel(
            name=node.name, line=node.lineno, params=params, extra_allowed=extra_allowed
        )
    return models


def _model_config_allows_extra(stmt: ast.Assign) -> bool:
    targets = {t.id for t in stmt.targets if isinstance(t, ast.Name)}
    if "model_config" not in targets:
        return False
    config = _literal(stmt.value)
    return isinstance(config, dict) and config.get("extra") == "allow"


def _is_required_field(value: ast.expr | None) -> bool:
    """No default is required; `Field(...)` with a literal Ellipsis is pydantic's way of saying so."""
    if value is None:
        return True
    if isinstance(value, ast.Call) and _dotted(value.func).rsplit(".", 1)[-1] == "Field":
        positional = value.args[0] if value.args else None
        if isinstance(positional, ast.Constant) and positional.value is Ellipsis:
            return True
        return _kwarg(value, "default") is None and not value.args
    return False


def _inner_type(annotation: str) -> str:
    """`Annotated[AnyUrl, Field(...)]` -> `AnyUrl`, so the real type drives the free-form check."""
    if annotation.startswith("Annotated["):
        return annotation[len("Annotated[") :].split(",")[0].strip()
    return annotation


class _Visitor(ast.NodeVisitor):
    def __init__(
        self, facts: SourceFacts, source: str, models: dict[str, _PydanticModel] | None = None
    ) -> None:
        self.facts = facts
        self.lines = source.splitlines()
        self.aliases: dict[str, str] = {}  # local name -> canonical dotted origin
        self.models = models or {}
        # AST node identity -> the Call fact recorded for it. Keyed by node rather than by line
        # because `Path(path).write_text(body)` is two calls on one line, and a line-keyed index
        # cannot tell the sink from its receiver.
        self.call_index: dict[int, Call] = {}
        # The function bodies worth running taint over, paired with the tool they implement.
        self.tool_nodes: list[tuple[ToolDef, ast.FunctionDef | ast.AsyncFunctionDef]] = []
        self.dispatch_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    # -- imports: build the alias map so dotted resolution survives renaming ---------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def _canonical(self, dotted: str) -> str:
        if not dotted:
            return ""
        head, _, tail = dotted.partition(".")
        origin = self.aliases.get(head)
        if not origin:
            return dotted
        return f"{origin}.{tail}" if tail else origin

    # -- capability sinks ------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        raw = _dotted(node.func)
        canonical = self._canonical(raw)
        last = canonical.rsplit(".", 1)[-1] if canonical else ""
        root = canonical.split(".", 1)[0] if canonical else ""
        line = node.lineno
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

        capability: str | None = None
        shell = False
        dynamic = False

        if canonical in _EXEC_CALLS or (root == "subprocess" and last in {"run", "Popen", "call"}):
            capability = EXEC
            shell = bool(_literal(_kwarg(node, "shell"))) or canonical in {"os.system", "os.popen"}
        elif raw in _DYNAMIC_EVAL and isinstance(node.func, ast.Name):
            capability = EXEC
            dynamic = True
        elif canonical in _FS_WRITE_CALLS or last in _FS_WRITE_METHODS:
            capability = FS_WRITE
        elif raw == "open" or canonical.endswith(".open"):
            mode = _literal(node.args[1]) if len(node.args) > 1 else _literal(_kwarg(node, "mode"))
            mode = mode if isinstance(mode, str) else "r"
            capability = FS_WRITE if any(m in mode for m in "wax+") else FS_READ
        elif canonical in _FS_READ_CALLS or last in _FS_READ_METHODS:
            capability = FS_READ
        elif root in _NET_ROOTS or last in _NET_METHODS:
            capability = NET
        elif canonical in {"os.getenv", "os.environ.get", "dotenv.load_dotenv"}:
            capability = ENV

        if capability:
            call = Call(
                # `Path(p).write_text(...)` resolves to "().write_text"; report it as the reader
                # would say it out loud.
                name=(canonical or raw).removeprefix("()."),
                line=line,
                capability=capability,
                shell=shell,
                dynamic_eval=dynamic,
                raw=snippet,
                literal_args=_string_literals(node),
            )
            self.facts.calls.append(call)
            self.call_index[id(node)] = call
        elif self._is_log_call(canonical, last, root):
            self.facts.log_calls.append(Call(name=canonical or raw, line=line, raw=snippet))

        self._maybe_server(node, canonical, raw, line)
        self._maybe_schema_tool(node, canonical, raw, line)
        self._maybe_port(node, line)
        self.generic_visit(node)

    def _is_log_call(self, canonical: str, last: str, root: str) -> bool:
        if last not in _LOG_METHODS:
            return False
        return root in _LOG_ROOTS or "log" in root.lower() or "audit" in root.lower()

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # `except Exception: pass` — the failure happened and left no trace of itself.
        if all(isinstance(stmt, ast.Pass) for stmt in node.body):
            name = _dotted(node.type) if node.type is not None else "bare except"
            self.facts.swallowed_excepts.append((node.lineno, name or "Exception"))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self._canonical(_dotted(node)) == "os.environ":
            line = node.lineno
            call = Call(
                name="os.environ",
                line=line,
                capability=ENV,
                raw=self.lines[line - 1].strip() if line <= len(self.lines) else "",
            )
            self.facts.calls.append(call)
            self.call_index[id(node)] = call
        self.generic_visit(node)

    # -- servers ---------------------------------------------------------------------------
    def _maybe_server(self, node: ast.Call, canonical: str, raw: str, line: int) -> None:
        ctor = (canonical or raw).rsplit(".", 1)[-1]
        if ctor not in _SERVER_CTORS:
            return
        name = _literal(node.args[0]) if node.args else _literal(_kwarg(node, "name"))
        port = _literal(_kwarg(node, "port"))
        self.facts.servers.append(
            ServerDef(
                file=self.facts.path,
                line=line,
                kind=ctor,
                name=name if isinstance(name, str) else None,
                port=port if isinstance(port, int) else None,
                transport=_transport_of(_literal(_kwarg(node, "transport"))),
            )
        )

    def _maybe_port(self, node: ast.Call, line: int) -> None:
        port = _literal(_kwarg(node, "port"))
        if isinstance(port, int):
            self.facts.ports.append((line, port))

    # -- tools declared as `types.Tool(name=..., inputSchema={...})` ------------------------
    def _maybe_schema_tool(self, node: ast.Call, canonical: str, raw: str, line: int) -> None:
        if (canonical or raw).rsplit(".", 1)[-1] != "Tool":
            return
        name = _literal(_kwarg(node, "name")) or (_literal(node.args[0]) if node.args else None)
        if not isinstance(name, str):
            return

        schema_node = _kwarg(node, "inputSchema") or _kwarg(node, "input_schema")
        schema = _literal(schema_node)
        description_node = _kwarg(node, "description")
        description = _literal(description_node)

        tool = ToolDef(
            name=name,
            file=self.facts.path,
            line=line,
            origin="python",
            schema=schema if isinstance(schema, dict) else None,
            has_schema=isinstance(schema, dict),
            description=description if isinstance(description, str) else None,
            description_line=description_node.lineno if description_node is not None else None,
        )

        if isinstance(schema, dict):
            tool.params = params_from_json_schema(schema, line)
            tool.additional_properties_open = schema.get("additionalProperties", True) is not False
        elif (model := self._model_behind(schema_node)) is not None:
            tool.params = model.params
            tool.has_schema = True
            # pydantic drops unknown fields unless the model opts into extra="allow", so a pydantic
            # schema is closed even though model_json_schema() omits additionalProperties.
            tool.additional_properties_open = model.extra_allowed

        self.facts.tools.append(tool)

    def _model_behind(self, node: ast.expr | None) -> _PydanticModel | None:
        """Resolve `inputSchema=Fetch.model_json_schema()` back to the Fetch class."""
        if not isinstance(node, ast.Call):
            return None
        dotted = _dotted(node.func)
        if not dotted.endswith(".model_json_schema") and not dotted.endswith(".schema"):
            return None
        return self.models.get(dotted.split(".")[0])

    # -- tools declared as `@mcp.tool()` decorated functions --------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function(node)
        self.generic_visit(node)

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        end = node.end_lineno or node.lineno
        for deco in node.decorator_list:
            call = deco if isinstance(deco, ast.Call) else None
            target = call.func if call else deco
            attr = _dotted(target).rsplit(".", 1)[-1]

            if attr in _DISPATCH_DECORATORS:
                self.facts.dispatch_spans.append((node.lineno, end))
                if attr == "call_tool":
                    self.dispatch_nodes.append(node)
                continue
            if attr not in _TOOL_DECORATORS:
                continue

            declared = _literal(_kwarg(call, "name")) if call else None
            # FastMCP shows the model the docstring when no explicit description is given, so the
            # docstring *is* the tool description as far as prompt injection is concerned.
            described = _literal(_kwarg(call, "description")) if call else None
            docstring = ast.get_docstring(node)
            description = described if isinstance(described, str) else docstring

            tool = ToolDef(
                name=declared if isinstance(declared, str) else node.name,
                file=self.facts.path,
                line=node.lineno,
                origin="python",
                params=self._params_from_signature(node),
                has_schema=False,  # FastMCP infers the schema from type hints
                handler_start=node.lineno,
                handler_end=end,
                description=description,
                description_line=_docstring_line(node) if description is docstring else node.lineno,
            )
            self.facts.tools.append(tool)
            self.tool_nodes.append((tool, node))

    def _params_from_signature(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ToolParam]:
        args = node.args
        positional = args.posonlyargs + args.args
        defaults_start = len(positional) - len(args.defaults)
        params: list[ToolParam] = []

        for i, arg in enumerate(positional):
            if arg.arg in {"self", "cls", "ctx", "context"}:
                continue
            params.append(
                self._param_from_arg(arg, required=i < defaults_start)
            )
        # kwonlyargs and kw_defaults are always parallel in a valid AST.
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
            params.append(self._param_from_arg(arg, required=default is None))
        return params

    def _param_from_arg(self, arg: ast.arg, required: bool) -> ToolParam:
        annotation = ast.unparse(arg.annotation) if arg.annotation else None
        constrained = bool(
            annotation
            and any(marker in annotation for marker in _CONSTRAINED_ANNOTATION_MARKERS)
        )
        return ToolParam(
            name=arg.arg,
            type=_python_type_to_schema_type(annotation),
            required=required,
            constrained=constrained,
            line=arg.lineno,
        )


def _string_literals(node: ast.Call) -> list[str]:
    """Every string constant this call touches: its arguments, and its receiver chain.

    The receiver matters because the path of a method-style sink lives there, not in the arguments:
    in `Path("~/.ssh/id_rsa").expanduser().read_text()` the sink is `read_text()`, which is passed
    nothing at all. A rule asking "what file does this touch?" has to look left of the dot.
    """
    out: list[str] = []
    for arg in list(node.args) + [kw.value for kw in node.keywords]:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            out.append(arg.value)
        elif isinstance(arg, (ast.List, ast.Tuple)):
            out.extend(
                e.value for e in arg.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
            )

    if isinstance(node.func, ast.Attribute):
        for sub in ast.walk(node.func.value):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                out.append(sub.value)

    return list(dict.fromkeys(out))


def _docstring_line(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int | None:
    first = node.body[0] if node.body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        return first.lineno
    return None


@dataclass
class _Tainted:
    """A value known to derive from a tool parameter, and how it got here."""

    source: str
    steps: list[int]
    sanitized: bool = False


class _FlowAnalyzer:
    """Intraprocedural taint tracking over one tool handler.

    Sources are the tool's parameters — the only values in a handler the model controls. We
    propagate them through assignments, f-strings, concatenation, `%`, `.format()` and `.join()`
    until they reach a sink, which gives MCP05 something MCP03 does not have: proof the value the
    model chose is the value that gets executed.

    Deliberately flow-insensitive and intraprocedural. Taint that leaves through a helper function
    call is lost, so this under-reports rather than over-reports — the right direction to be wrong
    in for a tool people are meant to run in CI.
    """

    def __init__(self, call_index: dict[int, Call], tool_name: str) -> None:
        self.call_index = call_index
        self.tool_name = tool_name
        self.tainted: dict[str, _Tainted] = {}
        self.origins: dict[str, Call] = {}  # var -> the net/env call it was assigned from
        # Keyed so the second propagation pass refines a flow rather than reporting it twice.
        self._flows: dict[tuple[str, int], TaintFlow] = {}
        self._returns: dict[tuple[int, int], ExternalReturn] = {}
        self.args_dict: str | None = None  # the `arguments` param of a low-level dispatcher

    @property
    def flows(self) -> list[TaintFlow]:
        return list(self._flows.values())

    @property
    def returns(self) -> list[ExternalReturn]:
        return list(self._returns.values())

    # -- taint of an expression ------------------------------------------------------------
    def _taint_of(self, node: ast.AST | None) -> _Tainted | None:
        if node is None:
            return None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return self.tainted[sub.id]
            # `arguments["command"]` / `arguments.get("command")` in a low-level dispatcher: the
            # key names the tool parameter, so the key is the source.
            key = self._args_key(sub)
            if key is not None:
                return _Tainted(source=key, steps=[getattr(sub, "lineno", 0)])
        return None

    def _args_key(self, node: ast.AST) -> str | None:
        if self.args_dict is None:
            return None
        if isinstance(node, ast.Subscript) and _dotted(node.value) == self.args_dict:
            key = _literal(node.slice)
            return key if isinstance(key, str) else None
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if dotted == f"{self.args_dict}.get" and node.args:
                key = _literal(node.args[0])
                return key if isinstance(key, str) else None
        return None

    def _origin_of(self, node: ast.AST | None) -> Call | None:
        """The external call a value came from: a network fetch, or the environment.

        Deliberately excludes local file reads. A file-reading tool returning file contents is the
        tool doing its job; flagging it would bury the real signal — content pulled from the
        *network*, which an attacker can rewrite between two calls, and the environment, which the
        model has no business seeing at all.
        """
        if node is None:
            return None
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.origins:
                return self.origins[sub.id]
            call = self.call_index.get(id(sub))
            if call is not None and call.capability in (NET, ENV):
                return call
        return None

    def _sanitizer(self, node: ast.AST | None) -> bool:
        if not isinstance(node, ast.Call):
            return False
        dotted = _dotted(node.func)
        return dotted in _SANITIZERS or dotted.rsplit(".", 1)[-1] == "quote"

    # -- the walk --------------------------------------------------------------------------
    def run(self, node: ast.FunctionDef | ast.AsyncFunctionDef, sources: list[ToolParam]) -> None:
        for param in sources:
            self.tainted[param.name] = _Tainted(source=param.name, steps=[param.line or node.lineno])

        # Two passes: a value can be assigned from a variable defined later in a nested branch,
        # and one extra sweep is enough to catch the chains that occur in practice without paying
        # for a real fixpoint.
        for _ in range(2):
            self._walk(node)

    def _walk(self, node: ast.AST) -> None:
        for stmt in ast.walk(node):
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                self._assign(stmt)
            elif isinstance(stmt, ast.Call):
                self._call(stmt)
            elif isinstance(stmt, ast.Return):
                self._return(stmt)

    def _assign(self, stmt: ast.Assign | ast.AnnAssign | ast.AugAssign) -> None:
        value = stmt.value
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not names:
            return

        taint = self._taint_of(value)
        if taint is not None:
            sanitized = taint.sanitized or self._sanitizer(value)
            for name in names:
                self.tainted[name] = _Tainted(
                    source=taint.source,
                    steps=[*taint.steps, stmt.lineno],
                    sanitized=sanitized,
                )
        elif isinstance(stmt, ast.Assign):
            # Reassigned from something untainted — the variable is clean again.
            for name in names:
                self.tainted.pop(name, None)

        origin = self._origin_of(value)
        if origin is not None:
            for name in names:
                self.origins[name] = origin

    def _call(self, node: ast.Call) -> None:
        sink = self.call_index.get(id(node))
        if sink is None or sink.capability not in (EXEC, FS_READ, FS_WRITE):
            return

        for arg in self._sink_arguments(node, sink):
            taint = self._taint_of(arg)
            if taint is None:
                continue
            self._flows[(taint.source, sink.line)] = TaintFlow(
                source=taint.source,
                sink=sink,
                tool=self.tool_name,
                steps=[*taint.steps, node.lineno],
                proven=True,
                sanitized=taint.sanitized,
            )
            return  # one flow per sink is enough to make the point

    def _sink_arguments(self, node: ast.Call, sink: Call) -> list[ast.expr]:
        """The argument positions where taint actually means something, for this kind of sink.

        Not every argument of a dangerous call is dangerous. `Path(p).write_text(body)` is a
        traversal risk because of `p`, not because of `body` — the content of a file the caller
        already chose to write is not the vulnerability. Likewise `subprocess.run(["make", target])`
        passes `target` as an argument to a fixed program, which is not command injection.
        """
        if sink.capability in (FS_READ, FS_WRITE):
            method = sink.name.rsplit(".", 1)[-1]
            if method in _FS_WRITE_METHODS or method in _FS_READ_METHODS:
                # `Path(p).read_text()` — the path is the receiver, and the arguments are content.
                return [node.func.value] if isinstance(node.func, ast.Attribute) else []
            # `open(p)`, `os.remove(p)`, `shutil.copy(src, dst)` — the leading arguments are paths.
            return list(node.args[:2])

        if sink.capability == EXEC and not sink.shell and not sink.dynamic_eval:
            # argv-style exec: only the program slot is an injection; the rest are its arguments.
            first = node.args[0] if node.args else None
            if first is None:
                return []
            if isinstance(first, (ast.List, ast.Tuple)):
                return [first.elts[0]] if first.elts else []
            return [first]

        # A shell or an evaluator parses whatever it is handed, wherever it sits.
        return list(node.args) + [kw.value for kw in node.keywords]

    def _return(self, stmt: ast.Return) -> None:
        origin = self._origin_of(stmt.value)
        if origin is not None:
            self._returns[(origin.line, stmt.lineno)] = ExternalReturn(
                origin=origin, line=stmt.lineno, tool=self.tool_name or None
            )


def _python_type_to_schema_type(annotation: str | None) -> str | None:
    if not annotation:
        return None
    base = annotation.split("[")[0].strip().lower()
    return {
        "str": "string",
        "int": "integer",
        "float": "number",
        "bool": "boolean",
        "list": "array",
        "dict": "object",
        "any": "any",
    }.get(base, base)


def _transport_of(value) -> str | None:
    return value if isinstance(value, str) else None


def params_from_json_schema(schema: dict, line: int) -> list[ToolParam]:
    """Normalize a JSON Schema `properties` block into ToolParams. Shared with the TS parser."""
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    required = schema.get("required")
    required_names = set(required) if isinstance(required, list) else set()

    params: list[ToolParam] = []
    for name, spec in properties.items():
        spec = spec if isinstance(spec, dict) else {}
        constrained = any(
            key in spec for key in ("enum", "pattern", "const", "maxLength", "format")
        )
        params.append(
            ToolParam(
                name=str(name),
                type=spec.get("type") if isinstance(spec.get("type"), str) else None,
                required=name in required_names,
                constrained=constrained,
                line=line,
            )
        )
    return params


def _args_dict_param(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """The dict of tool arguments in `async def call_tool(name, arguments)` — the model's input."""
    args = [a.arg for a in node.args.posonlyargs + node.args.args]
    for candidate in ("arguments", "args", "params", "kwargs"):
        if candidate in args:
            return candidate
    return args[-1] if len(args) >= 2 else None


def _analyze_flows(visitor: _Visitor, facts: SourceFacts) -> None:
    """Run taint over every handler, and record what leaves through its return."""
    for tool, node in visitor.tool_nodes:
        analyzer = _FlowAnalyzer(visitor.call_index, tool.name)
        analyzer.run(node, tool.params)
        facts.taint_flows.extend(analyzer.flows)
        facts.external_returns.extend(analyzer.returns)

    for node in visitor.dispatch_nodes:
        # A low-level dispatcher implements every tool in one function, so the flow can't be
        # attributed to a tool by span. The `arguments["x"]` key names the parameter instead, and
        # the rule matches it back to whichever tool declares it.
        analyzer = _FlowAnalyzer(visitor.call_index, "")
        analyzer.args_dict = _args_dict_param(node)
        analyzer.run(node, [])
        facts.taint_flows.extend(analyzer.flows)
        facts.external_returns.extend(analyzer.returns)


def parse_python(path: str, source: str) -> SourceFacts:
    facts = SourceFacts(path=path, language="python")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        facts.parse_error = f"syntax error at line {exc.lineno}: {exc.msg}"
        return facts

    # Models first: a tool can reference a schema class defined below it in the file.
    visitor = _Visitor(facts, source, _collect_pydantic_models(tree))
    visitor.visit(tree)
    _analyze_flows(visitor, facts)
    return facts
