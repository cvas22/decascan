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
    ServerDef,
    SourceFacts,
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
            self.facts.calls.append(
                Call(
                    # `Path(p).write_text(...)` resolves to "().write_text"; report it as the reader
                    # would say it out loud.
                    name=(canonical or raw).removeprefix("()."),
                    line=line,
                    capability=capability,
                    shell=shell,
                    dynamic_eval=dynamic,
                    raw=snippet,
                )
            )

        self._maybe_server(node, canonical, raw, line)
        self._maybe_schema_tool(node, canonical, raw, line)
        self._maybe_port(node, line)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self._canonical(_dotted(node)) == "os.environ":
            line = node.lineno
            self.facts.calls.append(
                Call(
                    name="os.environ",
                    line=line,
                    capability=ENV,
                    raw=self.lines[line - 1].strip() if line <= len(self.lines) else "",
                )
            )
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

        tool = ToolDef(
            name=name,
            file=self.facts.path,
            line=line,
            origin="python",
            schema=schema if isinstance(schema, dict) else None,
            has_schema=isinstance(schema, dict),
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
                continue
            if attr not in _TOOL_DECORATORS:
                continue

            declared = _literal(_kwarg(call, "name")) if call else None
            self.facts.tools.append(
                ToolDef(
                    name=declared if isinstance(declared, str) else node.name,
                    file=self.facts.path,
                    line=node.lineno,
                    origin="python",
                    params=self._params_from_signature(node),
                    has_schema=False,  # FastMCP infers the schema from type hints
                    handler_start=node.lineno,
                    handler_end=end,
                )
            )

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


def parse_python(path: str, source: str) -> SourceFacts:
    facts = SourceFacts(path=path, language="python")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        facts.parse_error = f"syntax error at line {exc.lineno}: {exc.msg}"
        return facts

    # Models first: a tool can reference a schema class defined below it in the file.
    _Visitor(facts, source, _collect_pydantic_models(tree)).visit(tree)
    return facts
