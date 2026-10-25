"""Extract the same facts from TypeScript/JavaScript MCP servers.

This is a lexical parser, not a real AST: v0.1 deliberately avoids a Node/tsc dependency so that
`pip install decascan` is the whole install story. It is brace-aware (so it can pull complete
schema object literals out of source) and understands the two dominant SDK shapes — the high-level
`server.tool(name, schema, handler)` registration and the low-level
`setRequestHandler(ListToolsRequestSchema, ...)` + `CallToolRequestSchema` dispatcher.

The tradeoff is real and worth stating: aliased imports and computed names are missed here in a way
they are not for Python. Replacing this with the TypeScript compiler API is tracked for v0.2.
"""

from __future__ import annotations

import json
import re

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
from .python_source import params_from_json_schema

# (regex, capability, shell?, dynamic-eval?)
_SINKS: list[tuple[re.Pattern[str], str, bool, bool]] = [
    (re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\("), EXEC, True, False),
    (re.compile(r"\b(?:child_process\.)?spawn(?:Sync)?\s*\("), EXEC, False, False),
    (re.compile(r"\b(?:child_process\.)?execFile(?:Sync)?\s*\("), EXEC, False, False),
    (re.compile(r"\beval\s*\("), EXEC, False, True),
    (re.compile(r"\bnew\s+Function\s*\("), EXEC, False, True),
    (re.compile(r"\bvm\.(?:runInNewContext|runInThisContext|Script)\s*\("), EXEC, False, True),
    (
        re.compile(
            r"\b(?:fs|fsPromises|fs\.promises)\.(?:writeFile|writeFileSync|appendFile|"
            r"appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|mkdir|mkdirSync|rename|"
            r"copyFile|chmod|truncate)\s*\("
        ),
        FS_WRITE,
        False,
        False,
    ),
    (
        re.compile(
            r"\b(?:fs|fsPromises|fs\.promises)\.(?:readFile|readFileSync|readdir|readdirSync|"
            r"stat|statSync|createReadStream|access)\s*\("
        ),
        FS_READ,
        False,
        False,
    ),
    (re.compile(r"\bfetch\s*\("), NET, False, False),
    (re.compile(r"\baxios\.(?:get|post|put|patch|delete|request)\s*\("), NET, False, False),
    (re.compile(r"\b(?:https?)\.(?:request|get)\s*\("), NET, False, False),
    (re.compile(r"\bgot\s*\("), NET, False, False),
    (re.compile(r"\bprocess\.env\b"), ENV, False, False),
]

_SERVER_CTOR = re.compile(r"\bnew\s+(Server|McpServer|MCPServer|FastMCP)\s*\(")
_LISTEN = re.compile(r"\.listen\s*\(\s*(\d{2,5})")
_PORT_KV = re.compile(r"\bport\s*[:=]\s*(\d{2,5})")
_TOOL_REGISTER = re.compile(
    r"\b(?:server|mcp|app)\.(?:tool|registerTool)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]\s*,"
)
_TOOL_OBJECT = re.compile(r"\{\s*(?:name)\s*:\s*[\"'`]([^\"'`]+)[\"'`]")
_CALL_TOOL_HANDLER = re.compile(r"setRequestHandler\s*\(\s*CallToolRequestSchema")
_ZOD_FIELD = re.compile(
    r"[\"'`]?(\w+)[\"'`]?\s*:\s*z\.(\w+)\s*\(([^)]*)\)((?:\s*\.\w+\s*\([^)]*\))*)"
)
_ZOD_CONSTRAINING = ("regex", "enum", "uuid", "email", "url", "max", "length", "literal", "ip")

_DESCRIPTION = re.compile(r"\bdescription\s*:\s*([\"'`])((?:\\.|(?!\1).)*)\1", re.S)
# `server.tool("name", "description", schema, handler)` — the SDK's positional-description form.
_TOOL_REGISTER_DESC = re.compile(
    r"\b(?:server|mcp|app)\.(?:tool|registerTool)\s*\(\s*[\"'`][^\"'`]+[\"'`]\s*,\s*"
    r"([\"'`])((?:\\.|(?!\1).)*)\1"
)
_LOG_CALL = re.compile(
    r"\b(?:console|logger|log|winston|pino|bunyan|audit)\s*\.\s*"
    r"(?:log|info|warn|warning|error|debug|trace|fatal)\s*\("
)
_EMPTY_CATCH = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}")
_STRING_LITERAL = re.compile(r"[\"'`]([^\"'`]*)[\"'`]")
_RETURN_STMT = re.compile(r"\breturn\b([^;\n]*)")
# `${name}`, `" + name`, or the bare identifier — the three ways a value lands in a JS sink.
_INTERPOLATION = "${%s}"


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, preserving offsets so line numbers stay correct."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif text.startswith("/*", i):
            while i < n and not text.startswith("*/", i):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            for j in range(i, min(i + 2, n)):
                out[j] = " "
            i += 2
        else:
            i += 1
    return "".join(out)


def _extract_call(text: str, start: int) -> int | None:
    """Return the index just past the `)` closing the call that opens at or after `start`.

    Used for handler spans: a tool registration's handler is the arrow function *inside* the call,
    so the only reliable span is the call itself. Matching braces instead would stop at the
    destructuring pattern in `async ({ command }) => { ... }`.
    """
    open_idx = text.find("(", start)
    if open_idx == -1:
        return None
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _extract_object(text: str, start: int) -> tuple[str, int] | None:
    """Return the balanced `{...}` literal beginning at or after `start`, and its end index."""
    open_idx = text.find("{", start)
    if open_idx == -1:
        return None
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx : i + 1], i + 1
        i += 1
    return None


def _js_object_to_dict(literal: str) -> dict | None:
    """Best-effort JS-object-literal -> dict. Returns None when it isn't plain JSON-ish data."""
    if "z." in literal or "=>" in literal:
        return None  # zod schema or code, not data — handled separately
    text = literal
    text = re.sub(r"'([^'\\]*)'", r'"\1"', text)  # single -> double quotes
    text = re.sub(r"([{,]\s*)([A-Za-z_$][\w$]*)\s*:", r'\1"\2":', text)  # quote bare keys
    text = re.sub(r",(\s*[}\]])", r"\1", text)  # trailing commas
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _params_from_zod(literal: str, line: int) -> list[ToolParam]:
    params: list[ToolParam] = []
    for match in _ZOD_FIELD.finditer(literal):
        name, kind, inner, chain = match.groups()
        chain = chain or ""
        constrained = kind == "enum" or any(c in chain for c in _ZOD_CONSTRAINING)
        params.append(
            ToolParam(
                name=name,
                type={"string": "string", "number": "number", "boolean": "boolean"}.get(kind, kind),
                required="optional" not in chain and "nullish" not in chain,
                constrained=constrained,
                line=line,
            )
        )
    return params


def parse_javascript(path: str, source: str) -> SourceFacts:
    language = "typescript" if path.endswith((".ts", ".tsx", ".mts")) else "javascript"
    facts = SourceFacts(path=path, language=language)
    text = _strip_comments(source)
    lines = source.splitlines()

    def snippet(line: int) -> str:
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    # Sink -> the text of its arguments, so the taint pass below can ask what reaches it.
    call_args: dict[int, str] = {}

    for pattern, capability, shell, dynamic in _SINKS:
        for match in pattern.finditer(text):
            line = _line_of(text, match.start())
            args = _call_args(text, match.start())
            call = Call(
                name=match.group(0).rstrip("(").strip(),
                line=line,
                capability=capability,
                shell=shell,
                dynamic_eval=dynamic,
                raw=snippet(line),
                literal_args=_STRING_LITERAL.findall(args),
            )
            facts.calls.append(call)
            call_args[line] = args

    for match in _LOG_CALL.finditer(text):
        line = _line_of(text, match.start())
        facts.log_calls.append(
            Call(name=match.group(0).rstrip("(").strip(), line=line, raw=snippet(line))
        )

    for match in _EMPTY_CATCH.finditer(text):
        facts.swallowed_excepts.append((_line_of(text, match.start()), "catch"))

    for match in _SERVER_CTOR.finditer(text):
        line = _line_of(text, match.start())
        facts.servers.append(
            ServerDef(file=path, line=line, kind=match.group(1), name=_server_name(text, match.end()))
        )

    for pattern in (_LISTEN, _PORT_KV):
        for match in pattern.finditer(text):
            facts.ports.append((_line_of(text, match.start()), int(match.group(1))))

    for match in _CALL_TOOL_HANDLER.finditer(text):
        body = _extract_object(text, match.end())
        start_line = _line_of(text, match.start())
        end_line = _line_of(text, match.end() + len(body[0])) if body else start_line
        facts.dispatch_spans.append((start_line, end_line))

    facts.tools.extend(_tools_from_registrations(text, path))
    facts.tools.extend(_tools_from_object_literals(text, path, {t.name for t in facts.tools}))

    _find_flows(facts, call_args)
    _find_external_returns(text, facts)
    return facts


def _call_args(text: str, start: int) -> str:
    """The text between a call's parentheses. '' when they don't balance."""
    end = _extract_call(text, start)
    open_idx = text.find("(", start)
    if end is None or open_idx == -1:
        return ""
    return text[open_idx + 1 : end - 1]


def _find_flows(facts: SourceFacts, call_args: dict[int, str]) -> None:
    """Heuristic taint: does a tool parameter's name appear in the arguments of a sink in its span?

    This is a *name match*, not a proof of flow — there is no AST here to track assignments through.
    Every flow it produces is marked `proven=False` so MCP05 reports it at lower confidence than the
    Python equivalent. It catches the shape that actually appears in TS servers
    (`exec(`git log ${branch}`)`) and misses anything laundered through a local variable.
    """
    for tool in facts.tools:
        if tool.handler_start is None:
            continue
        for call in facts.calls_in_tool(tool):
            if call.capability not in (EXEC, FS_READ, FS_WRITE):
                continue
            args = call_args.get(call.line, "")
            if not args:
                continue
            for param in tool.params:
                if not _mentions(args, param.name):
                    continue
                # An argv array (`execFile(cmd, [args])`) is not a shell; only a tainted program
                # name is the injection, matching the Python analyzer's rule.
                if call.capability == EXEC and not call.shell and not call.dynamic_eval:
                    if not _mentions(args.split(",", 1)[0], param.name):
                        continue
                facts.taint_flows.append(
                    TaintFlow(
                        source=param.name,
                        sink=call,
                        tool=tool.name,
                        steps=[tool.line, call.line],
                        proven=False,
                        sanitized=_is_quoted(args, param.name),
                    )
                )
                break


_QUOTED_LITERAL = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")


def _mentions(args: str, param: str) -> bool:
    """Whether `param` is used as a value in `args`, not merely named inside a string literal.

    `exec("echo command")` mentions the word `command` but does not use the parameter of that name.
    Quoted literals are blanked first; `${param}` inside a template literal is checked on the raw text.
    """
    if _INTERPOLATION % param in args:
        return True
    code = _QUOTED_LITERAL.sub('""', args)
    return bool(re.search(rf"(?<![\w.$]){re.escape(param)}(?![\w$])", code))


def _is_quoted(args: str, param: str) -> bool:
    """`shell-quote`/`shescape` wrappers around the value neutralize the metacharacters."""
    return bool(
        re.search(rf"\b(?:quote|shellQuote|shescape|escapeShell)\s*\(\s*[^)]*\b{re.escape(param)}\b", args)
    )


def _find_external_returns(text: str, facts: SourceFacts) -> None:
    """A network response handed straight back to the model is a prompt-injection delivery path."""
    external = [c for c in facts.calls if c.capability in (NET, ENV)]
    if not external:
        return

    lines = text.splitlines()

    for match in _RETURN_STMT.finditer(text):
        line = _line_of(text, match.start())
        body = match.group(1)
        for call in external:
            name = call.name.split(".")[0]
            # Either the fetch is returned inline, or a variable holding its result is — both
            # within a few lines of the call, which is as much flow as a lexical parser can claim.
            carriers = {name} | _carrier_variables(lines, call.line, line)
            if any(re.search(rf"(?<![\w.$]){re.escape(n)}(?![\w$])", body) for n in carriers) or (
                call.capability == ENV and "env" in body
            ):
                if 0 <= line - call.line <= 8:
                    tool = next(
                        (t.name for t in facts.tools if t.spans(line)),
                        None,
                    )
                    facts.external_returns.append(
                        ExternalReturn(origin=call, line=line, tool=tool)
                    )
                    break


_ASSIGNMENT = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(.*)")


def _carrier_variables(lines: list[str], first: int, last: int) -> set[str]:
    """Variables holding the result of the call on line `first`, as seen by line `last`.

    `const res = await fetch(url); const body = await res.text(); return body` carries the fetch
    through two assignments. Two hops cover the shapes that occur in practice.
    """
    carriers: set[str] = set()
    window = range(max(first, 1), min(last, len(lines)) + 1)
    for hop in range(2):
        for number in window:
            match = _ASSIGNMENT.search(lines[number - 1])
            if not match:
                continue
            name, rhs = match.groups()
            if hop == 0 and number == first or any(
                re.search(rf"(?<![\w.$]){re.escape(c)}(?![\w$])", rhs) for c in carriers
            ):
                carriers.add(name)
    return carriers


def _server_name(text: str, start: int) -> str | None:
    match = re.search(r"name\s*:\s*[\"'`]([^\"'`]+)[\"'`]", text[start : start + 200])
    return match.group(1) if match else None


def _description_near(text: str, start: int, end: int | None) -> tuple[str | None, int | None]:
    """The description a tool registration shows the model, in either SDK spelling.

    `server.tool("name", "description", schema, handler)` puts it second; `registerTool("name",
    { description, inputSchema }, handler)` puts it in the options object.
    """
    positional = _TOOL_REGISTER_DESC.match(text, start)
    if positional:
        return positional.group(2), _line_of(text, positional.start(2))

    window = text[start : end if end else start + 400]
    keyed = _DESCRIPTION.search(window)
    if keyed:
        return keyed.group(2), _line_of(text, start + keyed.start(2))
    return None, None


def _tools_from_registrations(text: str, path: str) -> list[ToolDef]:
    """`server.tool("name", { schema }, handler)` — schema is zod or JSON Schema."""
    tools: list[ToolDef] = []
    for match in _TOOL_REGISTER.finditer(text):
        name = match.group(1)
        line = _line_of(text, match.start())
        extracted = _extract_object(text, match.end())
        tool = ToolDef(name=name, file=path, line=line, origin=language_of(path))

        # The handler lives inside the registration call, so the call's extent is the tool's span.
        call_end = _extract_call(text, match.start())
        tool.handler_start = line
        tool.handler_end = _line_of(text, call_end - 1) if call_end else line
        tool.description, tool.description_line = _description_near(text, match.start(), call_end)

        if extracted:
            literal, _ = extracted

            if "z." in literal:
                tool.params = _params_from_zod(literal, line)
                tool.has_schema = bool(tool.params)
                tool.additional_properties_open = False  # zod objects are closed by default
            else:
                parsed = _js_object_to_dict(literal) or {}
                schema = parsed.get("inputSchema") if "inputSchema" in parsed else parsed
                if isinstance(schema, dict) and schema.get("properties"):
                    tool.schema = schema
                    tool.has_schema = True
                    tool.params = params_from_json_schema(schema, line)
                    tool.additional_properties_open = (
                        schema.get("additionalProperties", True) is not False
                    )
        tools.append(tool)
    return tools


def _tools_from_object_literals(text: str, path: str, seen: set[str]) -> list[ToolDef]:
    """`{ name: "x", description: "...", inputSchema: {...} }` inside a ListTools handler."""
    tools: list[ToolDef] = []
    for match in _TOOL_OBJECT.finditer(text):
        name = match.group(1)
        if name in seen:
            continue
        extracted = _extract_object(text, match.start())
        if not extracted:
            continue
        parsed = _js_object_to_dict(extracted[0])
        if not parsed or "inputSchema" not in parsed:
            continue
        schema = parsed.get("inputSchema")
        if not isinstance(schema, dict):
            continue
        line = _line_of(text, match.start())
        seen.add(name)
        description = parsed.get("description")
        tools.append(
            ToolDef(
                name=name,
                file=path,
                line=line,
                origin=language_of(path),
                schema=schema,
                has_schema=True,
                params=params_from_json_schema(schema, line),
                additional_properties_open=schema.get("additionalProperties", True) is not False,
                description=description if isinstance(description, str) else None,
                description_line=line,
            )
        )
    return tools


def language_of(path: str) -> str:
    return "typescript" if path.endswith((".ts", ".tsx", ".mts")) else "javascript"
