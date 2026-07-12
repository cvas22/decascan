"""Extract the same facts from TypeScript/JavaScript MCP servers.

This is a lexical parser, not a real AST: v0.1 deliberately avoids a Node/tsc dependency so that
`pip install mcpaudit` is the whole install story. It is brace-aware (so it can pull complete
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
    ServerDef,
    SourceFacts,
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

    for pattern, capability, shell, dynamic in _SINKS:
        for match in pattern.finditer(text):
            line = _line_of(text, match.start())
            facts.calls.append(
                Call(
                    name=match.group(0).rstrip("(").strip(),
                    line=line,
                    capability=capability,
                    shell=shell,
                    dynamic_eval=dynamic,
                    raw=snippet(line),
                )
            )

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
    return facts


def _server_name(text: str, start: int) -> str | None:
    match = re.search(r"name\s*:\s*[\"'`]([^\"'`]+)[\"'`]", text[start : start + 200])
    return match.group(1) if match else None


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
            )
        )
    return tools


def language_of(path: str) -> str:
    return "typescript" if path.endswith((".ts", ".tsx", ".mts")) else "javascript"
