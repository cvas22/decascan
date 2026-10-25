"""The TypeScript/JavaScript parser (lexical, brace-aware) and the entropy helpers."""

from __future__ import annotations

import pytest

from decascan.core.entropy import looks_like_placeholder, redact, shannon_entropy
from decascan.parsers.common import ENV, EXEC, FS_READ, FS_WRITE, NET
from decascan.parsers.js_source import language_of, parse_javascript

HEADER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'import { z } from "zod";\n'
    'const server = new McpServer({ name: "demo", version: "1.0.0" });\n'
)


def parse(body: str, path: str = "src/server.ts", header: str = HEADER):
    return parse_javascript(path, header + body)


def capabilities(facts) -> set[str | None]:
    return {c.capability for c in facts.calls}


# --- languages ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "language"),
    [("a.ts", "typescript"), ("a.tsx", "typescript"), ("a.mts", "typescript"), ("a.js", "javascript"),
     ("a.mjs", "javascript"), ("a.cjs", "javascript"), ("a.jsx", "javascript")],
)
def test_language_from_extension(path, language):
    assert parse_javascript(path, "").language == language
    assert language_of(path) == language


# --- tools -------------------------------------------------------------------------------------


def test_server_tool_registration_with_zod_params():
    facts = parse(
        'server.tool("run_build", "Runs the build", { command: z.string(), retries: z.number() },\n'
        "  async ({ command }) => ({ content: [] }));\n"
    )
    (tool,) = facts.tools
    assert tool.name == "run_build" and tool.origin == "typescript"
    assert {p.name: p.type for p in tool.params} == {"command": "string", "retries": "number"}


def test_two_tools_are_both_found():
    facts = parse(
        'server.tool("a", "first", { x: z.string() }, async () => ({}));\n'
        'server.tool("b", "second", { y: z.string() }, async () => ({}));\n'
    )
    assert sorted(t.name for t in facts.tools) == ["a", "b"]


def test_tool_without_params_has_no_params():
    facts = parse('server.tool("ping", "Ping", async () => ({ content: [] }));\n')
    assert [t.name for t in facts.tools] == ["ping"] and facts.tools[0].params == []


def test_object_literal_tools_with_json_schema():
    facts = parse(
        "const tools = [\n"
        '  { name: "search", description: "Search", inputSchema: { type: "object",'
        ' properties: { query: { type: "string" } } } },\n'
        "];\n"
    )
    found = {t.name: t for t in facts.tools}
    assert "search" in found and [p.name for p in found["search"].params] == ["query"]


def test_lowlevel_call_tool_handler_defines_a_dispatch_span():
    facts = parse(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
        "  const { name } = request.params;\n"
        "  return { content: [] };\n"
        "});\n"
    )
    assert len(facts.dispatch_spans) == 1
    start, end = facts.dispatch_spans[0]
    assert end > start


# --- capabilities ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "capability"),
    [
        ('exec(cmd);', EXEC),
        ('execSync("ls");', EXEC),
        ('spawn("ls", []);', EXEC),
        ('child_process.exec(cmd);', EXEC),
        ('fs.readFileSync("a.txt");', FS_READ),
        ('fs.writeFileSync("a.txt", data);', FS_WRITE),
        ('await fetch("https://x.test");', NET),
        ('axios.get(url);', NET),
        ('const home = process.env.HOME;', ENV),
    ],
)
def test_sinks_map_to_capabilities(code, capability):
    assert capability in capabilities(parse(code + "\n"))


def test_no_sinks_means_no_calls():
    assert parse("const x = 1 + 2;\n").calls == []


def test_literal_arguments_are_collected_for_path_checks():
    facts = parse('fs.readFileSync("/home/u/.ssh/id_rsa", "utf-8");\n')
    call = next(c for c in facts.calls if c.capability == FS_READ)
    assert "/home/u/.ssh/id_rsa" in call.literal_args and call.touches_sensitive_path


def test_dynamic_evaluators_are_marked():
    facts = parse("const f = new Function(body);\neval(code);\n")
    assert any(c.dynamic_eval for c in facts.calls)


def test_commented_out_code_is_ignored():
    facts = parse("// exec(cmd)\n/* eval(code) */\nconst a = 1;\n")
    assert facts.calls == []


# --- taint (name-matched, lower confidence) ----------------------------------------------------


def test_a_tool_parameter_reaching_exec_is_a_flow():
    facts = parse(
        'server.tool("run", "Run", { command: z.string() }, async ({ command }) => {\n'
        "  exec(command);\n  return { content: [] };\n});\n"
    )
    assert facts.taint_flows
    flow = facts.taint_flows[0]
    assert flow.source == "command" and flow.sink.capability == EXEC and not flow.proven


def test_a_quoted_mention_is_not_a_flow():
    facts = parse(
        'server.tool("run", "Run", { command: z.string() }, async ({ command }) => {\n'
        '  exec("echo command");\n  return { content: [] };\n});\n'
    )
    assert facts.taint_flows == []


def test_an_unrelated_variable_is_not_a_flow():
    facts = parse(
        'server.tool("run", "Run", { command: z.string() }, async ({ command }) => {\n'
        '  const fixed = "ls";\n  exec(fixed);\n  return { content: [] };\n});\n'
    )
    assert facts.taint_flows == []


# --- logging, swallowed errors, servers, ports -------------------------------------------------


@pytest.mark.parametrize("call", ["console.log('x');", "logger.info('x');", "console.error(e);", "log.warn('x');"])
def test_log_calls_are_recorded(call):
    assert parse(call + "\n").log_calls


def test_no_logging_means_no_log_calls():
    assert parse("const a = 1;\n").log_calls == []


def test_empty_catch_blocks_are_swallowed_errors():
    facts = parse("try { run(); } catch (e) {}\ntry { run(); } catch {}\n")
    assert len(facts.swallowed_excepts) == 2 and all(kind == "catch" for _, kind in facts.swallowed_excepts)


def test_catch_that_handles_the_error_is_not_swallowed():
    assert parse("try { run(); } catch (e) { console.error(e); }\n").swallowed_excepts == []


def test_server_constructors_are_found():
    facts = parse_javascript("a.ts", HEADER + 'const other = new Server({ name: "second" });\n')
    assert len(facts.servers) == 2 and facts.servers[0].name == "demo"


def test_listen_and_port_values_are_collected():
    facts = parse("app.listen(8080);\nconst opts = { port: 9090 };\n")
    assert sorted(p for _, p in facts.ports) == [8080, 9090]


# --- external returns --------------------------------------------------------------------------


def test_fetched_content_returned_by_a_tool():
    facts = parse(
        'server.tool("get", "Get", { url: z.string() }, async ({ url }) => {\n'
        "  const res = await fetch(url);\n"
        "  return { content: [{ type: 'text', text: await res.text() }] };\n});\n"
    )
    assert facts.external_returns


def test_environment_returned_by_a_tool():
    facts = parse(
        'server.tool("env", "Env", async () => {\n'
        "  return { content: [{ type: 'text', text: JSON.stringify(process.env) }] };\n});\n"
    )
    assert facts.external_returns


def test_a_constant_return_is_not_external():
    facts = parse(
        'server.tool("hi", "Hi", async () => {\n  return { content: [{ type: "text", text: "hi" }] };\n});\n'
    )
    assert facts.external_returns == []


# --- robustness --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    ["", "{", "server.tool(", 'server.tool("a", "b", {', "((((((", "`unterminated template", "/* never closed"],
)
def test_malformed_input_never_raises(source):
    parse_javascript("a.ts", source)


# --- entropy helpers ---------------------------------------------------------------------------


def test_entropy_separates_random_tokens_from_words():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("Zk39fQ81xyzLmN04pQrS7tUv") > 4.0
    assert shannon_entropy("changeme") < 3.0


@pytest.mark.parametrize(
    "value",
    ["", "   ", "changeme", "your-api-key-here", "${API_KEY}", "{{ secret }}", "<token>", "xxxxxxxx",
     "aaaaaaaa", "placeholder", "REPLACE_ME", "todo", "os.environ['X']", "process.env.X", "dummy-value", "n/a"],
)
def test_placeholders_are_recognised(value):
    assert looks_like_placeholder(value)


@pytest.mark.parametrize("value", ["Zk39fQ81xyzLmN04pQrS7tUv", "sk-live-9fA3kL0pQ2sT4uV6", "hunter2hunter3"])
def test_real_looking_values_are_not_placeholders(value):
    assert not looks_like_placeholder(value)


def test_redact_keeps_a_short_prefix_and_never_the_rest():
    secret = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5"
    shown = redact(secret)
    assert shown.startswith("sk-a") and secret[8:] not in shown and "*" in shown
    assert redact("abc") == "***" and redact("") == ""
    assert len(redact("x" * 100)) <= 4 + 20
