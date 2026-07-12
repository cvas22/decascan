# mcpaudit

**A security scanner for Model Context Protocol servers, mapped to the OWASP MCP Top 10.**

MCP servers run with the privileges of the developer who installed them: they read files, call
internal APIs, and execute commands on behalf of an LLM that anything in its context window can
influence. `mcpaudit` reads a server's manifest, config, and source and tells you where that trust
is misplaced — before you ship it.

No API key. No network calls. No account. `mcpaudit scan .` and you have your answer.

## Example run

A real scan of `tests/fixtures/vulnerable_ts` — a 30-line TypeScript MCP server. Nine findings in
under 10 ms. Reproduce it yourself with the command below; nothing here is mocked up.

```console
$ mcpaudit scan tests/fixtures/vulnerable_ts

 CRITICAL  MCP01 Token Mismanagement & Secret Exposure  [MCP01-001]
  GitHub token committed to source
  src/server.ts:11
  │ const GITHUB_TOKEN = "ghp_********************";
  A live-looking GitHub token appears in `src/server.ts`. Anything in the repository is
  readable by every developer, every CI job, and every MCP client that can read the
  workspace — treat this credential as compromised.
  Fix: Revoke and rotate the credential now — removing the line does not un-leak it. Load it
  from the environment instead (`os.environ[...]` / `process.env[...]`) and keep the value in
  a secret manager or an untracked `.env` file.
  CWE-798 · confidence 95%

 CRITICAL  MCP02 Privilege Escalation via Scope Creep  [MCP02-001]
  Tool `run_build` can execute shell commands or evaluate code, which `mcp.json` does not grant
  src/server.ts:16
  │ const output = exec(command);
  `exec` at src/server.ts:16 exercises the `exec` capability, but the declared server scopes
  ['read:files'] do not cover it. The client authorized this server on the strength of those
  scopes; the implementation quietly exceeds them.
  Fix: Either drop the `exec` operation, or declare the matching scope in `mcp.json` so the
  grant is honest — and expect clients to review it.
  CWE-269 · confidence 85%

 CRITICAL  MCP03 Tool Poisoning  [MCP03-001]
  Tool `run_build` accepts unvalidated `command` and executes it
  src/server.ts:16
  │ const output = exec(command);
  `run_build` declares `command` as an unconstrained string — no `enum`, no `pattern`, no
  allowlist — and its handler calls `exec` at src/server.ts:16 with `shell=True`. Anything
  that can influence the model's tool call (a poisoned document, a web page, a hostile file
  in the workspace) can choose what gets executed.
  Fix: Constrain `command` to an allowlist (`enum`, or a strict `pattern`) and pass arguments
  as a list rather than a shell string. If the tool genuinely needs to run arbitrary commands,
  that is a design decision the client must be able to see — say so in the tool description
  and require explicit approval.
  CWE-78 · confidence 90%

 CRITICAL  MCP07 Insufficient Authentication & Authorization  [MCP07-001]
  `mcp.json` exposes a network server with no authentication
  mcp.json:1
  This server is reachable over the network (it declares port 8080) and the manifest declares
  no authentication at all. Any process that can reach the port — another container, a
  colleague on the VPN, a browser page via DNS rebinding — can call every tool it exposes,
  with the server's own filesystem and network privileges.
  Fix: Require a bearer token or mTLS on the transport, bind to `127.0.0.1` rather than
  `0.0.0.0` if the server is only for local clients, and validate the token on every request
  — not just at connection setup.
  CWE-306 · confidence 90%

 HIGH  MCP09 Shadow MCP Servers  [MCP09-002]
  Port 9090 is bound in code but declared in no manifest
  src/server.ts:30
  │ httpServer.listen(9090);
  `src/server.ts` listens on port 9090, which appears in none of the 1 manifest(s) scanned
  (declared: [8080]). An operator reading the manifest has no idea this listener exists, so
  it will not be firewalled, monitored, or reviewed.
  Fix: Declare port 9090 in the manifest, or remove the listener. If it is a
  development-only endpoint, gate it behind an explicit environment flag that is off by
  default.
  CWE-1059 · confidence 70%

  [ 2 more HIGH (fs:write beyond scope, wildcard CORS) and 2 MEDIUM omitted here ]

Severity  Count
CRITICAL      4
HIGH          3
MEDIUM        2

9 finding(s) across 2 files (12 rules, 0.00s)
```

Four things that run demonstrates, in order of how much they matter:

- **The secret is redacted** (`ghp_********`). A scanner that echoes a live credential into your CI
  logs while reporting it has made the problem worse.
- **The scope diff is the check nobody else runs.** The manifest declares `read:files`; the code
  calls `exec()` and `fs.writeFileSync()`. The client granted access on the strength of that
  declaration and the implementation quietly exceeds it.
- **`run_build` is the one that gets you owned.** `command` is a bare `z.string()` landing in
  `exec()`. Anything that can influence the model's tool call chooses what runs on your machine.
- **Confidence is reported honestly** — 90% on the co-location check, 65% on the `path` heuristic —
  because one is near-certain and the other is a pattern that is only *usually* a problem.

By contrast, `mcpaudit scan tests/fixtures/clean_python` prints a green "No findings" and exits `0`,
and so do the real `mcp-server-fetch` and `mcp-server-time`.

## Install

```bash
pip install mcpaudit
```

## Use

```bash
mcpaudit scan ./server              # human-readable
mcpaudit scan ./server -o json      # for pipelines
mcpaudit scan ./server -o sarif -f results.sarif   # for GitHub Code Scanning
mcpaudit rules                      # what it checks and why
```

`mcpaudit scan` exits `1` when it finds something at or above `--fail-on` (default: `high`), so it
drops into CI unchanged:

```yaml
- run: pip install mcpaudit
- run: mcpaudit scan . --output sarif --output-file mcpaudit.sarif --no-fail
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpaudit.sarif
```

Suppress a finding you've reviewed by putting `mcpaudit:ignore` on the line.

## What v0.1 checks

Five of the ten OWASP MCP Top 10 risks — the five that are both high-signal and statically
decidable. The other five are on the roadmap below; this table is the honest scope.

| Risk | Rule | What fires |
|------|------|-----------|
| **MCP01** Token Mismanagement | `MCP01-001` | A credential is committed to config or source. Provider-shaped tokens (Anthropic, OpenAI, GitHub, AWS, Slack, Stripe, …) match on structure; anything else must clear a Shannon-entropy floor, so `password = "changeme"` doesn't fire. Secrets are redacted in every output format. |
| | `MCP01-002` | A tool takes `api_key` / `token` / `password` as an *input parameter* — which forces the secret through the model's context window and the provider's logs. |
| **MCP02** Scope Creep | `MCP02-001` | The code exercises a capability the manifest never declared a scope for. A tool that declares `read:files` and calls `subprocess.run` is a privilege escalation whether or not it's malicious: the client granted it on false pretenses. |
| | `MCP02-002` | A manifest exposes tools but declares no scopes at all, so there's nothing to diff against. |
| **MCP03** Tool Poisoning | `MCP03-001` | A free-form, dangerously-named parameter (`command`, `path`, `query`) reaches a handler that shells out or evaluates code. |
| | `MCP03-002` | An input schema permits `additionalProperties`, so callers can smuggle fields the handler never validates. |
| | `MCP03-003` | A risky parameter has no `enum`, `pattern`, or `maxLength`. |
| | `MCP03-004` | A tool is declared with no input schema at all. |
| **MCP07** Insufficient AuthN/AuthZ | `MCP07-001` | A **network-exposed** server (HTTP/SSE transport, or a bound port) declares no authentication. Deliberately silent on stdio servers — they're spawned as a subprocess by their client and have no socket to protect. |
| | `MCP07-002` | Wildcard CORS origin, in the manifest or in code. |
| **MCP09** Shadow Servers | `MCP09-001` | More than one MCP server is constructed in the codebase. The extra ones expose tools under the same privileges, usually without the review the primary server got. |
| | `MCP09-002` | Code binds a port that no manifest declares. |

Findings carry a CWE id and a confidence score, and every one of them tells you how to fix it.

## How it works, and where it stops

**Python is parsed with a real AST.** Callees are resolved through the import alias map, so
`import subprocess as sp; sp.run(...)` and `from subprocess import run; run(...)` both land on the
same capability. Tools are found in all three shapes the ecosystem actually uses: FastMCP
`@mcp.tool()` decorators, `types.Tool(inputSchema={...})` literals, and
`types.Tool(inputSchema=Model.model_json_schema())` — the pydantic form the official MCP servers
use, which is resolved back to the model's fields. Capabilities are attributed to the tool whose
handler span contains them, falling back to the `@server.call_tool()` dispatcher for low-level
servers that implement every tool in one function.

**TypeScript/JavaScript is parsed lexically, not with a real AST.** v0.1 deliberately avoids a
Node/`tsc` dependency so that `pip install mcpaudit` is the entire install story. The parser is
brace-aware — it pulls complete zod and JSON Schema literals out of source, and it understands both
the high-level `server.tool(name, schema, handler)` shape and the low-level
`setRequestHandler(CallToolRequestSchema, …)` dispatcher. **It will miss aliased imports and
computed names in a way the Python parser does not.** Moving TS to the TypeScript compiler API is
the top item for v0.2.

**There is no taint analysis.** MCP03-001 pairs a dangerous parameter with a dangerous sink in the
same handler; it does not prove the value flows from one to the other. That's a deliberate v0.1
tradeoff — it's why the rule reports 90% confidence rather than certainty. Full dataflow (and with
it, MCP05 Command Injection) needs a real IR.

**Not yet implemented:** MCP04 (supply chain), MCP05 (command injection with dataflow), MCP06
(prompt injection), MCP08 (audit logging), MCP10 (context over-sharing). No dynamic analysis: the
scanner never executes the server it's auditing.

## False positives

A security tool nobody trusts is a security tool nobody runs, so the rules are tuned to stay quiet:

- stdio servers are not nagged about authentication
- placeholders (`${API_KEY}`, `changeme`, `xxxx`) and `.env.example` files don't fire
- capabilities the manifest *does* grant are not reported
- a finding already reported with force by a precise rule isn't repeated by a vaguer one

`tests/fixtures/clean_python/` is a well-behaved server that must produce zero findings at MEDIUM or
above; a test enforces it. If a rule change lights it up, the change has a false-positive problem.

As a check against real code, v0.1 scans clean on the official `mcp-server-fetch` and
`mcp-server-time` — and does so *having actually read their schemas*, not by failing to parse them.
That's a sample of two, which is not a false-positive rate; measuring one properly across ~100
public servers is a v0.2 deliverable.

## Development

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
pytest
```

Rules live in `src/mcpaudit/rules/`, one module per OWASP risk. A rule is a function from a
`ScanContext` to `Finding`s, registered with a decorator — see `rules/base.py`. Parsers normalize
every language into the shared vocabulary in `parsers/common.py`, so rules never care whether a
server is Python or TypeScript.

## Status

v0.1, pre-release. Aligned to the OWASP MCP Top 10 v0.1 numbering. Not yet an OWASP project.

## License

Apache-2.0.
