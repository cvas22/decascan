# Rules

Every rule maps to a risk in the OWASP MCP Top 10 (v0.1) and carries a CWE id and a confidence
score. Confidence below 1.0 means the rule matches a *pattern* that is usually a vulnerability, not
a proof of one — read the finding before you act on it.

Suppress a reviewed finding with `mcpcheck:ignore` on the offending line.

---

## MCP01 — Token Mismanagement & Secret Exposure

### MCP01-001 — Hardcoded credential
**Severity:** CRITICAL (HIGH for generic matches; LOW in `.example`/`.sample`/template files)
**CWE:** CWE-798, CWE-321

Fires when a credential is committed to config or source. Two detectors:

- **Provider-shaped tokens** match on structure — Anthropic (`sk-ant-`), OpenAI, GitHub (`ghp_`,
  `github_pat_`), AWS (`AKIA`), Slack (`xox*`), Google (`AIza`), GitLab, Stripe, Hugging Face, npm,
  and PEM private key blocks. A structural match is a finding on its own.
- **Generic assignments** (`api_key = "..."`, `"token": "..."`) must additionally clear a Shannon
  entropy floor of 3.2 bits/char and survive a placeholder check, so `password = "changeme"` and
  `API_KEY="${YOUR_KEY}"` do not fire.

Secrets are redacted in every output format, including SARIF. A scanner that leaks the secret into
CI logs while reporting it has made the problem worse.

**Fix:** revoke and rotate — removing the line does not un-leak it — then load from the environment
or a secret manager.

### MCP01-002 — Credential accepted as tool input
**Severity:** MEDIUM · **CWE:** CWE-522

A tool declares `api_key`, `token`, `password`, `client_secret` (etc.) as an input parameter. For
the model to call it, the secret must be present in the conversation context: sent to the model
provider, retained in transcripts, and readable by anything else with access to that context.

**Fix:** the server should hold its own credentials and read them at call time. Never ask the LLM
for one.

---

## MCP02 — Privilege Escalation via Scope Creep

### MCP02-001 — Capability exceeds declared scope
**Severity:** CRITICAL (`exec`) / HIGH (`fs:write`, `net`) / MEDIUM (`env`) · **CWE:** CWE-269

Diffs the scopes a manifest *declares* against the capabilities the code actually exercises. A
server that declares `read:files` and calls `subprocess.run` is a privilege escalation regardless of
intent: the client granted access on the strength of a claim the implementation does not honour.

Capabilities are `fs:read`, `fs:write`, `net`, `exec`, `env`. Scope strings are matched
case-insensitively across the common spellings (`read:files`, `files:read`, `filesystem:read`, …); a
wildcard scope (`*`, `all`, `admin`) grants everything and silences the rule.

Capabilities are attributed to the tool whose handler span contains the call, so the finding names
the tool, not just the file.

### MCP02-002 — No scopes declared
**Severity:** INFO · **CWE:** CWE-1220

A manifest exposes tools but declares no scopes, so there is nothing to diff against and a client
has no basis on which to decide what it is granting.

---

## MCP03 — Tool Poisoning

### MCP03-001 — Unconstrained input reaches a dangerous sink
**Severity:** CRITICAL (shell or eval) / HIGH · **CWE:** CWE-78, CWE-94

A tool declares an unconstrained string parameter — no `enum`, no `pattern`, no allowlist — and its
handler reaches a shell or an evaluator. Anything that can influence the model's tool call (a
poisoned document, a fetched web page, a hostile file in the workspace) can then choose what runs.

**Where a shell (`shell=True`, `child_process.exec`) or an evaluator (`eval`, `new Function`) is
involved, *any* free-form string parameter fires the rule** — `grep {pattern}` is exactly as
exploitable as `{command}`, and gating on the parameter's name would miss it. A dangerous-sounding
name (`command`, `path`, `query`, `code`, `url`, …) raises confidence from 75% to 90% rather than
deciding whether to report at all. For argv-style execution (`subprocess.run([...])`,
`execFile`) — which does not re-interpret its arguments — the name is still the signal, so only
risky-named parameters fire, at HIGH.

Sinks are matched inside the tool's own handler, or inside the `@server.call_tool()` dispatcher for
low-level servers that implement every tool in one function.

**This is a co-location check, not taint analysis.** The rule proves the parameter and the sink live
in the same handler, not that the value flows from one to the other. Real dataflow lands with MCP05.

### MCP03-002 — Open tool input schema
**Severity:** MEDIUM · **CWE:** CWE-20

The input schema does not set `additionalProperties: false`, so a caller can attach fields the
handler never validates.

### MCP03-003 — Risky parameter without validation
**Severity:** MEDIUM · **CWE:** CWE-20

A dangerously-named string parameter has no `enum`, `pattern`, or `maxLength`. Suppressed when
MCP03-001 already reports the same tool with more force.

### MCP03-004 — Tool declared without an input schema
**Severity:** MEDIUM · **CWE:** CWE-20

A manifest declares a tool with no `inputSchema` at all.

---

## MCP07 — Insufficient Authentication & Authorization

### MCP07-001 — Network-exposed server without authentication
**Severity:** CRITICAL · **CWE:** CWE-306

An MCP server reachable over the network — an HTTP/SSE transport, or a bound port — declares no
authentication. Anything that can reach the port can call every tool it exposes, with the server's
own filesystem and network privileges.

**This rule is deliberately silent on stdio servers.** A stdio server is spawned as a subprocess by
its client and speaks over pipes; it has no socket, and demanding an auth block there would be noise
that teaches people to ignore the tool.

### MCP07-002 — Wildcard CORS origin
**Severity:** HIGH · **CWE:** CWE-942

`allowOrigin: "*"` in the manifest, or a wildcard CORS middleware / `Access-Control-Allow-Origin: *`
header in code. Any web page the user visits can then reach the server from their browser.

---

## MCP09 — Shadow MCP Servers

### MCP09-001 — Multiple server instantiations
**Severity:** HIGH · **CWE:** CWE-1059

More than one MCP server is constructed in the codebase. The primary server is identified by name
match against a manifest, then by manifest entrypoint; every other one is reported. Shadow servers
expose tools under the same privileges, typically without the auth, logging, or scope review the
primary server received.

### MCP09-002 — Undeclared listening port
**Severity:** HIGH · **CWE:** CWE-1059

Code binds a port that appears in no manifest. An operator reading the manifest does not know the
listener exists, so it will not be firewalled, monitored, or reviewed.

---

## Not yet implemented

MCP04 (supply chain), MCP05 (command injection with dataflow), MCP06 (prompt injection), MCP08
(audit logging), MCP10 (context over-sharing). See the README for the roadmap.
