# Rules

The first part covers the OWASP MCP Top 10 (v0.1); the Top 10 for LLM Applications (2025) and the web
Top 10 (2021) follow. Every rule maps to a risk in exactly one of the lists and carries a CWE id and a confidence
score. Confidence below 1.0 means the rule matches a *pattern* that is usually a vulnerability, not
a proof of one — read the finding before you act on it.

Suppress a reviewed finding with `mcp-sift:ignore` on the offending line.

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

## MCP04 — Supply Chain / Dependency Tampering

Parsed from `requirements.txt`, `pyproject.toml` (PEP 621 and Poetry), and `package.json`. A local
path dependency that is the project itself (`-e .`) is not reported.

### MCP04-001 — Dependency from a non-registry source
**Severity:** HIGH (git/URL) / MEDIUM (path) · **CWE:** CWE-829

A package is installed from a git ref, a URL, or a local path rather than an immutable registry
release. A published release has a hash behind it; a branch or tag is a moving target that can change
between review and install with no change to the reference in the file.

**Fix:** depend on a published release and pin it. If a git source is unavoidable, pin the full
commit SHA — a tag can be moved, a SHA cannot.

### MCP04-002 — Floating dependencies with no lockfile
**Severity:** MEDIUM · **CWE:** CWE-1357

Registry dependencies are declared as ranges and no lockfile in the repository records what those
ranges resolved to. Two installs can ship different code, and a compromised transitive release lands
silently. Silenced entirely when any lockfile (`uv.lock`, `poetry.lock`, `package-lock.json`, …) is
present, since the lockfile is the record.

### MCP04-003 — Code executes at install time
**Severity:** HIGH · **CWE:** CWE-829

An npm `preinstall`/`install`/`postinstall`/`prepare` script runs on every install, with the
installing user's privileges, before anyone reads the package. Install hooks are the standard
delivery mechanism for a compromised npm package.

---

## MCP05 — Command Injection & Execution

Where MCP03-001 reports a dangerous parameter and a dangerous sink *in the same handler*, MCP05 only
fires when a tool parameter **demonstrably reaches** the sink. **Python is tracked with a real AST**
— the value is followed through assignments, f-strings, `%`, `.format()`, `.join()`, and
concatenation into the sink (`proven=true`, high confidence). **TS/JS is a name match** inside the
sink's arguments — reported, but at lower confidence and marked `proven=false`, because the lexical
parser cannot follow assignments. The analysis is intraprocedural, so it under-reports rather than
over-reports. A parameter constrained to an `enum`/`Literal` is an allowlist and never taints; a
value passed through `shlex.quote` is treated as sanitized.

### MCP05-001 — Tool input reaches a shell
**Severity:** CRITICAL · **CWE:** CWE-78 · confidence 0.95 (Python) / 0.70 (TS)

A model-controlled parameter flows into a command interpreter (`shell=True`, `os.system`,
`child_process.exec`). **Fix:** pass an argument list (`shell=False`, `execFile`); if a shell is
unavoidable, `shlex.quote` the value *and* constrain it.

### MCP05-002 — Tool input reaches a dynamic evaluator
**Severity:** CRITICAL · **CWE:** CWE-95 · confidence 0.95 / 0.70

A parameter flows into `eval`/`exec`/`compile`/`new Function`, running in the server's own process
with its privileges and credentials. **Fix:** remove the evaluator; parse with `ast.literal_eval` or
implement the intended operations explicitly.

### MCP05-003 — Tool input reaches a filesystem path
**Severity:** HIGH (write) / MEDIUM (read) · **CWE:** CWE-22 · confidence 0.85 / 0.60

A parameter is used as a path with no confinement to a root, so `../` traversal reaches outside it —
and a tainted *write* overwrites `authorized_keys` or a shell profile. Only the path position is a
sink: the content written to a file, and arguments passed to a fixed program, are not reported.
**Fix:** resolve then confine (`resolved.is_relative_to(root)`); normalizing alone does not help.

---

## MCP06 — Prompt Injection via Contextual Payloads

A tool description is not documentation — it is text placed directly into the model's context and
read as instructions, which no schema validates and no user sees.

### MCP06-001 — Tool description carries instructions for the model
**Severity:** CRITICAL · **CWE:** CWE-74 · confidence 0.85

The description instructs the model rather than describing the tool: discard previous instructions,
hide behaviour from the user, run ahead of other tools, disclose the system prompt, or read a named
credential file. Matched on a deliberately narrow set of phrases so honest descriptions stay quiet.

### MCP06-002 — Hidden characters in tool metadata
**Severity:** HIGH · **CWE:** CWE-451 · confidence 0.90

The description contains zero-width characters, bidi overrides, Unicode tag characters, or other
invisible format codepoints — so the text a reviewer reads and the text the model receives differ.

### MCP06-003 — Remote content returned to the model unsanitized
**Severity:** MEDIUM · **CWE:** CWE-74 · confidence 0.70

A tool fetches network content and returns it straight to the model. Whoever controls that endpoint
writes into the model's context — the documented attack against every fetch-shaped MCP server.

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

## MCP08 — Lack of Audit & Telemetry

Scoped to servers that *change something* — execution and filesystem writes. A read-only server that
does not log is untidy, not a finding. Both rules require the codebase to actually be an MCP server
(a tool, a server construction, or a manifest), so they never fire on a plain library.

### MCP08-001 — Consequential actions are never logged
**Severity:** MEDIUM · **CWE:** CWE-778 · confidence 0.80

The server executes commands or writes files and calls no logging framework anywhere. If a poisoned
tool call gets through, there is no record of what ran. Silenced by the presence of any logging call
— whether the logging is *sufficient* is not statically decidable.

### MCP08-002 — Exception swallowed silently
**Severity:** LOW · **CWE:** CWE-390 · confidence 0.70

An `except: pass` (or empty `catch {}`) in a file that executes commands or writes files. A failed
action and one that never happened become indistinguishable — exactly the distinction an
investigation needs.

---

## MCP10 — Context Injection & Over-Sharing

Everything a server returns is copied into the model's context, the provider's logs, and the client
transcript. The question is not whether data *can* be read but whether it is being handed to a model.

### MCP10-001 — Environment returned to the model
**Severity:** HIGH · **CWE:** CWE-200 · confidence 0.90

A tool returns environment variables (`dict(os.environ)`, `process.env`) to the model — where the API
keys, database URLs, and cloud credentials live. **Fix:** return only named, non-secret keys, and
rotate anything already exposed.

### MCP10-002 — Credential file within reach of a tool
**Severity:** HIGH · **CWE:** CWE-538 · confidence 0.85

Code reads or writes a path containing SSH keys, cloud credentials, `.netrc`, `/etc/shadow`, or
similar — credentials for systems outside the server's remit, one tool response from a context
window.

### MCP10-003 — Tool operates on a filesystem root
**Severity:** MEDIUM · **CWE:** CWE-668 · confidence 0.70

A file operation is rooted at `/`, a home directory, or a drive root, so the tool's real scope is
everything the user owns. **Fix:** root at the narrowest directory that works, from configuration,
and confine every resolved path to it.

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

<!-- generated: rules for the LLM and web Top 10 lists (scripts/generate_rule_docs.py) -->

---

# OWASP Top 10 for LLM Applications (2025)

Pattern-based rules: a regex finds the sink, a balanced-parenthesis walk reads its
arguments, and a one-hop pass marks request-derived names. Comments and docstrings are
blanked first, and test directories are skipped. Confidence is below 1.0 throughout,
and the examples below are the scanner's own test samples.

## LLM01 — Prompt Injection

### LLM01-001 — Variable data interpolated into the system prompt
**Severity:** MEDIUM to HIGH, depending on context · **CWE:** CWE-77 · **Confidence:** 0.50-0.70

A system message is built with an f-string, .format() or concatenation.

**Fires on:** `m = [{"role": "system", "content": f"Be nice to {user}"}]`; `m = [{"role": "system", "content": "Hi {}".format(name)}]`

**Stays quiet on:** `m = [{"role": "system", "content": "You are helpful."}]`; `m = [{"role": "user", "content": f"hi {user}"}]`

**Fix:** Keep the system prompt a constant. Pass variable data in a separate user message, clearly delimited, and treat it as untrusted input.

## LLM02 — Sensitive Information Disclosure

### LLM02-001 — Secret interpolated into a prompt
**Severity:** HIGH · **CWE:** CWE-200 · **Confidence:** 0.65

An environment variable, key or password is formatted into text sent to the model.

**Fires on:** `prompt = f"Use {os.environ['TOKEN']} to call the API"`; `const prompt = 'key is ${process.env.SECRET}';`

**Stays quiet on:** `prompt = f"Summarise {text}"`

**Fix:** Never put credentials in model input. Hold them in the tool or backend that needs them and give the model an opaque handle instead.

## LLM03 — Supply Chain

### LLM03-001 — Model or dataset code executed from a remote repository
**Severity:** HIGH · **CWE:** CWE-94 · **Confidence:** 0.95

`trust_remote_code=True` runs Python shipped inside the model repository.

**Fires on:** `AutoModel.from_pretrained("o/m", trust_remote_code=True)`

**Stays quiet on:** `AutoModel.from_pretrained("o/m", trust_remote_code=False)`

**Fix:** Drop the flag and use a natively supported architecture, or vendor the reviewed modeling code and pin the repository to a commit SHA.

### LLM03-002 — Model weights loaded through pickle
**Severity:** HIGH · **CWE:** CWE-502 · **Confidence:** 0.80

`torch.load` / `joblib.load` without `weights_only=True` can execute code.

**Fires on:** `w = torch.load("m.bin")`; `w = joblib.load("m.pkl")`

**Stays quiet on:** `w = torch.load("m.bin", weights_only=True)`

**Fix:** Use `torch.load(..., weights_only=True)` or the safetensors format, and only load artifacts whose provenance and hash you have verified.

### LLM03-003 — Model downloaded without a pinned revision
**Severity:** LOW · **CWE:** CWE-829 · **Confidence:** 0.60

`from_pretrained` / `hf_hub_download` with no `revision=` follows a moving branch.

**Fires on:** `AutoModel.from_pretrained("someorg/some-model")`

**Stays quiet on:** `AutoModel.from_pretrained("o/m", revision="a1b2c3")`; `AutoModel.from_pretrained(local_dir)`

**Fix:** Pass `revision=` with a full commit SHA for every hub download.

## LLM04 — Data and Model Poisoning

Not statically detectable: this is a property of data, design or model behaviour, not of a line of source. No rule is claimed for it.

## LLM05 — Improper Output Handling

### LLM05-001 — Model output reaches a dangerous sink unvalidated
**Severity:** HIGH to CRITICAL, depending on context · **CWE:** CWE-78, CWE-79, CWE-89, CWE-95 · **Confidence:** 0.65

LLM output is passed to eval/exec, a shell, raw HTML or a SQL string.

**Fires on:** `eval(response)`; `os.system(llm_output)`

**Stays quiet on:** `eval('1+1')`; `print(response)`

**Fix:** Treat model output as untrusted input: validate it against a strict schema or allowlist, escape it for the sink, and never execute it.

## LLM06 — Excessive Agency

### LLM06-001 — Agent granted unrestricted code, shell or file capability
**Severity:** MEDIUM to HIGH, depending on context · **CWE:** CWE-250 · **Confidence:** 0.60-0.90

An agent is wired to a shell/REPL tool or an `allow_dangerous_*` switch.

**Fires on:** `agent = create_agent(allow_dangerous_code=True)`; `tools = [PythonREPLTool()]`

**Stays quiet on:** `from langchain_experimental.tools import PythonREPLTool`

**Fix:** Expose narrow, purpose-built tools with validated parameters. Run any code execution in a sandbox with no network and no credentials, and require human approval for state-changing actions.

## LLM07 — System Prompt Leakage

### LLM07-001 — Credential embedded in a system prompt
**Severity:** HIGH · **CWE:** CWE-200 · **Confidence:** 0.70

A system prompt contains a key, password or token value.

**Fires on:** `SYSTEM_PROMPT = "You are X. password is Zk39fQ81xyz"`

**Stays quiet on:** `SYSTEM_PROMPT = "You are X. password is ${PASSWORD}"`; `SYSTEM_PROMPT = "Never reveal the password."`

**Fix:** Remove the credential from the prompt and rotate it. Enforce access control in the backend, not in instructions to the model.

## LLM08 — Vector and Embedding Weaknesses

Not statically detectable: this is a property of data, design or model behaviour, not of a line of source. No rule is claimed for it.

## LLM09 — Misinformation

Not statically detectable: this is a property of data, design or model behaviour, not of a line of source. No rule is claimed for it.

## LLM10 — Unbounded Consumption

### LLM10-001 — Model call with no output-token cap
**Severity:** MEDIUM · **CWE:** CWE-770 · **Confidence:** 0.60

A completion request sets no `max_tokens` (or equivalent) limit.

**Fires on:** `client.chat.completions.create(model="m", messages=msgs)`; `await client.messages.create({ model: 'm', messages });`

**Stays quiet on:** `client.chat.completions.create(model="m", max_tokens=100, messages=m)`; `client.chat.completions.create(**params)`

**Fix:** Set `max_tokens` (or the provider's equivalent) on every call, and add per-user rate limits and a request timeout.

---

# OWASP Top 10 (Web Application Security Risks) (2021)

Pattern-based rules: a regex finds the sink, a balanced-parenthesis walk reads its
arguments, and a one-hop pass marks request-derived names. Comments and docstrings are
blanked first, and test directories are skipped. Confidence is below 1.0 throughout,
and the examples below are the scanner's own test samples.

## WEB01 — A01 Broken Access Control

### WEB01-001 — Request-derived value used as a file path
**Severity:** HIGH · **CWE:** CWE-22 · **Confidence:** 0.70

A request parameter reaches a file open/send call (path traversal).

**Fires on:** `return send_file(request.args["f"])`; `fs.readFile(req.query.file, cb);`

**Stays quiet on:** `open("config.yaml")`

**Fix:** Resolve the final path and check it stays inside the allowed base directory (`Path.resolve().is_relative_to(base)`), or map opaque ids to files server-side.

### WEB01-002 — CORS allows every origin together with credentials
**Severity:** HIGH · **CWE:** CWE-942 · **Confidence:** 0.75

A wildcard origin is combined with credentialed requests.

**Fires on:** `CORS(app, allow_origins=['*'], allow_credentials=True)`

**Stays quiet on:** `CORS(app, allow_origins=['https://a.example'], allow_credentials=True)`; `CORS(app, allow_origins=['*'])`

**Fix:** List the exact trusted origins; never combine a wildcard with credentials.

### WEB01-003 — CSRF protection disabled
**Severity:** MEDIUM · **CWE:** CWE-352 · **Confidence:** 0.70

A view or the whole app opts out of CSRF checks.

**Fires on:** `@csrf_exempt def view(request): ...`; `WTF_CSRF_ENABLED = False`

**Stays quiet on:** `csrf = CSRFProtect(app)`

**Fix:** Keep CSRF protection on. If an endpoint is a token-authenticated API, say so in a comment and make sure it does not also accept cookie authentication.

## WEB02 — A02 Cryptographic Failures

### WEB02-001 — Broken hash algorithm (MD5 / SHA-1)
**Severity:** MEDIUM · **CWE:** CWE-327 · **Confidence:** 0.60

MD5 or SHA-1 is used; both are collision-broken and far too fast for passwords.

**Fires on:** `digest = hashlib.sha1(data).hexdigest()`; `const h = crypto.createHash('md5');`

**Stays quiet on:** `hashlib.md5(data, usedforsecurity=False)`; `hashlib.sha256(data)`

**Fix:** Use SHA-256 or better for integrity, and a password hash (argon2id, scrypt or bcrypt) for credentials. For a non-security checksum, pass `usedforsecurity=False`.

### WEB02-002 — TLS certificate verification disabled
**Severity:** HIGH · **CWE:** CWE-295 · **Confidence:** 0.90

Certificate or hostname checking is turned off for an outbound connection.

**Fires on:** `requests.get(url, verify=False)`; `const agent = new https.Agent({ rejectUnauthorized: false });`

**Stays quiet on:** `requests.get(url, verify=True)`

**Fix:** Remove the override. If you need a private CA, point `verify=` / `ca` at its bundle instead of turning verification off.

### WEB02-003 — Weak or deprecated cipher
**Severity:** HIGH · **CWE:** CWE-327 · **Confidence:** 0.80

ECB mode, DES/3DES, RC4 or the deprecated `createCipher` is used.

**Fires on:** `c = AES.new(k, AES.MODE_ECB)`; `c = DES.new(k)`

**Stays quiet on:** `c = AES.new(k, AES.MODE_GCM)`

**Fix:** Use AES-GCM or ChaCha20-Poly1305 through a vetted library, with a fresh nonce.

### WEB02-004 — Non-cryptographic random for a security value
**Severity:** MEDIUM · **CWE:** CWE-338 · **Confidence:** 0.70

`random` / `Math.random` generates something named like a token, key or nonce.

**Fires on:** `session_token = random.randint(0, 10**9)`; `const nonce = Math.random();`

**Stays quiet on:** `color = random.choice(palette)`; `token = secrets.token_hex(16)`

**Fix:** Use `secrets` (Python) or `crypto.randomBytes` / `crypto.randomUUID` (Node).

## WEB03 — A03 Injection

### WEB03-001 — SQL built by string formatting
**Severity:** HIGH · **CWE:** CWE-89 · **Confidence:** 0.70

A query is assembled with f-strings, %, .format() or concatenation.

**Fires on:** `cur.execute(f"SELECT * FROM t WHERE id={i}")`; `cur.execute("SELECT * FROM t WHERE id=%s" % i)`

**Stays quiet on:** `cur.execute("SELECT * FROM t WHERE id = ?", (i,))`

**Fix:** Use parameterized queries (`cursor.execute(sql, params)`, `?`/`%s` placeholders) or the ORM's query builder. Allowlist anything that cannot be bound, such as a column name.

### WEB03-002 — OS command built from variable data
**Severity:** HIGH to CRITICAL, depending on context · **CWE:** CWE-78 · **Confidence:** 0.65-0.85

A shell command is assembled at runtime or run with shell=True.

**Fires on:** `os.system("ping " + host)`; `subprocess.run(f"ls {d}", shell=True)`

**Stays quiet on:** `subprocess.run(["ls", "-l"])`; `os.system("make build")`

**Fix:** Pass an argument list without a shell (`subprocess.run([...])`, `execFile`) and validate each argument against an allowlist.

### WEB03-003 — eval/exec on a non-literal
**Severity:** HIGH · **CWE:** CWE-95 · **Confidence:** 0.60

`eval`, `exec` or `new Function` runs a runtime-built string as code.

**Fires on:** `eval(expr)`; `exec(code)`

**Stays quiet on:** `ast.literal_eval(s)`; `eval("1 + 1")`

**Fix:** Replace it with a parser or lookup table (`ast.literal_eval`, `json.loads`, a dispatch dict). If evaluation is truly needed, sandbox it out of process.

### WEB03-004 — Unescaped output sink (XSS / template injection)
**Severity:** MEDIUM · **CWE:** CWE-1336, CWE-79 · **Confidence:** 0.50

Variable data is written as raw HTML or into a template string.

**Fires on:** `el.innerHTML = userHtml;`; `document.write(data);`

**Stays quiet on:** `el.textContent = userText;`; `el.innerHTML = '<b>static</b>';`

**Fix:** Output through the framework's auto-escaping (`textContent`, JSX expressions, `render_template` with a file). If HTML is required, sanitize it first (DOMPurify, bleach).

## WEB04 — A04 Insecure Design

Not statically detectable: this is a property of data, design or model behaviour, not of a line of source. No rule is claimed for it.

## WEB05 — A05 Security Misconfiguration

### WEB05-001 — Debug mode enabled
**Severity:** HIGH · **CWE:** CWE-489 · **Confidence:** 0.80

The framework's debugger / debug pages are switched on in code.

**Fires on:** `app.run(host='0.0.0.0', debug=True)`; `DEBUG = True`

**Stays quiet on:** `app.run(debug=False)`

**Fix:** Read the flag from the environment and default it to off; never ship `debug=True`.

### WEB05-002 — Insecure framework setting
**Severity:** MEDIUM to HIGH, depending on context · **CWE:** CWE-16, CWE-611, CWE-614 · **Confidence:** 0.80

Wildcard allowed hosts, insecure cookie flags, or XML external entities enabled.

**Fires on:** `ALLOWED_HOSTS = ['*']`; `SESSION_COOKIE_SECURE = False`

**Stays quiet on:** `ALLOWED_HOSTS = ['example.com']`

**Fix:** Set ALLOWED_HOSTS to the real hostnames.

## WEB06 — A06 Vulnerable and Outdated Components

Not statically detectable: this is a property of data, design or model behaviour, not of a line of source. No rule is claimed for it.
Use pip-audit or osv-scanner for known-vulnerable dependencies.

## WEB07 — A07 Identification and Authentication Failures

### WEB07-001 — JWT verification weakened or disabled
**Severity:** CRITICAL · **CWE:** CWE-347 · **Confidence:** 0.90

Signature, expiry or audience checks are turned off, or the `none` algorithm is allowed.

**Fires on:** `jwt.decode(t, k, options={'verify_signature': False})`; `jwt.decode(t, k, algorithms=['none'])`

**Stays quiet on:** `jwt.decode(t, k, algorithms=['HS256'])`

**Fix:** Always verify the signature with a pinned algorithm list, and keep exp/aud validation enabled.

### WEB07-002 — Hard-coded application secret or password
**Severity:** HIGH · **CWE:** CWE-798 · **Confidence:** 0.85

A SECRET_KEY, JWT secret or password is a string literal in source.

**Fires on:** `SECRET_KEY = "Zk39fQ81-live-signing-key"`; `DB_PASSWORD = "s3cretPassw0rd!x"`

**Stays quiet on:** `SECRET_KEY = os.environ["SECRET_KEY"]`; `SECRET_KEY = "changeme"`

**Fix:** Rotate it, then load it from the environment or a secret manager. Commit only a placeholder in `.env.example`.

## WEB08 — A08 Software and Data Integrity Failures

### WEB08-001 — Unsafe deserialization
**Severity:** HIGH · **CWE:** CWE-502 · **Confidence:** 0.60

pickle/marshal/yaml.load or a similar deserializer is applied to data.

**Fires on:** `obj = pickle.loads(blob)`; `cfg = yaml.load(text)`

**Stays quiet on:** `cfg = yaml.load(text, Loader=yaml.SafeLoader)`; `cfg = yaml.safe_load(text)`

**Fix:** Use a data-only format (JSON, `yaml.safe_load`, protobuf). If pickle is unavoidable, sign the payload and verify it before loading.

### WEB08-002 — Remote script piped straight to a shell
**Severity:** MEDIUM · **CWE:** CWE-494 · **Confidence:** 0.80

`curl ... | sh` runs unverified code fetched at execution time.

**Fires on:** `curl -sSL https://x.example/i.sh | sh`; `wget -qO- https://x.example/i.sh | sudo bash`

**Stays quiet on:** `curl -sSL https://x.example/i.sh -o i.sh`

**Fix:** Download to a file, verify a pinned checksum or signature, then execute it.

## WEB09 — A09 Security Logging and Monitoring Failures

### WEB09-001 — Sensitive value written to the log
**Severity:** MEDIUM · **CWE:** CWE-532 · **Confidence:** 0.65

A password, token or key is passed to a logging or print call.

**Fires on:** `logger.info(f"login {user} password {password}")`; `logger.debug("auth", token)`

**Stays quiet on:** `logger.info("login failed for user %s", user)`; `logger.warning("invalid token supplied")`

**Fix:** Log an identifier or a redacted form (`****1234`), never the value itself.

### WEB09-002 — Exception silently swallowed
**Severity:** LOW · **CWE:** CWE-390 · **Confidence:** 0.60

A broad `except: pass` / empty `catch {}` hides failures, including attacks.

**Fires on:** `try: x() except Exception: pass`; `try: x() except: pass`

**Stays quiet on:** `try: x() except ValueError: pass`; `try: x() except Exception as e: log(e)`

**Fix:** Catch the specific exception you expect, and log it (with context) at least once.

## WEB10 — A10 Server-Side Request Forgery

### WEB10-001 — Outbound request to a request-supplied URL
**Severity:** HIGH · **CWE:** CWE-918 · **Confidence:** 0.70

An HTTP client is called with a URL taken from the incoming request (SSRF).

**Fires on:** `requests.get(request.args["url"])`; `u = request.args["u"] httpx.get(u)`

**Stays quiet on:** `requests.get("https://api.example.com/data")`; `requests.get(CONFIG_URL)`

**Fix:** Accept only an allowlist of hosts or ids mapped server-side. Resolve and reject private, loopback and link-local addresses, and disable redirects.
