"""OWASP Top 10 (2021) -- the classic web application risks, for Python and JS/TS source.

A04 (insecure design) and A06 (vulnerable components) are not here on purpose. One is a property of
the architecture; the other needs a vulnerability database, which this offline scanner does not
carry -- run pip-audit or osv-scanner for it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.entropy import looks_like_placeholder, redact, shannon_entropy
from ..core.findings import Finding, Severity
from ._scan import (
    call_args,
    calls,
    is_comment,
    is_dynamic_string,
    is_literal,
    is_tainted,
    line_of,
    line_text,
    make_finding,
    source_files,
    tainted_names,
)
from .base import rule

# --- A01 Broken Access Control -----------------------------------------------------------------

_FILE_SINK = re.compile(
    r"(?<![.\w])open\(|\bsend_file\(|\bsend_from_directory\(|\bFileResponse\(|\bos\.path\.join\(|"
    r"\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|sendFile|writeFile|writeFileSync)\(|"
    r"\bpath\.join\(|\bres\.download\("
)


@rule(
    id="WEB01-001",
    mcp_id="WEB01",
    name="Request-derived value used as a file path",
    description="A request parameter reaches a file open/send call (path traversal).",
)
def path_traversal(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for call in calls(src, _FILE_SINK):
            if not is_tainted(call.args, names):
                continue
            yield make_finding(
                rule_id="WEB01-001",
                risk_id="WEB01",
                severity=Severity.HIGH,
                title="Request input flows into a filesystem path",
                description=(
                    "A client-supplied value selects the file. With `../` sequences or an absolute "
                    "path the caller can read, or overwrite, files outside the intended directory."
                ),
                remediation=(
                    "Resolve the final path and check it stays inside the allowed base directory "
                    "(`Path.resolve().is_relative_to(base)`), or map opaque ids to files server-side."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-22",
                confidence=0.7,
            )


_CORS_WILDCARD = re.compile(
    r"(?:allow_origins|allowed_origins|origins?|CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)\s*[:=]\s*"
    r"(?:[\[\(]\s*)?(?:[\"'`]\*[\"'`]|True\b|true\b)"
)
_CORS_CREDENTIALS = re.compile(r"(?:allow_credentials|supports_credentials|credentials|CORS_ALLOW_CREDENTIALS)\s*[:=]\s*(?:True|true)\b")


@rule(
    id="WEB01-002",
    mcp_id="WEB01",
    name="CORS allows every origin together with credentials",
    description="A wildcard origin is combined with credentialed requests.",
)
def cors_credentials(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        wildcard = _CORS_WILDCARD.search(src.text)
        if not wildcard or not _CORS_CREDENTIALS.search(src.text):
            continue
        line_no = line_of(src.text, wildcard.start())
        yield make_finding(
            rule_id="WEB01-002",
            risk_id="WEB01",
            severity=Severity.HIGH,
            title="CORS: any origin may make credentialed requests",
            description=(
                "The server accepts cross-origin requests from every site and lets them carry "
                "cookies or auth headers. Any page a logged-in user visits can then act as them."
            ),
            remediation="List the exact trusted origins; never combine a wildcard with credentials.",
            path=src.path,
            line=line_no,
            source_line=line_text(src.text, line_no),
            cwe="CWE-942",
            confidence=0.75,
        )


_CSRF_OFF = re.compile(r"@csrf_exempt\b|\bWTF_CSRF_ENABLED\s*=\s*False\b|\bcsrf\s*[:=]\s*(?:False|false)\b|\bcsrf_protect\s*=\s*False\b")


@rule(
    id="WEB01-003",
    mcp_id="WEB01",
    name="CSRF protection disabled",
    description="A view or the whole app opts out of CSRF checks.",
)
def csrf_disabled(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _CSRF_OFF.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line):
                continue
            yield make_finding(
                rule_id="WEB01-003",
                risk_id="WEB01",
                severity=Severity.MEDIUM,
                title="CSRF protection is switched off",
                description=(
                    "State-changing requests are accepted without a CSRF token. A hostile page can "
                    "make a signed-in user's browser submit them."
                ),
                remediation=(
                    "Keep CSRF protection on. If an endpoint is a token-authenticated API, say so in a "
                    "comment and make sure it does not also accept cookie authentication."
                ),
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-352",
                confidence=0.7,
            )


# --- A02 Cryptographic Failures ----------------------------------------------------------------

_WEAK_HASH = re.compile(r"\bhashlib\.(?:md5|sha1)\(|\bcreateHash\(\s*[\"'](?:md5|sha1)[\"']\s*\)")
_PASSWORD_WORDS = re.compile(r"passw|pwd|credential", re.I)


@rule(
    id="WEB02-001",
    mcp_id="WEB02",
    name="Broken hash algorithm (MD5 / SHA-1)",
    description="MD5 or SHA-1 is used; both are collision-broken and far too fast for passwords.",
)
def weak_hash(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for call in calls(src, _WEAK_HASH):
            if "usedforsecurity=False" in call.args.replace(" ", ""):
                continue
            about_passwords = bool(_PASSWORD_WORDS.search(call.source_line))
            yield make_finding(
                rule_id="WEB02-001",
                risk_id="WEB02",
                severity=Severity.HIGH if about_passwords else Severity.MEDIUM,
                title="MD5/SHA-1 used" + (" for a password" if about_passwords else ""),
                description=(
                    "These digests are broken for collision resistance and can be computed billions "
                    "of times per second, so hashed passwords fall to brute force almost instantly."
                ),
                remediation=(
                    "Use SHA-256 or better for integrity, and a password hash (argon2id, scrypt or "
                    "bcrypt) for credentials. For a non-security checksum, pass "
                    "`usedforsecurity=False`."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-327",
                confidence=0.85 if about_passwords else 0.6,
            )


_TLS_OFF = re.compile(
    r"\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED[^\n]{0,400}[\"']?0|"
    r"\b_create_unverified_context\b|\bssl\.CERT_NONE\b|\bInsecureSkipVerify\b|\bcheck_hostname\s*=\s*False\b"
)


@rule(
    id="WEB02-002",
    mcp_id="WEB02",
    name="TLS certificate verification disabled",
    description="Certificate or hostname checking is turned off for an outbound connection.",
)
def tls_verification_off(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _TLS_OFF.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line):
                continue
            yield make_finding(
                rule_id="WEB02-002",
                risk_id="WEB02",
                severity=Severity.HIGH,
                title="TLS verification is disabled",
                description=(
                    "Without certificate validation any network attacker can impersonate the remote "
                    "host and read or alter everything sent over the 'secure' connection."
                ),
                remediation=(
                    "Remove the override. If you need a private CA, point `verify=` / `ca` at its "
                    "bundle instead of turning verification off."
                ),
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-295",
                confidence=0.9,
            )


_WEAK_CIPHER = re.compile(r"\bAES\.MODE_ECB\b|\bDES3?\.new\(|\bARC4\b|\bcreateCipher\(|[\"']aes-\d+-ecb[\"']|[\"']des(?:-ede3)?[\"']", re.I)


@rule(
    id="WEB02-003",
    mcp_id="WEB02",
    name="Weak or deprecated cipher",
    description="ECB mode, DES/3DES, RC4 or the deprecated `createCipher` is used.",
)
def weak_cipher(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _WEAK_CIPHER.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line):
                continue
            yield make_finding(
                rule_id="WEB02-003",
                risk_id="WEB02",
                severity=Severity.HIGH,
                title="Weak or deprecated encryption primitive",
                description=(
                    "ECB leaks plaintext structure, DES/3DES/RC4 are broken or sunset, and "
                    "`createCipher` derives keys without a salt."
                ),
                remediation="Use AES-GCM or ChaCha20-Poly1305 through a vetted library, with a fresh nonce.",
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-327",
                confidence=0.8,
            )


_INSECURE_RANDOM = re.compile(r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits)\(|\bMath\.random\(\)")
_SECURITY_WORDS = re.compile(r"token|secret|password|passwd|session|api_?key|nonce|otp|csrf|salt|reset", re.I)


@rule(
    id="WEB02-004",
    mcp_id="WEB02",
    name="Non-cryptographic random for a security value",
    description="`random` / `Math.random` generates something named like a token, key or nonce.",
)
def insecure_random(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _INSECURE_RANDOM.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line) or not _SECURITY_WORDS.search(line):
                continue
            yield make_finding(
                rule_id="WEB02-004",
                risk_id="WEB02",
                severity=Severity.MEDIUM,
                title="Predictable random number generator used for a security value",
                description=(
                    "Mersenne Twister and `Math.random` are predictable from a few outputs. A token or "
                    "key built from them can be guessed."
                ),
                remediation="Use `secrets` (Python) or `crypto.randomBytes` / `crypto.randomUUID` (Node).",
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-338",
                confidence=0.7,
            )


# --- A03 Injection -----------------------------------------------------------------------------

_SQL_SINK = re.compile(
    r"\.(?:execute|executemany|executescript|raw|queryRawUnsafe|\$queryRawUnsafe|\$executeRawUnsafe)\(|"
    r"(?<![\w])(?:cursor|conn|connection|db|pool|client)\.query\("
)


@rule(
    id="WEB03-001",
    mcp_id="WEB03",
    name="SQL built by string formatting",
    description="A query is assembled with f-strings, %, .format() or concatenation.",
)
def sql_injection(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for call in calls(src, _SQL_SINK):
            if not is_dynamic_string(call.args):
                continue
            from_request = is_tainted(call.args, names)
            yield make_finding(
                rule_id="WEB03-001",
                risk_id="WEB03",
                severity=Severity.CRITICAL if from_request else Severity.HIGH,
                title="SQL statement is assembled from variable data",
                description=(
                    "Values are formatted straight into the query text instead of being bound as "
                    "parameters, so a crafted value changes the statement itself."
                    + (" A request-derived value reaches it." if from_request else "")
                ),
                remediation=(
                    "Use parameterized queries (`cursor.execute(sql, params)`, `?`/`%s` placeholders) "
                    "or the ORM's query builder. Allowlist anything that cannot be bound, such as a "
                    "column name."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-89",
                confidence=0.85 if from_request else 0.7,
            )


_SHELL_SINK = re.compile(
    r"\bos\.(?:system|popen)\(|\bsubprocess\.(?:run|call|check_call|check_output|Popen)\(|"
    r"\b(?:execSync|spawnSync|exec|spawn)\("
)


@rule(
    id="WEB03-002",
    mcp_id="WEB03",
    name="OS command built from variable data",
    description="A shell command is assembled at runtime or run with shell=True.",
)
def command_injection(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for call in calls(src, _SHELL_SINK):
            if ".exec(" in call.source_line and not src.is_js:
                continue
            uses_shell = bool(re.search(r"shell\s*=\s*True", call.args)) or "os.system" in call.source_line or "os.popen" in call.source_line
            dynamic = is_dynamic_string(call.args)
            from_request = is_tainted(call.args, names)
            if not (from_request or (dynamic and (uses_shell or src.is_js))):
                continue
            yield make_finding(
                rule_id="WEB03-002",
                risk_id="WEB03",
                severity=Severity.CRITICAL if from_request else Severity.HIGH,
                title="Shell command is built from variable data",
                description=(
                    "The command line is a runtime string handed to a shell. Shell metacharacters in "
                    "any interpolated value become extra commands."
                ),
                remediation=(
                    "Pass an argument list without a shell (`subprocess.run([...])`, `execFile`) and "
                    "validate each argument against an allowlist."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-78",
                confidence=0.85 if from_request else 0.65,
            )


_EVAL = re.compile(r"(?<![.\w])eval\(|(?<![.\w])exec\(|\bnew Function\(")


def _function_body(args: str) -> str:
    """The last top-level argument of `new Function(p1, p2, body)`."""
    depth, last, quote = 0, 0, ""
    for i, ch in enumerate(args):
        if quote:
            if ch == quote and args[i - 1] != "\\":
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            last = i + 1
    return args[last:]


@rule(
    id="WEB03-003",
    mcp_id="WEB03",
    name="eval/exec on a non-literal",
    description="`eval`, `exec` or `new Function` runs a runtime-built string as code.",
)
def dynamic_code_execution(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for call in calls(src, _EVAL):
            checked = _function_body(call.args) if "new Function" in call.source_line else call.args
            if is_literal(checked) or not checked.strip():
                continue
            if src.is_js and "exec(" in call.source_line and "eval(" not in call.source_line and "Function" not in call.source_line:
                continue  # bare exec() in JS is child_process; WEB03-002 covers it
            from_request = is_tainted(call.args, names)
            yield make_finding(
                rule_id="WEB03-003",
                risk_id="WEB03",
                severity=Severity.CRITICAL if from_request else Severity.HIGH,
                title="Dynamic code execution",
                description=(
                    "A string built at runtime is executed as code. If any part of it is influenced "
                    "from outside, the attacker runs code in your process."
                ),
                remediation=(
                    "Replace it with a parser or lookup table (`ast.literal_eval`, `json.loads`, a "
                    "dispatch dict). If evaluation is truly needed, sandbox it out of process."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-95",
                confidence=0.85 if from_request else 0.6,
            )


_XSS_ASSIGN = re.compile(r"\b(?:innerHTML|outerHTML)\s*(?:\+)?=\s*(?!\s*[\"'`][^\"'`$]*[\"'`]\s*;?\s*$)[^\n]+|\bdocument\.write(?:ln)?\(")
_XSS_CALLS = re.compile(r"\bmark_safe\(|\bMarkup\(|\brender_template_string\(|\bdangerouslySetInnerHTML\b")


@rule(
    id="WEB03-004",
    mcp_id="WEB03",
    name="Unescaped output sink (XSS / template injection)",
    description="Variable data is written as raw HTML or into a template string.",
)
def xss(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for pattern in (_XSS_ASSIGN, _XSS_CALLS):
            for match in pattern.finditer(src.text):
                line_no = line_of(src.text, match.start())
                line = line_text(src.text, line_no)
                if is_comment(line):
                    continue
                if match.group(0).startswith("document.write") and is_literal(call_args(src.text, match.end())):
                    continue  # writing a fixed string is not an injection
                from_request = is_tainted(line, names)
                dynamic = (
                    pattern is _XSS_ASSIGN  # the regex already excluded plain-literal assignments
                    or is_dynamic_string(line)
                    or from_request
                    or "dangerouslySetInnerHTML" in line
                )
                if not dynamic:
                    continue
                template = "render_template_string" in line
                yield make_finding(
                    rule_id="WEB03-004",
                    risk_id="WEB03",
                    severity=Severity.HIGH if from_request else Severity.MEDIUM,
                    title="Server-side template injection" if template else "Raw HTML output of variable data",
                    description=(
                        "Data is rendered without escaping, so markup or template syntax inside it "
                        "executes in the victim's browser" + (" or on the server." if template else ".")
                    ),
                    remediation=(
                        "Output through the framework's auto-escaping (`textContent`, JSX expressions, "
                        "`render_template` with a file). If HTML is required, sanitize it first "
                        "(DOMPurify, bleach)."
                    ),
                    path=src.path,
                    line=line_no,
                    source_line=line,
                    cwe="CWE-1336" if template else "CWE-79",
                    confidence=0.7 if from_request else 0.5,
                )


# --- A05 Security Misconfiguration -------------------------------------------------------------

_DEBUG_ON = re.compile(r"\.run\([^)\n]{0,300}debug\s*=\s*True|^[ \t]*DEBUG\s*=\s*True\b|\bFLASK_DEBUG\s*=\s*[\"']?1", re.M)
_DEV_FILE = re.compile(r"dev|local|example|sample|test|debug", re.I)


@rule(
    id="WEB05-001",
    mcp_id="WEB05",
    name="Debug mode enabled",
    description="The framework's debugger / debug pages are switched on in code.",
)
def debug_enabled(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _DEBUG_ON.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line):
                continue
            dev = bool(_DEV_FILE.search(src.path))
            yield make_finding(
                rule_id="WEB05-001",
                risk_id="WEB05",
                severity=Severity.MEDIUM if dev else Severity.HIGH,
                title="Debug mode is on",
                description=(
                    "Debug mode exposes stack traces, settings and -- for the Werkzeug debugger -- an "
                    "interactive console that executes arbitrary code."
                ),
                remediation="Read the flag from the environment and default it to off; never ship `debug=True`.",
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-489",
                confidence=0.4 if dev else 0.8,
            )


_HOSTS_WILDCARD = re.compile(r"\bALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']")
_COOKIE_FLAGS_OFF = re.compile(
    r"\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b|\bCSRF_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b|"
    r"\b(?:httpOnly|secure)\s*:\s*false\b|\bsamesite\s*=\s*[\"']None[\"']",
    re.I,
)
_XXE = re.compile(r"\bresolve_entities\s*=\s*True\b|\bXMLParser\([^)\n]{0,300}no_network\s*=\s*False")


@rule(
    id="WEB05-002",
    mcp_id="WEB05",
    name="Insecure framework setting",
    description="Wildcard allowed hosts, insecure cookie flags, or XML external entities enabled.",
)
def insecure_settings(ctx: ScanContext) -> Iterable[Finding]:
    checks = (
        (_HOSTS_WILDCARD, "ALLOWED_HOSTS accepts every host", "Set ALLOWED_HOSTS to the real hostnames.", "CWE-16", Severity.MEDIUM),
        (_COOKIE_FLAGS_OFF, "Session/CSRF cookie flag weakened", "Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.", "CWE-614", Severity.MEDIUM),
        (_XXE, "XML external entity resolution enabled", "Disable entity resolution and network access in the XML parser (use defusedxml).", "CWE-611", Severity.HIGH),
    )
    for src in source_files(ctx):
        for pattern, title, fix, cwe, severity in checks:
            for match in pattern.finditer(src.text):
                line_no = line_of(src.text, match.start())
                line = line_text(src.text, line_no)
                if is_comment(line):
                    continue
                yield make_finding(
                    rule_id="WEB05-002",
                    risk_id="WEB05",
                    severity=severity,
                    title=title,
                    description=(
                        "A security-relevant default has been relaxed in code, widening what an "
                        "attacker can reach or steal."
                    ),
                    remediation=fix,
                    path=src.path,
                    line=line_no,
                    source_line=line,
                    cwe=cwe,
                    confidence=0.8,
                )


# --- A07 Identification and Authentication Failures --------------------------------------------

_JWT_UNSAFE = re.compile(
    r"[\"']verify_signature[\"']\s*:\s*False|algorithms\s*[:=]\s*\[\s*[\"']none[\"']|\bignoreExpiration\s*:\s*true\b|"
    r"\bverify_(?:exp|aud)[\"']\s*:\s*False|jwt\.decode\([^)\n]{0,300}verify\s*=\s*False",
    re.I,
)


@rule(
    id="WEB07-001",
    mcp_id="WEB07",
    name="JWT verification weakened or disabled",
    description="Signature, expiry or audience checks are turned off, or the `none` algorithm is allowed.",
)
def jwt_unverified(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _JWT_UNSAFE.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line):
                continue
            yield make_finding(
                rule_id="WEB07-001",
                risk_id="WEB07",
                severity=Severity.CRITICAL,
                title="JWT is accepted without full verification",
                description=(
                    "A token is trusted without checking its signature, expiry or audience. Anyone "
                    "can forge one and authenticate as any user."
                ),
                remediation=(
                    "Always verify the signature with a pinned algorithm list, and keep exp/aud "
                    "validation enabled."
                ),
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-347",
                confidence=0.9,
            )


_HARDCODED = re.compile(
    r"\b(?P<name>SECRET_KEY|JWT_SECRET|jwt_secret|secret_key|app\.secret_key|[A-Z_]*PASSWORD|[a-z_]*password|passwd|DB_PASS)"
    r"\s*[:=]\s*(?P<q>[\"'])(?P<value>[^\"'\n]{6,})(?P=q)"
)


@rule(
    id="WEB07-002",
    mcp_id="WEB07",
    name="Hard-coded application secret or password",
    description="A SECRET_KEY, JWT secret or password is a string literal in source.",
)
def hardcoded_secret(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _HARDCODED.finditer(src.text):
            value = match.group("value")
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line) or looks_like_placeholder(value) or " " in value:
                continue
            strong = shannon_entropy(value) >= 3.2
            yield make_finding(
                rule_id="WEB07-002",
                risk_id="WEB07",
                severity=Severity.HIGH,
                title=f"Hard-coded {match.group('name')}",
                description=(
                    "The secret lives in source control, so everyone with read access -- and anyone "
                    "who ever clones the repository -- holds the key that signs sessions or opens "
                    "the account."
                ),
                remediation=(
                    "Rotate it, then load it from the environment or a secret manager. Commit only a "
                    "placeholder in `.env.example`."
                ),
                path=src.path,
                line=line_no,
                snippet=f"{match.group('name')} = {redact(value)}",
                cwe="CWE-798",
                confidence=0.85 if strong else 0.6,
            )


# --- A08 Software and Data Integrity Failures --------------------------------------------------

_DESERIALIZE = re.compile(
    r"\b(?:pickle|cPickle|_pickle|marshal|shelve|jsonpickle|dill)\.(?:loads?|decode|open)\(|\byaml\.(?:load|unsafe_load|full_load)\(|"
    r"\bunserialize\("
)


@rule(
    id="WEB08-001",
    mcp_id="WEB08",
    name="Unsafe deserialization",
    description="pickle/marshal/yaml.load or a similar deserializer is applied to data.",
)
def unsafe_deserialization(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for call in calls(src, _DESERIALIZE):
            if "yaml." in call.source_line and re.search(r"SafeLoader|CSafeLoader|BaseLoader", call.args):
                continue
            from_request = is_tainted(call.args, names)
            yield make_finding(
                rule_id="WEB08-001",
                risk_id="WEB08",
                severity=Severity.CRITICAL if from_request else Severity.HIGH,
                title="Deserialization can execute code",
                description=(
                    "These formats rebuild arbitrary objects, running constructors and `__reduce__` "
                    "hooks while they do. Untrusted input becomes remote code execution."
                ),
                remediation=(
                    "Use a data-only format (JSON, `yaml.safe_load`, protobuf). If pickle is "
                    "unavoidable, sign the payload and verify it before loading."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-502",
                confidence=0.85 if from_request else 0.6,
            )


_PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")


@rule(
    id="WEB08-002",
    mcp_id="WEB08",
    name="Remote script piped straight to a shell",
    description="`curl ... | sh` runs unverified code fetched at execution time.",
)
def pipe_to_shell(ctx: ScanContext) -> Iterable[Finding]:
    for rel in ctx.files:
        if not rel.lower().endswith((".sh", ".py", ".yml", ".yaml", ".js", ".ts")) or rel.startswith("."):
            continue
        text = ctx.text(rel)
        for match in _PIPE_TO_SHELL.finditer(text):
            line_no = line_of(text, match.start())
            line = line_text(text, line_no)
            if is_comment(line):
                continue
            yield make_finding(
                rule_id="WEB08-002",
                risk_id="WEB08",
                severity=Severity.MEDIUM,
                title="Unverified remote script executed",
                description=(
                    "Whatever the URL serves at that moment runs with this script's privileges, with "
                    "no checksum or signature to catch a compromised host or a hijacked domain."
                ),
                remediation="Download to a file, verify a pinned checksum or signature, then execute it.",
                path=rel,
                line=line_no,
                source_line=line,
                cwe="CWE-494",
                confidence=0.8,
            )


# --- A09 Security Logging and Monitoring Failures ----------------------------------------------

_LOG_CALL = re.compile(
    r"\b(?:logger|logging|log|console|app\.logger)\.(?:debug|info|warning|warn|error|critical|exception|log)\(|(?<![.\w])print\("
)
_SENSITIVE = r"(?:password|passwd|secret|api_?key|authorization|access_?token|refresh_?token|private_?key|ssn|card_?number|cvv)"
_SENSITIVE_IN_LOG = re.compile(
    rf"\{{[^}}\n]{{0,200}}{_SENSITIVE}[^}}\n]{{0,200}}\}}|\$\{{[^}}\n]{{0,200}}{_SENSITIVE}[^}}\n]{{0,200}}\}}|,\s*[\w.\[\]\"']*{_SENSITIVE}\w*\s*(?:[,)]|$)|"
    rf"%\s*\(?[^)\n]{{0,300}}{_SENSITIVE}|\+\s*[\w.]*{_SENSITIVE}|,\s*(?:token|jwt|bearer)\s*(?:[,)]|$)",
    re.I,
)


@rule(
    id="WEB09-001",
    mcp_id="WEB09",
    name="Sensitive value written to the log",
    description="A password, token or key is passed to a logging or print call.",
)
def sensitive_logging(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for call in calls(src, _LOG_CALL):
            if not _SENSITIVE_IN_LOG.search(call.args):
                continue
            yield make_finding(
                rule_id="WEB09-001",
                risk_id="WEB09",
                severity=Severity.MEDIUM,
                title="Credential or personal data is logged",
                description=(
                    "Logs are copied to aggregators, tickets and laptops with far weaker controls "
                    "than the secret store, so a value logged once is effectively leaked."
                ),
                remediation="Log an identifier or a redacted form (`****1234`), never the value itself.",
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-532",
                confidence=0.65,
            )


_SWALLOWED = re.compile(
    r"^[ \t]*except(?:[ \t]+(?:Exception|BaseException))?(?:[ \t]+as[ \t]+\w+)?[ \t]*:[ \t]*\n[ \t]*(?:pass|\.\.\.)[ \t]*$|"
    r"\bcatch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}",
    re.M,
)


@rule(
    id="WEB09-002",
    mcp_id="WEB09",
    name="Exception silently swallowed",
    description="A broad `except: pass` / empty `catch {}` hides failures, including attacks.",
)
def swallowed_exception(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _SWALLOWED.finditer(src.text):
            line_no = line_of(src.text, match.start())
            yield make_finding(
                rule_id="WEB09-002",
                risk_id="WEB09",
                severity=Severity.LOW,
                title="Errors are caught and discarded",
                description=(
                    "A broad handler drops the exception without logging it. Failed logins, tampered "
                    "input and downstream outages leave no trace to investigate."
                ),
                remediation="Catch the specific exception you expect, and log it (with context) at least once.",
                path=src.path,
                line=line_no,
                source_line=line_text(src.text, line_no),
                cwe="CWE-390",
                confidence=0.6,
            )


# --- A10 Server-Side Request Forgery -----------------------------------------------------------

_HTTP_CLIENT = re.compile(
    r"\brequests\.(?:get|post|put|patch|delete|head|request)\(|\bhttpx\.(?:get|post|put|patch|delete|head|request)\(|"
    r"\burlopen\(|\burllib\.request\.urlretrieve\(|\baxios(?:\.(?:get|post|put|delete|request))?\(|"
    r"(?<![.\w])fetch\(|\bhttps?\.(?:get|request)\(|\bgot(?:\.\w+)?\(|\baiohttp\.\w+\(|\bsession\.(?:get|post)\("
)


@rule(
    id="WEB10-001",
    mcp_id="WEB10",
    name="Outbound request to a request-supplied URL",
    description="An HTTP client is called with a URL taken from the incoming request (SSRF).",
)
def ssrf(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        names = tainted_names(src.text)
        for call in calls(src, _HTTP_CLIENT):
            if not is_tainted(call.args, names):
                continue
            yield make_finding(
                rule_id="WEB10-001",
                risk_id="WEB10",
                severity=Severity.HIGH,
                title="Server fetches a URL chosen by the client",
                description=(
                    "The caller picks where the server connects, so they can reach cloud metadata "
                    "endpoints (169.254.169.254), internal admin panels and localhost services with "
                    "the server's network position."
                ),
                remediation=(
                    "Accept only an allowlist of hosts or ids mapped server-side. Resolve and reject "
                    "private, loopback and link-local addresses, and disable redirects."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-918",
                confidence=0.7,
            )
