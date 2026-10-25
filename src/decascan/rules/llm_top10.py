"""OWASP Top 10 for LLM Applications (2025) -- the application side of the model call.

Three categories are not here on purpose: LLM04 (data and model poisoning), LLM08 (vector and
embedding weaknesses) and LLM09 (misinformation) are properties of training data, retrieval
corpora and model behaviour, not of a line of source. `decascan standards` reports them as
"not statically detectable" instead of letting a clean scan imply they were checked.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.entropy import looks_like_placeholder
from ..core.findings import Finding, Severity
from ._scan import (
    calls,
    is_comment,
    is_import,
    line_of,
    line_text,
    make_finding,
    source_files,
)
from .base import rule

_USER_HINT = re.compile(r"user|input|query|request|message|question|text|prompt|body|param", re.I)
_INTERPOLATION = re.compile(r"\$?\{([^{}\n]*)\}|\.format\(([^)\n]{0,300})\)|\+\s*([\w.\[\]]+)")


def _interpolated(segment: str) -> str:
    """The expressions spliced into a string on this line, so keywords elsewhere do not count."""
    return " ".join(part for groups in _INTERPOLATION.findall(segment) for part in groups if part)

# --- LLM01 -------------------------------------------------------------------------------------

# A "system" message whose content is assembled at runtime. The system role is the trusted channel;
# splicing anything variable into it lets that data speak with the operator's authority.
_SYSTEM_DYNAMIC = (
    re.compile(r"[\"']role[\"']\s*:\s*[\"']system[\"']\s*,\s*[\"']content[\"']\s*:\s*(f[\"']|[^\n]{0,400}\.format\(|[^\n]{0,400}[\"']\s*\+\s*\w)"),
    re.compile(r"\brole\s*:\s*[\"'`]system[\"'`]\s*,\s*content\s*:\s*`[^`]*\$\{"),
    re.compile(r"\bSystemMessage\(\s*(?:content\s*=\s*)?(f[\"']|[^\n)]*\.format\()"),
    re.compile(r"\bsystem\s*=\s*(f[\"'][^\n]{0,400}\{|[^\n]{0,400}\.format\()"),
)


@rule(
    id="LLM01-001",
    mcp_id="LLM01",
    name="Variable data interpolated into the system prompt",
    description="A system message is built with an f-string, .format() or concatenation.",
)
def dynamic_system_prompt(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for pattern in _SYSTEM_DYNAMIC:
            for match in pattern.finditer(src.text):
                line_no = line_of(src.text, match.start())
                line = line_text(src.text, line_no)
                if is_comment(line):
                    continue
                looks_like_user = bool(_USER_HINT.search(_interpolated(line[line.find("content") :])))
                yield make_finding(
                    rule_id="LLM01-001",
                    risk_id="LLM01",
                    severity=Severity.HIGH if looks_like_user else Severity.MEDIUM,
                    title="System prompt is assembled from variable data",
                    description=(
                        "The system message is built at runtime. Whatever is spliced in -- a user "
                        "field, a retrieved document, a tool result -- is promoted to the operator's "
                        "authority, which is exactly what prompt injection needs."
                    ),
                    remediation=(
                        "Keep the system prompt a constant. Pass variable data in a separate user "
                        "message, clearly delimited, and treat it as untrusted input."
                    ),
                    path=src.path,
                    line=line_no,
                    source_line=line,
                    cwe="CWE-77",
                    confidence=0.7 if looks_like_user else 0.5,
                )


# --- LLM02 -------------------------------------------------------------------------------------

_SECRET_IN_PROMPT = re.compile(
    r"f[\"'][^\n\"']*\{[^}\n]{0,200}(?:os\.environ|getenv|api_?key|secret|password|passwd|private_key)[^}\n]{0,200}\}|"
    r"`[^`\n]*\$\{[^}\n]{0,200}(?:process\.env|apiKey|secret|password)[^}\n]{0,200}\}",
    re.I,
)
_PROMPT_CONTEXT = re.compile(r"prompt|system|messages?|content|instruction", re.I)


@rule(
    id="LLM02-001",
    mcp_id="LLM02",
    name="Secret interpolated into a prompt",
    description="An environment variable, key or password is formatted into text sent to the model.",
)
def secret_in_prompt(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _SECRET_IN_PROMPT.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line) or not _PROMPT_CONTEXT.search(line):
                continue
            yield make_finding(
                rule_id="LLM02-001",
                risk_id="LLM02",
                severity=Severity.HIGH,
                title="Secret value is formatted into a prompt",
                description=(
                    "A credential reaches the model's context. Anything in that context can be "
                    "echoed back, logged by the provider, or extracted by a prompt-injection "
                    "attack."
                ),
                remediation=(
                    "Never put credentials in model input. Hold them in the tool or backend that "
                    "needs them and give the model an opaque handle instead."
                ),
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-200",
                confidence=0.65,
            )


# --- LLM03 -------------------------------------------------------------------------------------

_TRUST_REMOTE = re.compile(r"\btrust_remote_code\s*=\s*True\b")
_UNSAFE_LOAD = re.compile(r"\b(?:torch\.load|joblib\.load|dill\.loads?|cloudpickle\.loads?)\(")
_FROM_PRETRAINED = re.compile(r"\b(?:from_pretrained|hf_hub_download|snapshot_download)\(")


@rule(
    id="LLM03-001",
    mcp_id="LLM03",
    name="Model or dataset code executed from a remote repository",
    description="`trust_remote_code=True` runs Python shipped inside the model repository.",
)
def trust_remote_code(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for match in _TRUST_REMOTE.finditer(src.text):
            line_no = line_of(src.text, match.start())
            line = line_text(src.text, line_no)
            if is_comment(line):
                continue
            yield make_finding(
                rule_id="LLM03-001",
                risk_id="LLM03",
                severity=Severity.HIGH,
                title="`trust_remote_code=True` executes code from the model repository",
                description=(
                    "Loading a model with this flag imports and runs arbitrary Python from the hub "
                    "repository. Whoever controls that repository, or the account behind it, "
                    "controls your process."
                ),
                remediation=(
                    "Drop the flag and use a natively supported architecture, or vendor the "
                    "reviewed modeling code and pin the repository to a commit SHA."
                ),
                path=src.path,
                line=line_no,
                source_line=line,
                cwe="CWE-94",
                confidence=0.95,
            )


@rule(
    id="LLM03-002",
    mcp_id="LLM03",
    name="Model weights loaded through pickle",
    description="`torch.load` / `joblib.load` without `weights_only=True` can execute code.",
)
def unsafe_model_load(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        if src.is_js:
            continue
        for call in calls(src, _UNSAFE_LOAD):
            if "weights_only=True" in call.args.replace(" ", ""):
                continue
            yield make_finding(
                rule_id="LLM03-002",
                risk_id="LLM03",
                severity=Severity.HIGH,
                title="Model artifact is deserialized with pickle semantics",
                description=(
                    "Pickle-based loaders run code embedded in the file. A downloaded or "
                    "user-supplied checkpoint is therefore a remote-code-execution vector."
                ),
                remediation=(
                    "Use `torch.load(..., weights_only=True)` or the safetensors format, and only "
                    "load artifacts whose provenance and hash you have verified."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-502",
                confidence=0.8,
            )


@rule(
    id="LLM03-003",
    mcp_id="LLM03",
    name="Model downloaded without a pinned revision",
    description="`from_pretrained` / `hf_hub_download` with no `revision=` follows a moving branch.",
)
def unpinned_model(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        if src.is_js:
            continue
        for call in calls(src, _FROM_PRETRAINED):
            first = call.args.strip()
            if "revision" in call.args or not re.match(r"[\"'][\w.\-]+/[\w.\-]+[\"']", first):
                continue  # pinned, or a local path / variable we cannot judge
            yield make_finding(
                rule_id="LLM03-003",
                risk_id="LLM03",
                severity=Severity.LOW,
                title="Hub model is fetched without pinning a revision",
                description=(
                    "Without `revision=<commit sha>` the model resolves to whatever the repository's "
                    "default branch holds today. A later push silently changes the weights your "
                    "application runs."
                ),
                remediation="Pass `revision=` with a full commit SHA for every hub download.",
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-829",
                confidence=0.6,
            )


# --- LLM05 -------------------------------------------------------------------------------------

_MODEL_OUTPUT = (
    r"(?:response|completion|llm_?(?:output|response|result)|model_?(?:output|response)|generated(?:_text)?|"
    r"ai_?(?:reply|response|message)|chat_?(?:response|completion)|answer|\.choices\b|\.output_text\b)"
)
_OUTPUT_SINKS = (
    (re.compile(rf"(?<![.\w])(?:eval|exec)\([^\n]{{0,400}}{_MODEL_OUTPUT}", re.I), "evaluated as code", Severity.CRITICAL, "CWE-95"),
    (re.compile(rf"\bos\.system\([^\n]{{0,400}}{_MODEL_OUTPUT}|\bsubprocess\.\w+\([^\n]{{0,400}}{_MODEL_OUTPUT}", re.I), "run as a shell command", Severity.CRITICAL, "CWE-78"),
    (re.compile(rf"\b(?:execSync|exec|spawn)\([^\n]{{0,400}}{_MODEL_OUTPUT}", re.I), "run as a shell command", Severity.CRITICAL, "CWE-78"),
    (re.compile(rf"\b(?:innerHTML|outerHTML)\s*=[^\n]{{0,400}}{_MODEL_OUTPUT}|dangerouslySetInnerHTML[^\n]{{0,400}}{_MODEL_OUTPUT}", re.I), "rendered as raw HTML", Severity.HIGH, "CWE-79"),
    (re.compile(rf"\.(?:execute|executemany|query)\(\s*(?:f[\"']|`)[^\n]{{0,400}}{_MODEL_OUTPUT}", re.I), "spliced into a SQL statement", Severity.HIGH, "CWE-89"),
)


@rule(
    id="LLM05-001",
    mcp_id="LLM05",
    name="Model output reaches a dangerous sink unvalidated",
    description="LLM output is passed to eval/exec, a shell, raw HTML or a SQL string.",
)
def improper_output_handling(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for pattern, consequence, severity, cwe in _OUTPUT_SINKS:
            for match in pattern.finditer(src.text):
                line_no = line_of(src.text, match.start())
                line = line_text(src.text, line_no)
                if is_comment(line):
                    continue
                yield make_finding(
                    rule_id="LLM05-001",
                    risk_id="LLM05",
                    severity=severity,
                    title=f"Model output is {consequence}",
                    description=(
                        f"A value that looks like LLM output is {consequence} with no validation "
                        "in between. The model's text is attacker-influenced whenever any input "
                        "to it is, so this is injection with an extra hop."
                    ),
                    remediation=(
                        "Treat model output as untrusted input: validate it against a strict "
                        "schema or allowlist, escape it for the sink, and never execute it."
                    ),
                    path=src.path,
                    line=line_no,
                    source_line=line,
                    cwe=cwe,
                    confidence=0.65,
                )


# --- LLM06 -------------------------------------------------------------------------------------

_DANGEROUS_FLAG = re.compile(r"\ballow_dangerous_(?:code|requests)\s*=\s*True\b")
_DANGEROUS_TOOL = re.compile(r"\b(?:ShellTool|PythonREPLTool|PythonAstREPLTool|BashProcess|TerminalTool)\b")
_BROAD_TOOLKIT = re.compile(
    r"\b(?:create_(?:pandas_dataframe|python|csv|spark)_agent|FileManagementToolkit|SQLDatabaseToolkit)\b"
)


@rule(
    id="LLM06-001",
    mcp_id="LLM06",
    name="Agent granted unrestricted code, shell or file capability",
    description="An agent is wired to a shell/REPL tool or an `allow_dangerous_*` switch.",
)
def excessive_agency(ctx: ScanContext) -> Iterable[Finding]:
    checks = (
        (_DANGEROUS_FLAG, Severity.HIGH, "an explicit `allow_dangerous_*` opt-in", 0.9),
        (_DANGEROUS_TOOL, Severity.HIGH, "a shell or Python REPL tool", 0.85),
        (_BROAD_TOOLKIT, Severity.MEDIUM, "a broad toolkit that executes generated code or SQL", 0.6),
    )
    for src in source_files(ctx):
        for pattern, severity, what, confidence in checks:
            for match in pattern.finditer(src.text):
                line_no = line_of(src.text, match.start())
                line = line_text(src.text, line_no)
                if is_comment(line) or is_import(line):
                    continue
                yield make_finding(
                    rule_id="LLM06-001",
                    risk_id="LLM06",
                    severity=severity,
                    title=f"Agent has {what}",
                    description=(
                        "The model can act on the host with the application's own privileges. One "
                        "successful prompt injection turns into code execution, file access or "
                        "arbitrary queries."
                    ),
                    remediation=(
                        "Expose narrow, purpose-built tools with validated parameters. Run any code "
                        "execution in a sandbox with no network and no credentials, and require "
                        "human approval for state-changing actions."
                    ),
                    path=src.path,
                    line=line_no,
                    source_line=line,
                    cwe="CWE-250",
                    confidence=confidence,
                )


# --- LLM07 -------------------------------------------------------------------------------------

_SYSTEM_PROMPT_LINE = re.compile(
    r"(?:system[_ ]?(?:prompt|message|instruction)s?|[\"']role[\"']\s*:\s*[\"']system)", re.I
)
_CREDENTIAL_IN_TEXT = re.compile(
    r"(api[_ -]?key|passw(?:or)?d|secret|token|bearer)\s*(?:is|=|:)\s*[\"']?([A-Za-z0-9_\-./+=]{8,})", re.I
)


@rule(
    id="LLM07-001",
    mcp_id="LLM07",
    name="Credential embedded in a system prompt",
    description="A system prompt contains a key, password or token value.",
)
def secret_in_system_prompt(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for number, line in enumerate(src.text.splitlines(), start=1):
            if is_comment(line) or not _SYSTEM_PROMPT_LINE.search(line):
                continue
            match = _CREDENTIAL_IN_TEXT.search(line)
            if not match or looks_like_placeholder(match.group(2)):
                continue
            yield make_finding(
                rule_id="LLM07-001",
                risk_id="LLM07",
                severity=Severity.HIGH,
                title="System prompt carries a credential",
                description=(
                    "System prompts are not secret: models routinely repeat them when asked, and "
                    "prompt-injection attacks extract them on purpose. Anything placed there should "
                    "be assumed public."
                ),
                remediation=(
                    "Remove the credential from the prompt and rotate it. Enforce access control in "
                    "the backend, not in instructions to the model."
                ),
                path=src.path,
                line=number,
                snippet=f"{match.group(1)} = {match.group(2)[:4]}{'*' * 8}",
                cwe="CWE-200",
                confidence=0.7,
            )


# --- LLM10 -------------------------------------------------------------------------------------

_LLM_CALL = re.compile(
    r"\b(?:chat\.completions\.create|completions\.create|messages\.create|responses\.create|"
    r"generate_content|ChatOpenAI|ChatAnthropic|OpenAI\w*Chat|invoke_model)\("
)
_TOKEN_CAP = re.compile(
    r"max_tokens|max_output_tokens|max_completion_tokens|max_new_tokens|maxTokens|maxOutputTokens|"
    r"max_tokens_to_sample|\*\*\s*\w+"
)


@rule(
    id="LLM10-001",
    mcp_id="LLM10",
    name="Model call with no output-token cap",
    description="A completion request sets no `max_tokens` (or equivalent) limit.",
)
def unbounded_generation(ctx: ScanContext) -> Iterable[Finding]:
    for src in source_files(ctx):
        for call in calls(src, _LLM_CALL):
            if _TOKEN_CAP.search(call.args):
                continue  # capped, or built from **kwargs we cannot see into
            yield make_finding(
                rule_id="LLM10-001",
                risk_id="LLM10",
                severity=Severity.MEDIUM,
                title="LLM request has no output-token limit",
                description=(
                    "Without a cap, a single request can generate until the model's context limit. "
                    "Repeated by one client, that is a denial-of-wallet and denial-of-service "
                    "vector."
                ),
                remediation=(
                    "Set `max_tokens` (or the provider's equivalent) on every call, and add "
                    "per-user rate limits and a request timeout."
                ),
                path=src.path,
                line=call.line,
                source_line=call.source_line,
                cwe="CWE-770",
                confidence=0.6,
            )
