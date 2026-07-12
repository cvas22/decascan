"""MCP01 — Token Mismanagement & Secret Exposure.

Two distinct failure modes, two checks:
  * credentials committed into config or source (the classic), and
  * tools that take a credential as an *input parameter*, which forces the secret through the LLM's
    context window and, usually, the provider's logs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.entropy import looks_like_placeholder, redact, shannon_entropy
from ..core.findings import Finding, Severity
from .base import rule

# High-precision provider tokens. These have enough structure that a match is a finding on its own,
# no entropy check needed.
PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "CWE-798"),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}"), "CWE-798"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}"), "CWE-798"),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), "CWE-798"),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "CWE-798"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "CWE-798"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "CWE-798"),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), "CWE-798"),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"), "CWE-798"),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), "CWE-798"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "CWE-798"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "CWE-321"),
]

# Generic `key = "value"` assignments, gated on entropy so we don't flag `password = "changeme"`.
SECRET_KEY_NAMES = (
    r"api[_-]?key|apikey|secret[_-]?key|secret|token|access[_-]?token|auth[_-]?token|"
    r"bearer|password|passwd|pwd|client[_-]?secret|private[_-]?key|credential"
)
GENERIC_ASSIGNMENT = re.compile(
    rf"(?i)\b({SECRET_KEY_NAMES})\b[\"']?\s*[:=]\s*[\"']([^\"'\n]{{12,}})[\"']"
)

# Parameter/property names that carry a credential through the LLM context if a tool declares them.
CREDENTIAL_FIELD_NAMES = {
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "secret",
    "password",
    "passwd",
    "client_secret",
    "private_key",
    "credential",
    "credentials",
    "bearer",
}

_SCANNED_SUFFIXES = (
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".sh",
    ".ini",
    ".cfg",
)


def _should_scan(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env.") or path.endswith(_SCANNED_SUFFIXES)


def _is_template_file(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in (".example", ".sample", ".template", "fixture"))


@rule(
    id="MCP01-001",
    mcp_id="MCP01",
    name="Hardcoded credential",
    description="A credential is committed to the repository in config or source.",
)
def hardcoded_credentials(ctx: ScanContext) -> Iterable[Finding]:
    for path in ctx.files:
        if not _should_scan(path):
            continue
        template = _is_template_file(path)

        for line_no, line in enumerate(ctx.text(path).splitlines(), start=1):
            if len(line) > 500:  # minified bundles produce nothing but noise here
                continue

            for label, pattern, cwe in PROVIDER_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                yield Finding(
                    rule_id="MCP01-001",
                    mcp_id="MCP01",
                    severity=Severity.LOW if template else Severity.CRITICAL,
                    title=f"{label} committed to source",
                    description=(
                        f"A live-looking {label} appears in `{path}`. Anything in the repository is "
                        "readable by every developer, every CI job, and every MCP client that can "
                        "read the workspace — treat this credential as compromised."
                    ),
                    file_path=path,
                    line=line_no,
                    snippet=_redacted_line(line, match.group(0)),
                    remediation=(
                        "Revoke and rotate the credential now — removing the line does not "
                        "un-leak it. Load it from the environment instead "
                        "(`os.environ[...]` / `process.env[...]`) and keep the value in a secret "
                        "manager or an untracked `.env` file."
                    ),
                    cwe_id=cwe,
                    confidence=0.6 if template else 0.95,
                    metadata={"kind": label},
                )

            for match in GENERIC_ASSIGNMENT.finditer(line):
                key, value = match.group(1), match.group(2)
                if looks_like_placeholder(value):
                    continue
                entropy = shannon_entropy(value)
                if entropy < ctx.config.min_entropy:
                    continue
                yield Finding(
                    rule_id="MCP01-001",
                    mcp_id="MCP01",
                    severity=Severity.LOW if template else Severity.HIGH,
                    title=f"Hardcoded value assigned to `{key}`",
                    description=(
                        f"`{key}` is set to a high-entropy literal ({entropy:.1f} bits/char) in "
                        f"`{path}`, which is what a real credential looks like."
                    ),
                    file_path=path,
                    line=line_no,
                    snippet=_redacted_line(line, value),
                    remediation=(
                        "Move the value to an environment variable or secret manager and reference "
                        "it at runtime. If this is test data, rename it or add `mcpcheck:ignore` to "
                        "the line."
                    ),
                    cwe_id="CWE-798",
                    confidence=0.5 if template else 0.75,
                    metadata={"entropy": f"{entropy:.2f}"},
                )


@rule(
    id="MCP01-002",
    mcp_id="MCP01",
    name="Credential accepted as tool input",
    description="A tool takes a secret as a parameter, routing it through the LLM context window.",
)
def credential_in_tool_signature(ctx: ScanContext) -> Iterable[Finding]:
    for tool in ctx.all_tools:
        for param in tool.params:
            if param.name.lower().strip("_") not in CREDENTIAL_FIELD_NAMES:
                continue
            yield Finding(
                rule_id="MCP01-002",
                mcp_id="MCP01",
                severity=Severity.MEDIUM,
                title=f"Tool `{tool.name}` accepts `{param.name}` as an input parameter",
                description=(
                    f"For the model to call `{tool.name}`, the value of `{param.name}` has to exist "
                    "in the conversation context — which means it is sent to the model provider, "
                    "retained in transcripts, and visible to anything else reading that context. "
                    "Servers should hold their own credentials, not ask the LLM for them."
                ),
                file_path=tool.file,
                line=param.line or tool.line,
                snippet=ctx.line(tool.file, param.line or tool.line).strip() or None,
                remediation=(
                    f"Remove `{param.name}` from the tool's input schema and read the credential "
                    "from the server's own environment or secret store at call time."
                ),
                cwe_id="CWE-522",
                confidence=0.9,
                metadata={"tool": tool.name},
            )


def _redacted_line(line: str, secret: str) -> str:
    return line.strip().replace(secret, redact(secret))
