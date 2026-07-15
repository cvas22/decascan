"""Rule tests, driven off the fixture servers in tests/fixtures/."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sift.core.config import ScanConfig
from mcp_sift.core.findings import Severity
from mcp_sift.core.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def vulnerable_python():
    return scan(FIXTURES / "vulnerable_python")


@pytest.fixture(scope="module")
def vulnerable_ts():
    return scan(FIXTURES / "vulnerable_ts")


@pytest.fixture(scope="module")
def lowlevel():
    return scan(FIXTURES / "lowlevel_python")


@pytest.fixture(scope="module")
def clean():
    return scan(FIXTURES / "clean_python")


@pytest.fixture(scope="module")
def poisoned():
    return scan(FIXTURES / "poisoned_python")


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def findings_for(result, rule_id: str) -> list:
    return [f for f in result.findings if f.rule_id == rule_id]


# --- MCP01: secrets -----------------------------------------------------------------------


def test_finds_hardcoded_anthropic_key(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP01-001")
    assert any(f.severity == Severity.CRITICAL and f.file_path == "server.py" for f in hits)


def test_hardcoded_key_is_redacted_in_output(vulnerable_python):
    for finding in findings_for(vulnerable_python, "MCP01-001"):
        assert "sk-ant-api03-Vq7hK2mZ" not in (finding.snippet or "")
        assert "*" in (finding.snippet or "")


def test_finds_github_token_in_typescript(vulnerable_ts):
    hits = findings_for(vulnerable_ts, "MCP01-001")
    assert any("GitHub token" in f.title for f in hits)


def test_flags_credential_accepted_as_tool_parameter(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP01-002")
    assert any(f.metadata.get("tool") == "sync_remote" for f in hits)


# --- MCP02: scope creep -------------------------------------------------------------------


def test_flags_exec_beyond_declared_read_scope(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP02-001")
    capabilities = {f.metadata.get("capability") for f in hits}
    assert "exec" in capabilities  # subprocess.run, declared scope is read:files only
    assert "fs:write" in capabilities  # Path.write_text
    assert "net" in capabilities  # httpx.get


def test_exec_scope_violation_is_critical(vulnerable_python):
    exec_hits = [
        f for f in findings_for(vulnerable_python, "MCP02-001")
        if f.metadata.get("capability") == "exec"
    ]
    assert exec_hits and all(f.severity == Severity.CRITICAL for f in exec_hits)


def test_granted_capability_is_not_flagged(vulnerable_python):
    """read_file uses Path.read_text and read:files IS declared — no MCP02 finding for it."""
    read_hits = [
        f for f in findings_for(vulnerable_python, "MCP02-001")
        if f.metadata.get("capability") == "fs:read"
    ]
    assert read_hits == []


# --- MCP03: tool poisoning ----------------------------------------------------------------


def test_flags_unconstrained_command_reaching_shell(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP03-001")
    assert any(f.metadata.get("tool") == "run_command" for f in hits)
    assert all(f.severity == Severity.CRITICAL for f in hits)


def test_flags_unconstrained_command_in_typescript(vulnerable_ts):
    hits = findings_for(vulnerable_ts, "MCP03-001")
    assert any(f.metadata.get("tool") == "run_build" for f in hits)


def test_flags_open_input_schema(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP03-002")
    assert any(f.metadata.get("tool") == "search_files" for f in hits)


def test_manifest_findings_point_at_the_tool_not_line_one(vulnerable_python):
    """A finding whose location is always `manifest:1` is a finding nobody can act on."""
    hits = [f for f in findings_for(vulnerable_python, "MCP03-002") if f.file_path == ".mcp.json"]
    assert hits and all(f.line > 1 for f in hits)
    assert any("search_files" in (f.snippet or "") for f in hits)


def test_flags_risky_param_without_a_sink_at_medium(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP03-003")
    tools = {f.metadata.get("tool") for f in hits}
    assert "read_file" in tools  # path: str, no exec sink -> medium, not critical
    assert "run_command" not in tools  # already reported by MCP03-001, not duplicated


def test_flags_tool_with_no_schema(vulnerable_ts):
    hits = findings_for(vulnerable_ts, "MCP03-004")
    assert any(f.metadata.get("tool") == "list_branches" for f in hits)


# --- The low-level SDK + pydantic shape the official servers use ---------------------------


def test_reads_a_pydantic_input_schema(lowlevel):
    """`inputSchema=Grep.model_json_schema()` must resolve to the Grep model's fields.

    The official MCP servers all declare tools this way. A scanner that can't follow it reports a
    clean bill of health on the exact servers people copy from.
    """
    from mcp_sift.core.config import ScanConfig
    from mcp_sift.core.context import build_context

    ctx = build_context(FIXTURES / "lowlevel_python", ScanConfig())
    tools = {t.name: t for t in ctx.code_tools}
    assert "grep_logs" in tools

    grep = tools["grep_logs"]
    assert grep.has_schema
    assert {p.name for p in grep.params} == {"pattern", "logfile"}
    assert grep.params[0].required  # Field(...) means required
    assert not grep.params[1].required  # has a default
    assert not grep.additional_properties_open  # pydantic drops extras unless extra="allow"


def test_flags_sink_inside_a_call_tool_dispatcher(lowlevel):
    hits = findings_for(lowlevel, "MCP03-001")
    assert any(f.metadata.get("tool") == "grep_logs" for f in hits)
    assert all(f.severity == Severity.CRITICAL for f in hits)  # shell=True


# --- MCP04: supply chain ------------------------------------------------------------------


def test_flags_git_dependency(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP04-001")
    assert any(f.metadata.get("dependency") == "internal-tools" for f in hits)
    assert all(f.metadata.get("source") == "vcs" for f in hits)


def test_flags_floating_deps_without_lockfile(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP04-002")
    assert hits  # httpx>=0.27, mcp>=1.0, ... and no lockfile committed


def test_flags_npm_install_hook(vulnerable_ts):
    hits = findings_for(vulnerable_ts, "MCP04-003")
    assert any(f.metadata.get("hook") == "postinstall" for f in hits)


def test_pinned_registry_dep_is_not_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.2\nrich==13.7.1\n")
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
    )
    result = scan(tmp_path)
    assert findings_for(result, "MCP04-001") == []
    assert findings_for(result, "MCP04-002") == []


def test_lockfile_silences_floating_dependency_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx>=0.27\n")
    (tmp_path / "requirements.lock").write_text("httpx==0.27.2\n")
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
    )
    assert findings_for(scan(tmp_path), "MCP04-002") == []


def test_classifiers_are_not_read_as_dependencies(tmp_path):
    """A pyproject array that isn't a dependency list must not become findings."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "x"\n'
        'classifiers = ["Topic :: Security", "License :: OSI Approved :: MIT License"]\n'
        'keywords = ["mcp", "security"]\n'
        'dependencies = ["httpx==0.27.2"]\n'
    )
    deps_findings = [
        f for f in scan(tmp_path).findings if f.mcp_id == "MCP04"
    ]
    assert deps_findings == []  # httpx is pinned; classifiers/keywords are not dependencies


# --- MCP05: command injection (taint-proven) ----------------------------------------------


def test_taint_proves_input_reaches_shell(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP05-001")
    assert any(f.metadata.get("param") == "command" for f in hits)
    assert all(f.severity == Severity.CRITICAL for f in hits)
    assert all(f.metadata.get("proven") == "true" for f in hits)  # real AST, not co-location


def test_taint_proves_input_reaches_path(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP05-003")
    params = {f.metadata.get("param") for f in hits}
    assert "path" in params


def test_write_content_is_not_reported_as_a_path(vulnerable_python):
    """`Path(path).write_text(body)` — `body` is content, not a path, and must not be an MCP05."""
    hits = findings_for(vulnerable_python, "MCP05-003")
    assert all(f.metadata.get("param") != "body" for f in hits)


def test_eval_of_tool_input_is_flagged(poisoned):
    hits = findings_for(poisoned, "MCP05-002")
    assert any(f.metadata.get("param") == "expr" for f in hits)


def test_enum_constrained_input_is_not_a_taint_finding(clean):
    """The clean fixture interpolates a Literal-constrained value into a path. Not injectable."""
    assert findings_for(clean, "MCP05-003") == []


def test_ts_taint_is_reported_but_less_confident(vulnerable_ts):
    """TS has no AST here, so the flow is a name match: reported, at lower confidence, marked so."""
    hits = findings_for(vulnerable_ts, "MCP05-001")
    assert hits
    assert all(f.metadata.get("proven") == "false" for f in hits)
    assert all(f.confidence < 0.8 for f in hits)


def test_argv_argument_is_not_command_injection(tmp_path):
    (tmp_path / "server.py").write_text(
        "import subprocess\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def build(target: str) -> str:\n"
        "    return subprocess.run(['make', target]).stdout\n"
    )
    # `target` is an argument to a fixed program, not the program — no shell, no injection.
    assert findings_for(scan(tmp_path), "MCP05-001") == []


def test_shlex_quote_sanitizes_the_flow(tmp_path):
    (tmp_path / "server.py").write_text(
        "import subprocess, shlex\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def echo(name: str) -> str:\n"
        "    safe = shlex.quote(name)\n"
        "    return subprocess.run(f'echo {safe}', shell=True).stdout\n"
    )
    assert findings_for(scan(tmp_path), "MCP05-001") == []


# --- MCP06: prompt injection --------------------------------------------------------------


def test_flags_instruction_in_tool_description(poisoned):
    hits = findings_for(poisoned, "MCP06-001")
    tools = {f.metadata.get("tool") for f in hits}
    assert "read_docs" in tools  # <IMPORTANT> block steering the model
    assert "summarize" in tools  # "ignore all previous instructions"


def test_flags_hidden_characters_in_description(poisoned):
    hits = findings_for(poisoned, "MCP06-002")
    assert any(f.metadata.get("tool") == "summarize" for f in hits)


def test_honest_description_is_not_flagged(clean):
    assert findings_for(clean, "MCP06-001") == []
    assert findings_for(clean, "MCP06-002") == []


def test_flags_remote_content_returned_to_model(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP06-003")
    assert any(f.metadata.get("tool") == "sync_remote" for f in hits)


# --- MCP08: audit -------------------------------------------------------------------------


def test_flags_missing_audit_trail(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP08-001")
    assert len(hits) == 1  # server shells out, logs nothing


def test_flags_swallowed_exception(poisoned):
    hits = findings_for(poisoned, "MCP08-002")
    assert any("OSError" in (f.metadata.get("exception") or "") for f in hits)


def test_audit_rule_does_not_fire_on_a_non_server(tmp_path):
    """A plain library that writes files is not a server with a missing audit trail."""
    (tmp_path / "util.py").write_text(
        "from pathlib import Path\n"
        "def save(p, b):\n"
        "    Path(p).write_text(b)\n"
    )
    assert findings_for(scan(tmp_path), "MCP08-001") == []


# --- MCP10: over-sharing ------------------------------------------------------------------


def test_flags_environment_returned_to_model(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP10-001")
    assert any(f.metadata.get("tool") == "dump_env" for f in hits)


def test_flags_credential_path_access(poisoned):
    hits = findings_for(poisoned, "MCP10-002")
    markers = {f.metadata.get("marker") for f in hits}
    assert markers & {".ssh", "id_rsa"}  # ~/.ssh/id_rsa read by load_identity


def test_flags_broad_filesystem_root(poisoned):
    hits = findings_for(poisoned, "MCP10-003")
    assert any(f.metadata.get("root") == "/" for f in hits)


# --- MCP07: auth --------------------------------------------------------------------------


def test_flags_network_server_without_auth(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP07-001")
    assert len(hits) == 1
    assert hits[0].severity == Severity.CRITICAL


def test_flags_wildcard_cors(vulnerable_python, vulnerable_ts):
    assert findings_for(vulnerable_python, "MCP07-002")  # manifest: cors.allowOrigin = "*"
    assert findings_for(vulnerable_ts, "MCP07-002")  # code: Access-Control-Allow-Origin: *


def test_stdio_server_is_not_flagged_for_missing_auth(clean):
    assert findings_for(clean, "MCP07-001") == []


# --- MCP09: shadow servers ----------------------------------------------------------------


def test_flags_second_server_instantiation(vulnerable_python):
    hits = findings_for(vulnerable_python, "MCP09-001")
    assert len(hits) == 1
    assert hits[0].file_path == "debug_server.py"


def test_flags_undeclared_port(vulnerable_python):
    ports = {f.metadata.get("port") for f in findings_for(vulnerable_python, "MCP09-002")}
    assert "8081" in ports  # bound in debug_server.py, absent from .mcp.json
    assert "8080" not in ports  # declared, so not a shadow listener


def test_flags_undeclared_port_in_typescript(vulnerable_ts):
    ports = {f.metadata.get("port") for f in findings_for(vulnerable_ts, "MCP09-002")}
    assert "9090" in ports


# --- False positives ----------------------------------------------------------------------


def test_clean_server_produces_no_actionable_findings(clean):
    actionable = [f for f in clean.findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert actionable == [], [f"{f.rule_id} {f.file_path}:{f.line} {f.title}" for f in actionable]


def test_scan_reports_no_internal_errors(vulnerable_python, vulnerable_ts, clean):
    for result in (vulnerable_python, vulnerable_ts, clean):
        assert result.errors == []


# --- Scanner plumbing ---------------------------------------------------------------------


def test_inline_suppression_silences_a_finding(tmp_path):
    (tmp_path / "server.py").write_text(
        'KEY = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5gH9jL0pQ2sT4uV6wX8yZ0aB2cD4eF6"\n'
    )
    assert findings_for(scan(tmp_path), "MCP01-001")

    (tmp_path / "server.py").write_text(
        'KEY = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5gH9jL0pQ2sT4uV6wX8yZ0aB2cD4eF6"'
        "  # mcp-sift:ignore\n"
    )
    assert findings_for(scan(tmp_path), "MCP01-001") == []


def test_fail_on_threshold(vulnerable_python, clean):
    assert vulnerable_python.should_fail(Severity.CRITICAL)
    assert not clean.should_fail(Severity.MEDIUM)


def test_rule_selection(vulnerable_python):
    only_mcp01 = scan(
        FIXTURES / "vulnerable_python",
        ScanConfig(enabled_rules=frozenset({"MCP01-001"})),
    )
    assert rule_ids(only_mcp01) == {"MCP01-001"}
    assert only_mcp01.rules_run == 1


def test_placeholders_are_not_reported(tmp_path):
    (tmp_path / ".env.example").write_text(
        'API_KEY="${YOUR_API_KEY_HERE}"\nPASSWORD="changeme"\nTOKEN="xxxxxxxxxxxxxxxx"\n'
    )
    assert scan(tmp_path).findings == []
