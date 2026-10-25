"""Repo-relative paths in SARIF/annotations, and merging one defect reported by several lists."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from decascan.cli import main
from decascan.core.config import ScanConfig
from decascan.core.findings import Finding, Severity
from decascan.core.merge import merge_cross_list
from decascan.core.paths import find_git_root, path_prefix, repo_path, resolve_repo_root
from decascan.core.scanner import scan
from decascan.outputs import github, sarif

# --- paths -------------------------------------------------------------------------------------


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "services" / "api").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "services" / "api" / "app.py").write_text("DEBUG = True\n", encoding="utf-8")
    return repo


def test_find_git_root_walks_up_and_accepts_a_git_file(tmp_path):
    repo = make_repo(tmp_path)
    assert find_git_root(repo / "services" / "api") == repo
    (tmp_path / "wt").mkdir()
    (tmp_path / "wt" / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")  # worktree/submodule
    assert find_git_root(tmp_path / "wt") == tmp_path / "wt"


def test_resolution_order_explicit_then_workspace_then_git(tmp_path):
    repo = make_repo(tmp_path)
    scan_root = repo / "services" / "api"
    other = tmp_path / "other"
    other.mkdir()
    assert resolve_repo_root(scan_root, other, {"GITHUB_WORKSPACE": str(repo)}) == other.resolve()
    assert resolve_repo_root(scan_root, None, {"GITHUB_WORKSPACE": str(repo)}) == repo.resolve()
    assert resolve_repo_root(scan_root, None, {}) == repo


def test_workspace_that_does_not_contain_the_scan_is_ignored(tmp_path):
    repo = make_repo(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    got = resolve_repo_root(repo / "services", None, {"GITHUB_WORKSPACE": str(elsewhere)})
    assert got == repo


@pytest.mark.parametrize(
    ("scan_rel", "expected"),
    [(".", ""), ("services", "services"), ("services/api", "services/api")],
)
def test_path_prefix(tmp_path, scan_rel, expected):
    repo = make_repo(tmp_path)
    assert path_prefix(repo / scan_rel, repo) == expected


def test_path_prefix_is_empty_without_a_repo_or_outside_it(tmp_path):
    repo = make_repo(tmp_path)
    assert path_prefix(repo, None) == ""
    assert path_prefix(tmp_path, repo) == ""


def test_repo_path_joins_with_a_forward_slash():
    assert repo_path("src", "a/b.py") == "src/a/b.py"
    assert repo_path("", "a/b.py") == "a/b.py"


def test_scan_records_the_prefix_and_sarif_uses_it(tmp_path):
    repo = make_repo(tmp_path)
    result = scan(repo / "services" / "api", ScanConfig(standards=frozenset({"web"})))
    assert result.path_prefix == "services/api"
    assert result.findings[0].file_path == "app.py"  # findings themselves stay scan-relative
    uri = json.loads(sarif.render(result))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert uri["artifactLocation"]["uri"] == "services/api/app.py"


def test_annotations_use_the_repo_relative_path(tmp_path):
    repo = make_repo(tmp_path)
    result = scan(repo / "services" / "api", ScanConfig(standards=frozenset({"web"})))
    assert "file=services/api/app.py" in github.render(result)


def test_scanning_the_repo_root_adds_no_prefix(tmp_path):
    repo = make_repo(tmp_path)
    result = scan(repo, ScanConfig(standards=frozenset({"web"})))
    assert result.path_prefix == ""
    assert result.repo_path(result.findings[0]) == "services/api/app.py"


def test_scanning_a_single_file_uses_its_directory(tmp_path):
    repo = make_repo(tmp_path)
    result = scan(repo / "services" / "api" / "app.py", ScanConfig(standards=frozenset({"web"})))
    assert result.repo_path(result.findings[0]) == "services/api/app.py"


def test_cli_repo_root_option_and_json_prefix(tmp_path):
    repo = make_repo(tmp_path)
    (repo / ".git").rmdir()  # no git root to find; the option must supply it
    scan_dir = str(repo / "services" / "api")
    out = CliRunner().invoke(
        main, ["scan", scan_dir, "-s", "web", "-o", "json", "--no-fail", "--repo-root", str(repo)]
    )
    assert json.loads(out.stdout)["path_prefix"] == "services/api"
    plain = CliRunner().invoke(main, ["scan", scan_dir, "-s", "web", "-o", "json", "--no-fail"])
    assert json.loads(plain.stdout)["path_prefix"] == ""


def test_cli_repo_root_from_environment(tmp_path):
    repo = make_repo(tmp_path)
    (repo / ".git").rmdir()
    out = CliRunner().invoke(
        main,
        ["scan", str(repo / "services"), "-s", "web", "-o", "github", "--no-fail"],
        env={"DECASCAN_REPO_ROOT": str(repo)},
    )
    assert "file=services/api/app.py" in out.stdout


def test_real_git_repository_is_detected(tmp_path):
    repo = tmp_path / "gitrepo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("DEBUG = True\n", encoding="utf-8")
    try:
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    result = scan(repo / "pkg", ScanConfig(standards=frozenset({"web"})))
    assert result.path_prefix == "pkg"


# --- merge -------------------------------------------------------------------------------------


def finding(rule_id, risk, severity=Severity.HIGH, confidence=0.8, line=5, cwe="CWE-78", file="a.py"):
    return Finding(
        rule_id=rule_id,
        mcp_id=risk,
        severity=severity,
        title=f"{rule_id} title",
        description="d",
        file_path=file,
        remediation="r",
        line=line,
        cwe_id=cwe,
        confidence=confidence,
    )


def test_same_line_and_cwe_across_lists_is_merged_into_the_strongest():
    mcp = finding("MCP05-001", "MCP05", Severity.CRITICAL, 0.7)
    web = finding("WEB03-002", "WEB03", Severity.HIGH, 0.65)
    llm = finding("LLM05-001", "LLM05", Severity.HIGH, 0.65)
    (kept,) = merge_cross_list([web, mcp, llm])
    assert kept.rule_id == "MCP05-001"
    assert kept.metadata["also_maps_to"] == "LLM05 (LLM05-001), WEB03 (WEB03-002)"


def test_equal_severity_prefers_confidence_then_the_mcp_list():
    a = finding("WEB03-002", "WEB03", confidence=0.9)
    b = finding("MCP05-001", "MCP05", confidence=0.7)
    assert merge_cross_list([a, b])[0].rule_id == "WEB03-002"
    c = finding("WEB03-002", "WEB03", confidence=0.7)
    assert merge_cross_list([c, b])[0].rule_id == "MCP05-001"


def test_different_cwe_line_or_file_is_not_merged():
    base = finding("MCP05-001", "MCP05")
    assert len(merge_cross_list([base, finding("WEB03-002", "WEB03", cwe="CWE-89")])) == 2
    assert len(merge_cross_list([base, finding("WEB03-002", "WEB03", line=6)])) == 2
    assert len(merge_cross_list([base, finding("WEB03-002", "WEB03", file="b.py")])) == 2


def test_two_findings_from_one_list_are_never_merged():
    one = finding("WEB03-001", "WEB03", cwe="CWE-89")
    two = finding("WEB03-001", "WEB03", cwe="CWE-89")
    assert len(merge_cross_list([one, two])) == 2


def test_findings_without_a_line_or_cwe_pass_through():
    a = finding("MCP07-001", "MCP07", line=None, cwe="CWE-306")
    b = finding("WEB05-002", "WEB05", line=None, cwe="CWE-306")
    c = finding("WEB02-001", "WEB02", cwe=None)
    d = finding("MCP01-001", "MCP01", cwe=None)
    assert len(merge_cross_list([a, b, c, d])) == 4


def test_merge_does_not_mutate_the_inputs():
    mcp = finding("MCP05-001", "MCP05", Severity.CRITICAL)
    web = finding("WEB03-002", "WEB03")
    merge_cross_list([mcp, web])
    assert mcp.metadata == {} and web.metadata == {}


def test_a_scan_reports_one_finding_per_defect_by_default(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask\nimport openai\nSECRET_KEY = 'Zk39fQ81-live-signing-key'\n"
        "eval(response)\n",
        encoding="utf-8",
    )
    default = scan(tmp_path, ScanConfig())
    kept = scan(tmp_path, ScanConfig(merge_duplicates=False))
    assert len(default.findings) < len(kept.findings)
    merged = [f for f in default.findings if f.metadata.get("also_maps_to")]
    assert merged and all(f.line for f in merged)


def test_cli_keep_duplicates_restores_per_list_findings(tmp_path):
    (tmp_path / "app.py").write_text("import openai\neval(response)\n", encoding="utf-8")
    runner = CliRunner()

    def count(*extra):
        out = runner.invoke(main, ["scan", str(tmp_path), "-s", "all", "-o", "json", "--no-fail", *extra])
        return json.loads(out.stdout)["summary"]["findings"]

    assert count("--keep-duplicates") > count()


def test_pretty_and_sarif_show_the_other_mappings(tmp_path):
    (tmp_path / "app.py").write_text("import openai\neval(response)\n", encoding="utf-8")
    result = scan(tmp_path, ScanConfig(standards=frozenset({"llm", "web"})))
    out = CliRunner().invoke(main, ["scan", str(tmp_path), "-s", "llm", "-s", "web", "--no-fail"]).output
    assert "Also maps to:" in out
    props = json.loads(sarif.render(result))["runs"][0]["results"][0]["properties"]
    assert props["alsoMapsTo"]
