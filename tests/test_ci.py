"""CI/CD surface: the `github` output format, exit codes, and the shipped action/hook files."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mcp_sift.cli import main
from mcp_sift.core.findings import Finding, Severity
from mcp_sift.core.scanner import ScanResult
from mcp_sift.outputs import github

ROOT = Path(__file__).parent.parent
FIXTURES = ROOT / "tests" / "fixtures"


def finding(severity=Severity.HIGH, path="src/a.py", line=3, title="Bad thing", description="d"):
    return Finding(
        rule_id="WEB05-001",
        mcp_id="WEB05",
        severity=severity,
        title=title,
        description=description,
        file_path=path,
        remediation="fix it",
        line=line,
    )


def result(findings, errors=()):
    return ScanResult(
        findings=list(findings),
        files_scanned=2,
        rules_run=5,
        duration_seconds=0.1,
        errors=list(errors),
    )


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "notice"),
        (Severity.INFO, "notice"),
    ],
)
def test_severity_maps_to_annotation_level(severity, level):
    first = github.render(result([finding(severity)])).splitlines()[0]
    assert first.startswith(f"::{level} ")


def test_annotation_carries_file_line_title_and_fix():
    line = github.render(result([finding()])).splitlines()[0]
    assert "file=src/a.py" in line and "line=3" in line
    assert "title=WEB05-001 Bad thing" in line
    assert line.endswith("Fix: fix it")


def test_annotation_without_a_line_omits_the_property():
    line = github.render(result([finding(line=None)])).splitlines()[0]
    assert "line=" not in line


def test_workflow_command_metacharacters_are_escaped():
    nasty = finding(path="a,b:c.py", title="100% bad\nnew line", description="x\r\ny")
    line = github.render(result([nasty])).splitlines()[0]
    assert "file=a%2Cb%3Ac.py" in line
    assert "100%25 bad%0Anew line" in line
    assert "\n" not in line and "\r" not in line
    assert "x%0D%0Ay" in line


def test_scan_errors_become_warnings_and_a_summary_closes_the_output():
    lines = github.render(result([finding()], errors=["boom"]), "9.9").splitlines()
    assert "::warning title=mcp-sift::boom" in lines
    assert lines[-1].startswith("::notice title=mcp-sift 9.9::2 files scanned: 1 high")


def test_empty_result_still_prints_a_summary():
    assert github.render(result([])) == "::notice title=mcp-sift 0.1.0::2 files scanned: no findings"


def test_cli_github_format_end_to_end():
    out = CliRunner().invoke(
        main, ["scan", str(FIXTURES / "vulnerable_webllm"), "-o", "github", "--no-fail"]
    ).output
    # Repo-relative: the fixture lives under tests/fixtures inside the repository.
    assert out.startswith("::error file=tests/fixtures/vulnerable_webllm/app.py,line=")
    assert "title=WEB03-001 " in out


@pytest.mark.parametrize(
    ("fixture", "args", "code"),
    [
        ("clean_webllm", [], 0),
        ("vulnerable_webllm", [], 1),
        ("vulnerable_webllm", ["--no-fail"], 0),
        ("vulnerable_webllm", ["--fail-on", "critical"], 1),
        ("clean_webllm", ["--fail-on", "info"], 0),
    ],
)
def test_exit_codes_are_the_pipeline_contract(fixture, args, code):
    assert CliRunner().invoke(main, ["scan", str(FIXTURES / fixture), *args]).exit_code == code


def test_bad_invocation_exits_two():
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(FIXTURES), "--rule", "NOPE-999"]).exit_code == 2
    assert runner.invoke(main, ["scan", str(FIXTURES / "missing")]).exit_code == 2
    assert runner.invoke(main, ["scan", str(FIXTURES), "-s", "bogus"]).exit_code == 2


def test_sarif_to_file_is_valid_for_upload(tmp_path):
    out = tmp_path / "r.sarif"
    result_ = CliRunner().invoke(
        main, ["scan", str(FIXTURES / "vulnerable_webllm"), "-o", "sarif", "-f", str(out), "--no-fail"]
    )
    assert result_.exit_code == 0
    import json

    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]


# --- shipped CI files --------------------------------------------------------------------------


def load(rel: str) -> dict:
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def test_action_metadata_is_a_composite_action_with_documented_inputs():
    action = load("action.yml")
    assert action["runs"]["using"] == "composite"
    assert {"path", "standard", "fail-on", "upload-sarif", "sarif-file"} <= set(action["inputs"])
    assert {"sarif-file", "exit-code"} == set(action["outputs"])


def test_action_never_interpolates_inputs_into_script_text():
    for step in load("action.yml")["runs"]["steps"]:
        script = step.get("run", "")
        assert "${{" not in script, f"input interpolated into a shell script in step {step.get('name')}"


def test_action_defaults_match_the_cli_defaults():
    inputs = load("action.yml")["inputs"]
    assert inputs["standard"]["default"] == "auto"
    assert inputs["fail-on"]["default"] == "high"


def test_pre_commit_hook_scans_the_whole_tree():
    (hook,) = load(".pre-commit-hooks.yaml")
    assert hook["id"] == "mcp-sift" and hook["pass_filenames"] is False
    assert hook["entry"] == "mcp-sift scan"


def test_the_ci_job_exercises_the_action():
    ci = load(".github/workflows/ci.yml")
    assert "action" in ci["jobs"]
    uses = [s.get("uses") for s in ci["jobs"]["action"]["steps"]]
    assert "./" in uses


def test_ci_documentation_covers_every_documented_system():
    docs = (ROOT / "docs" / "ci.md").read_text(encoding="utf-8")
    for system in ("GitHub Actions", "pre-commit", "GitLab CI", "Jenkins", "Azure Pipelines", "CircleCI"):
        assert system in docs


def test_ci_has_a_unit_test_gate_with_a_coverage_floor():
    ci = load(".github/workflows/ci.yml")
    steps = " ".join(str(s.get("run", "")) for s in ci["jobs"]["unit-tests"]["steps"])
    assert "pytest" in steps and "--cov=mcp_sift" in steps and "--junitxml" in steps
    assert set(ci["jobs"]["ci-pass"]["needs"]) == {"unit-tests", "test", "linux-distros", "action"}
    # tomllib is 3.11+, and this project still supports 3.10, so read the one value by hand.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"^fail_under\s*=\s*(\d+)", pyproject, re.M)
    assert match and int(match.group(1)) >= 80


def test_release_is_gated_on_the_ci_suite():
    release = load(".github/workflows/release.yml")
    assert release["jobs"]["tests"]["uses"] == "./.github/workflows/ci.yml"
    assert release["jobs"]["pypi"]["needs"] == "tests"
    assert "workflow_call" in load(".github/workflows/ci.yml")[True]  # YAML parses `on:` as True


def test_source_distribution_excludes_local_tooling_output():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = pyproject[pyproject.index("[tool.hatch.build.targets.sdist]") :]
    assert "/graphify-out" in section and "/uv.lock" in section
    assert "graphify-out/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
