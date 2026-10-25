"""Repository files that are easy to let rot: CODEOWNERS and the links in the README."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"


def entries() -> list[tuple[str, list[str]]]:
    out = []
    for raw in CODEOWNERS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            pattern, *owners = line.split()
            out.append((pattern, owners))
    return out


def test_codeowners_has_a_default_owner_for_everything():
    assert entries()[0][0] == "*"  # first, so the specific patterns below override it


def test_every_entry_names_at_least_one_owner_and_owners_look_like_handles():
    for pattern, owners in entries():
        assert owners, f"{pattern} has no owner"
        for owner in owners:
            assert re.fullmatch(r"@[\w.-]+(/[\w.-]+)?|[^@\s]+@[^@\s]+", owner), f"{pattern}: {owner}"


def test_no_pattern_is_listed_twice():
    patterns = [p for p, _ in entries()]
    assert len(patterns) == len(set(patterns))


def test_every_path_pattern_points_at_something_that_exists():
    for pattern, _ in entries():
        if pattern == "*":
            continue
        assert (ROOT / pattern.lstrip("/")).exists(), f"CODEOWNERS pattern {pattern} matches nothing"


def test_the_sensitive_paths_are_covered():
    patterns = {p for p, _ in entries()}
    for needed in ("/.github/", "/action.yml", "/src/mcp_sift/rules/", "/src/mcp_sift/data/", "/pyproject.toml"):
        assert needed in patterns, f"{needed} has no explicit owner"


def test_codeowners_sits_where_github_reads_it():
    assert CODEOWNERS.is_file()
    assert not (ROOT / "CODEOWNERS").exists() and not (ROOT / "docs" / "CODEOWNERS").exists()


def test_readme_links_to_files_in_this_repository_resolve():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    links = re.findall(r"\(https://github\.com/cvas22/mcp-sift/blob/main/([^)#\s]+)", readme)
    assert links, "expected the README to link to docs in the repository"
    for link in links:
        assert (ROOT / link).exists(), f"README links to {link}, which does not exist"


def test_readme_documents_the_commands_a_contributor_runs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for command in ("pytest", "ruff check .", "generate_rule_docs.py --check", "uv build"):
        assert command in readme
    assert "## Contributing" in readme and "CODEOWNERS" in readme


def test_the_maintainer_is_named_in_the_readme_and_codeowners_and_matches_the_package_author():
    name = "Srinivas Chippagiri"
    assert name in (ROOT / "README.md").read_text(encoding="utf-8")
    assert name in CODEOWNERS.read_text(encoding="utf-8")
    assert f'authors = [{{ name = "{name}" }}]' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
