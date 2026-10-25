"""Where the scanned directory sits inside its repository.

Findings carry paths relative to the directory that was scanned, which is what a person at a
terminal expects. Tools that map findings onto a repository -- GitHub code scanning and PR
annotations -- need paths relative to the *repository root*. Scanning `src` of a repo and reporting
`decascan/cli.py` makes GitHub look for a file that does not exist, so SARIF and annotation output
prepend the scan directory's position inside the repository.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def find_git_root(start: Path) -> Path | None:
    """The nearest ancestor of `start` (inclusive) containing a `.git` directory or file."""
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def resolve_repo_root(
    scan_root: Path, explicit: Path | None = None, env: Mapping[str, str] | None = None
) -> Path | None:
    """Pick the repository root: an explicit choice, then GITHUB_WORKSPACE, then the git root."""
    env = os.environ if env is None else env
    scan_root = scan_root.resolve()
    if explicit is not None:
        return explicit.resolve()
    workspace = env.get("GITHUB_WORKSPACE")
    if workspace:
        candidate = Path(workspace).resolve()
        if _is_inside(scan_root, candidate):
            return candidate
    return find_git_root(scan_root)


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def path_prefix(scan_root: Path, repo_root: Path | None) -> str:
    """The scan directory relative to the repository root, POSIX style ("" when they coincide).

    Empty when there is no repository root, or when the scan directory is outside it -- a prefix
    that points nowhere is worse than none.
    """
    if repo_root is None:
        return ""
    scan_root = scan_root.resolve()
    repo_root = repo_root.resolve()
    if not _is_inside(scan_root, repo_root):
        return ""
    relative = scan_root.relative_to(repo_root).as_posix()
    return "" if relative == "." else relative


def repo_path(prefix: str, file_path: str) -> str:
    """`file_path` (relative to the scan directory) relative to the repository root."""
    return f"{prefix}/{file_path}" if prefix else file_path
