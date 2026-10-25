"""MCP04 — Supply Chain / Dependency Tampering.

An MCP server's dependencies execute with the server's privileges, which are the developer's
privileges. The question every rule here asks is the same one: between the moment you review this
server and the moment it runs, can the code it installs change without anyone noticing?

Three ways it can, in descending order of how much they should worry you:

  1. A package is fetched from somewhere other than a registry — a git branch, a URL, a path. There
     is no immutable artifact behind it, so the bytes can change while the reference does not.
  2. An npm lifecycle script runs code at install time, before a human reads any of it.
  3. Versions float and nothing records what was resolved, so two installs need not agree.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.context import ScanContext
from ..core.findings import Finding, Severity
from ..parsers.common import Dependency
from .base import rule

# A local path dependency that *is* the project (`-e .`) is the developer installing their own
# code, not a third-party artifact of unknown provenance.
_SELF_REFERENCES = {".", "./", "-e .", "-e ./", ""}

_SOURCE_LABELS = {
    "vcs": "a version-control reference",
    "url": "a direct URL",
    "path": "a local path",
}


def _third_party(deps: Iterable[Dependency]) -> list[Dependency]:
    return [d for d in deps if d.name.strip() not in _SELF_REFERENCES]


@rule(
    id="MCP04-001",
    mcp_id="MCP04",
    name="Dependency from a non-registry source",
    description="A package is installed from a git ref, URL, or path rather than an immutable release.",
)
def non_registry_dependency(ctx: ScanContext) -> Iterable[Finding]:
    for dep in _third_party(ctx.dependencies):
        if dep.source == "registry":
            continue

        label = _SOURCE_LABELS.get(dep.source, dep.source)
        yield Finding(
            rule_id="MCP04-001",
            mcp_id="MCP04",
            severity=Severity.HIGH if dep.source in ("vcs", "url") else Severity.MEDIUM,
            title=f"`{dep.name}` is installed from {label}, not a registry",
            description=(
                f"`{dep.file}` pulls `{dep.name}` from {label} (`{dep.spec}`). A registry release is "
                "an immutable artifact with a hash behind it; a branch, tag, or URL is a moving "
                "target. Whoever controls that source can change the code between your review and "
                "your install, and the reference in this file will look exactly the same."
            ),
            file_path=dep.file,
            line=dep.line,
            snippet=ctx.line(dep.file, dep.line).strip() or None,
            remediation=(
                f"Depend on a published release of `{dep.name}` from the registry and pin it. If you "
                "must track a git source, pin the full commit SHA rather than a branch or tag — a "
                "tag can be moved, a SHA cannot."
            ),
            cwe_id="CWE-829",
            confidence=0.9,
            metadata={"dependency": dep.name, "source": dep.source, "ecosystem": dep.ecosystem},
        )


@rule(
    id="MCP04-002",
    mcp_id="MCP04",
    name="Floating dependencies with no lockfile",
    description="Versions are unpinned and nothing records what was resolved, so installs can differ.",
)
def unpinned_without_lockfile(ctx: ScanContext) -> Iterable[Finding]:
    if ctx.has_lockfile:
        return  # the lockfile records the resolved versions; the range in the manifest is not what installs

    floating: dict[str, list[Dependency]] = {}
    for dep in _third_party(ctx.dependencies):
        if dep.source == "registry" and not dep.pinned:
            floating.setdefault(dep.file, []).append(dep)

    for file, deps in floating.items():
        names = ", ".join(f"`{d.name}`" for d in deps[:4])
        more = f" and {len(deps) - 4} more" if len(deps) > 4 else ""
        yield Finding(
            rule_id="MCP04-002",
            mcp_id="MCP04",
            severity=Severity.MEDIUM,
            title=f"{len(deps)} dependencies in `{file}` float, and there is no lockfile",
            description=(
                f"{names}{more} are declared as ranges rather than exact versions, and no lockfile "
                "in this repository records what those ranges resolved to. Two installs a day apart "
                "can therefore ship different code, and a compromised release of any transitive "
                "dependency lands in this server the next time someone runs an install — with no "
                "diff for a reviewer to see."
            ),
            file_path=file,
            line=deps[0].line,
            snippet=ctx.line(file, deps[0].line).strip() or None,
            remediation=(
                "Commit a lockfile (`uv.lock`, `poetry.lock`, `package-lock.json`) so the resolved "
                "versions are reviewable and reproducible. Pinning exact versions in the manifest "
                "works too, but a lockfile is better: it covers transitive dependencies, which is "
                "where supply-chain attacks actually land."
            ),
            cwe_id="CWE-1357",
            confidence=0.75,
            metadata={"count": str(len(deps)), "file": file},
        )


@rule(
    id="MCP04-003",
    mcp_id="MCP04",
    name="Code executes at install time",
    description="An npm lifecycle script runs before anyone has reviewed the package.",
)
def install_time_execution(ctx: ScanContext) -> Iterable[Finding]:
    for script in ctx.install_scripts:
        yield Finding(
            rule_id="MCP04-003",
            mcp_id="MCP04",
            severity=Severity.HIGH,
            title=f"`{script.name}` runs code during `npm install`",
            description=(
                f"`{script.file}` defines a `{script.name}` script (`{script.command}`). It executes "
                "on every install, with the installing user's privileges, before a human has read a "
                "line of what was downloaded. Install hooks are the standard delivery mechanism for "
                "a compromised npm package, and an MCP server is installed by exactly the developers "
                "whose machines are worth compromising."
            ),
            file_path=script.file,
            line=script.line,
            snippet=ctx.line(script.file, script.line).strip() or None,
            remediation=(
                f"Remove the `{script.name}` hook and do the work in an explicit build step the "
                "installer chooses to run. If it genuinely must run at install time, say so in the "
                "README — and expect consumers to install with `--ignore-scripts`."
            ),
            cwe_id="CWE-829",
            confidence=0.85,
            metadata={"hook": script.name},
        )
