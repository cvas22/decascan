"""Read the packages a server pulls in at install time (MCP04).

An MCP server's dependencies run with the server's privileges, which are the developer's
privileges. Everything here is about one question: between the moment you review this server and
the moment it runs on your machine, can the code it installs change out from under you?

`pyproject.toml` is read with a regex rather than `tomllib` on purpose. `tomllib` is 3.11+, this
package supports 3.10, and a parser that silently degrades on one interpreter would make findings
depend on which Python you happened to run the scanner with. The regex also gives us line numbers,
which `tomllib` throws away.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .common import Dependency, InstallScript

REQUIREMENTS_NAMES = {"requirements.txt", "requirements-dev.txt", "requirements_dev.txt"}
DEPENDENCY_NAMES = REQUIREMENTS_NAMES | {"pyproject.toml", "package.json"}

# The presence of any of these means the resolved versions are recorded, so a loose range in the
# manifest is not actually a floating dependency.
LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "pdm.lock",
    "requirements.lock",
}

# npm lifecycle hooks: code that runs on `npm install`, before a human reads a line of the package.
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

_PEP508 = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<spec>[<>=!~^].*)?$"
)
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+", "git:", "github:", "gitlab:", "bitbucket:")
_URL_PREFIXES = ("http://", "https://")
_PATH_PREFIXES = ("file:", "./", "../", "/", ".\\", "link:", "portal:")

_TOML_SECTION = re.compile(r"^\s*\[+\s*([^\]]+?)\s*\]+\s*$")
_TOML_ARRAY_START = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*=\s*\[(?P<rest>.*)$")
_TOML_KEY_VALUE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*=\s*(?P<value>.+?)\s*$")
_TOML_STRING = re.compile(r"[\"']([^\"']+)[\"']")

# Poetry declares dependencies as a table of `name = "^1.2"` rather than a PEP 508 array.
_POETRY_SECTIONS = ("tool.poetry.dependencies", "tool.poetry.dev-dependencies")


def _pypi_source(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered.startswith(_VCS_PREFIXES):
        return "vcs"
    if lowered.startswith(_URL_PREFIXES):
        return "url"
    if lowered.startswith(_PATH_PREFIXES) or lowered.startswith("-e "):
        return "path"
    if " @ " in raw:  # PEP 508 direct reference: `name @ https://…`
        target = raw.split(" @ ", 1)[1].strip().lower()
        if target.startswith(_VCS_PREFIXES):
            return "vcs"
        if target.startswith(_URL_PREFIXES):
            return "url"
        return "path"
    return "registry"


def _is_pinned_pypi(spec: str) -> bool:
    """Only `==` and `===` pin a Python dependency. `>=`, `~=` and `*` all float."""
    spec = spec.strip()
    if not spec:
        return False
    return spec.startswith("==") or spec.startswith("===")


def _npm_source(spec: str) -> str:
    lowered = spec.strip().lower()
    if lowered.startswith(_VCS_PREFIXES) or "github.com" in lowered and lowered.startswith("git"):
        return "vcs"
    if lowered.startswith(_URL_PREFIXES):
        return "url"
    if lowered.startswith(_PATH_PREFIXES):
        return "path"
    return "registry"


def _is_pinned_npm(spec: str) -> bool:
    """An exact semver string pins; `^`, `~`, ranges, `*`, `latest` and tags do not."""
    spec = spec.strip()
    if not spec or spec in ("*", "latest", "next"):
        return False
    return bool(re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][\w.]+)?", spec))


def _parse_requirements(text: str, rel: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        # pip's rule: `#` starts a comment only at the start of a line or after whitespace. A bare
        # `#` is a URL fragment (`#egg=name`, `#sha256=...`), and cutting there lost the package name.
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].strip()
        if not line or line.startswith(("-r", "--requirement", "-c", "--constraint", "--index")):
            continue

        source = _pypi_source(line)
        if source != "registry":
            name = _name_from_direct_reference(line)
            deps.append(
                Dependency(
                    name=name,
                    spec=line,
                    file=rel,
                    line=line_no,
                    ecosystem="pypi",
                    source=source,
                    pinned=False,
                )
            )
            continue

        match = _PEP508.match(line)
        if not match:
            continue
        spec = (match.group("spec") or "").strip()
        deps.append(
            Dependency(
                name=match.group("name"),
                spec=spec,
                file=rel,
                line=line_no,
                ecosystem="pypi",
                source="registry",
                pinned=_is_pinned_pypi(spec),
            )
        )
    return deps


def _name_from_direct_reference(line: str) -> str:
    if " @ " in line:
        return line.split(" @ ", 1)[0].strip()
    if "#egg=" in line:
        return line.split("#egg=", 1)[1].strip()
    return line.removeprefix("-e ").strip().rstrip("/").split("/")[-1] or line.strip()


def _is_dependency_array(section: str, key: str) -> bool:
    """Only the arrays that actually install code. `classifiers` and `keywords` are not packages."""
    if section == "project" and key == "dependencies":
        return True
    if section == "project.optional-dependencies":
        return True  # every key here is an extra, and every extra is a dependency list
    if section == "build-system" and key == "requires":
        return True  # build-time code runs too
    if section.startswith("dependency-groups"):
        return True
    return False


def _parse_pyproject(text: str, rel: str) -> list[Dependency]:
    """Line-scan the TOML, tracking the current section.

    A regex over the whole file would happily read `classifiers` and ruff's `select` as
    dependencies. Sections are the only thing that says which arrays install code.
    """
    deps: list[Dependency] = []
    section = ""
    pending_key: str | None = None  # set while inside a multi-line array

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0] if not _inside_string(raw, raw.find("#")) else raw

        header = _TOML_SECTION.match(line)
        if header:
            section, pending_key = header.group(1), None
            continue

        if pending_key is not None:
            deps.extend(_deps_from_toml_line(line, rel, line_no))
            if "]" in line:
                pending_key = None
            continue

        if section in _POETRY_SECTIONS:
            dep = _poetry_dependency(line, rel, line_no)
            if dep:
                deps.append(dep)
            continue

        array = _TOML_ARRAY_START.match(line)
        if array and _is_dependency_array(section, array.group("key")):
            deps.extend(_deps_from_toml_line(array.group("rest"), rel, line_no))
            if "]" not in array.group("rest"):
                pending_key = array.group("key")

    return deps


def _inside_string(line: str, index: int) -> bool:
    """A `#` inside a quoted spec (`urllib3 ; python_version < '3'`) is not a comment."""
    if index == -1:
        return False
    return line.count('"', 0, index) % 2 == 1 or line.count("'", 0, index) % 2 == 1


def _deps_from_toml_line(fragment: str, rel: str, line_no: int) -> list[Dependency]:
    out: list[Dependency] = []
    for match in _TOML_STRING.finditer(fragment):
        requirement = match.group(1).strip()
        if not requirement:
            continue
        parsed = _parse_requirements(requirement, rel)
        if parsed:
            parsed[0].line = line_no
            out.append(parsed[0])
    return out


def _poetry_dependency(line: str, rel: str, line_no: int) -> Dependency | None:
    match = _TOML_KEY_VALUE.match(line)
    if not match:
        return None
    name, value = match.group("key"), match.group("value").strip()
    if name.lower() == "python":  # the interpreter, not a package
        return None

    if value.startswith("{"):
        source = "vcs" if ("git" in value or "url" in value) else "registry"
        if "path" in value:
            source = "path"
        version = _TOML_STRING.search(value)
        spec = version.group(1) if version else ""
        return Dependency(
            name=name,
            spec=spec,
            file=rel,
            line=line_no,
            ecosystem="pypi",
            source=source,
            pinned=False,
        )

    quoted = _TOML_STRING.match(value)
    if not quoted:
        return None
    spec = quoted.group(1)
    # Poetry's `^1.2` / `~1.2` are caret/tilde ranges; only a bare version is a pin.
    return Dependency(
        name=name,
        spec=spec,
        file=rel,
        line=line_no,
        ecosystem="pypi",
        source="registry",
        pinned=bool(re.fullmatch(r"v?\d+(?:\.\d+)*", spec)),
    )


def _parse_package_json(text: str, rel: str) -> tuple[list[Dependency], list[InstallScript]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return [], []
    if not isinstance(data, dict):
        return [], []

    lines = text.splitlines()
    deps: list[Dependency] = []

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            deps.append(
                Dependency(
                    name=str(name),
                    spec=spec,
                    file=rel,
                    line=_line_of_key(lines, str(name)),
                    ecosystem="npm",
                    source=_npm_source(spec),
                    pinned=_is_pinned_npm(spec),
                )
            )

    scripts: list[InstallScript] = []
    raw_scripts = data.get("scripts")
    if isinstance(raw_scripts, dict):
        for hook in INSTALL_HOOKS:
            command = raw_scripts.get(hook)
            if isinstance(command, str) and command.strip():
                scripts.append(
                    InstallScript(
                        name=hook,
                        command=command,
                        file=rel,
                        line=_line_of_key(lines, hook),
                    )
                )
    return deps, scripts


def _line_of_key(lines: list[str], key: str) -> int:
    needle = f'"{key}"'
    for line_no, line in enumerate(lines, start=1):
        if needle in line:
            return line_no
    return 1


def is_dependency_file(name: str) -> bool:
    return name in DEPENDENCY_NAMES


def is_lockfile(name: str) -> bool:
    return name in LOCKFILE_NAMES


def load_dependencies(path: Path, rel: str) -> tuple[list[Dependency], list[InstallScript]]:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return [], []

    name = path.name
    if name == "package.json":
        return _parse_package_json(text, rel)
    if name == "pyproject.toml":
        return _parse_pyproject(text, rel), []
    if name in REQUIREMENTS_NAMES:
        return _parse_requirements(text, rel), []
    return [], []
