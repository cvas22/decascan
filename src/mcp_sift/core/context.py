"""ScanContext — everything the rules see. Built once per scan, read-only from a rule's view."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from ..parsers.common import Dependency, InstallScript, SourceFacts, ToolDef
from ..parsers.dependencies import (
    is_dependency_file,
    is_lockfile,
    load_dependencies,
)
from ..parsers.js_source import parse_javascript
from ..parsers.manifest import Manifest, is_manifest_name, load_manifest
from ..parsers.python_source import parse_python
from .config import SOURCE_SUFFIXES, TEXT_SUFFIXES, ScanConfig
from .lines import line_text
from .log import get_logger

log = get_logger("context")


@dataclass
class ScanContext:
    root: Path
    config: ScanConfig
    files: list[str] = field(default_factory=list)  # repo-relative, POSIX-ish
    manifests: list[Manifest] = field(default_factory=list)
    source_facts: dict[str, SourceFacts] = field(default_factory=dict)
    dependencies: list[Dependency] = field(default_factory=list)
    install_scripts: list[InstallScript] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    # Per-file failures (a parser crashed on a hostile or odd file). The scan carries on without that
    # file's facts and reports these as warnings.
    errors: list[str] = field(default_factory=list)
    _text_cache: dict[str, str] = field(default_factory=dict, repr=False)
    _minified_cache: dict[str, bool] = field(default_factory=dict, repr=False)

    @property
    def has_lockfile(self) -> bool:
        """A lockfile records the resolved versions, so a loose range is not actually floating."""
        return bool(self.lockfiles)

    @cached_property
    def is_mcp_server(self) -> bool:
        """Whether this codebase actually exposes an MCP server.

        Some rules describe a whole-server property (it logs nothing; it over-shares) rather than a
        specific line. Those must not fire on a repository that merely contains Python — only on one
        that is an MCP server. A tool, a server construction, or a manifest is the evidence.
        """
        return bool(self.all_tools or self.code_servers or self.manifests)

    def text(self, rel_path: str) -> str:
        if rel_path not in self._text_cache:
            try:
                # utf-8-sig: a byte-order mark (common from Windows editors) would otherwise reach the
                # Python parser as a stray character and the file would not be scanned at all.
                self._text_cache[rel_path] = (self.root / rel_path).read_text(
                    encoding="utf-8-sig", errors="replace"
                )
            except OSError:
                self._text_cache[rel_path] = ""
        return self._text_cache[rel_path]

    def is_minified(self, rel_path: str, max_line_chars: int) -> bool:
        """Whether any line is longer than `max_line_chars` (cached: every rule asks per file)."""
        if rel_path not in self._minified_cache:
            self._minified_cache[rel_path] = any(
                len(line) > max_line_chars for line in self.text(rel_path).split("\n")
            )
        return self._minified_cache[rel_path]

    def line(self, rel_path: str, line_no: int) -> str:
        return line_text(self.text(rel_path), line_no)

    @cached_property
    def code_tools(self) -> list[ToolDef]:
        return [tool for facts in self.source_facts.values() for tool in facts.tools]

    @cached_property
    def manifest_tools(self) -> list[ToolDef]:
        return [tool for manifest in self.manifests for tool in manifest.tools]

    @cached_property
    def all_tools(self) -> list[ToolDef]:
        return self.code_tools + self.manifest_tools

    @cached_property
    def code_servers(self) -> list:
        return [server for facts in self.source_facts.values() for server in facts.servers]

    @cached_property
    def taint_flows(self) -> list:
        return [flow for facts in self.source_facts.values() for flow in facts.taint_flows]

    @cached_property
    def external_returns(self) -> list:
        return [ret for facts in self.source_facts.values() for ret in facts.external_returns]

    def facts_for(self, rel_path: str) -> SourceFacts | None:
        return self.source_facts.get(rel_path)

    def tool_named(self, name: str, file: str | None = None) -> ToolDef | None:
        for tool in self.code_tools:
            if tool.name == name and (file is None or tool.file == file):
                return tool
        return None


def _walk(root: Path, excludes: tuple[str, ...], counts: dict[str, int]) -> Iterator[Path]:
    """Files under `root`, without entering excluded directories or following symlinks.

    Excluded directories are pruned before they are entered, so `node_modules` and virtualenvs cost
    nothing. Symlinks are skipped entirely: a link inside the scanned tree must not make the scanner
    read a file outside it (or loop forever through a link to a parent directory).
    """
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for name in sorted(dirnames):
            full = Path(current) / name
            if name in excludes:
                counts["excluded"] += 1
            elif full.is_symlink():
                counts["symlink"] += 1
                log.debug("symlinked directory skipped", extra={"file": str(full)})
            else:
                kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            full = Path(current) / name
            if full.is_symlink():
                counts["symlink"] += 1
                log.debug("symlinked file skipped", extra={"file": str(full)})
            else:
                yield full


def _guarded(ctx: ScanContext, rel: str, what: str, fn: Callable, *args):
    """Run one parser on one file; a crash costs that file's facts, never the whole scan."""
    try:
        return fn(*args)
    except Exception as exc:  # hostile input can raise RecursionError, MemoryError-adjacent errors, ...
        message = f"{rel}: {what} failed ({type(exc).__name__}: {str(exc)[:80]})"
        ctx.errors.append(message)
        log.warning("parser failed", extra={"file": rel, "parser": what, "error": type(exc).__name__})
        return None


def build_context(root: Path, config: ScanConfig) -> ScanContext:
    root = root.resolve()
    ctx = ScanContext(root=root, config=config)

    counts = {"excluded": 0, "too_large": 0, "unreadable": 0, "not_scannable": 0, "symlink": 0}
    if root.is_file():
        candidates: Iterator[Path] = iter([root])
        root = root.parent
        ctx.root = root
    else:
        candidates = _walk(root, config.excludes, counts)

    for path in candidates:
        try:
            if path.stat().st_size > config.max_file_bytes:
                counts["too_large"] += 1
                log.debug(
                    "file skipped: over size limit",
                    extra={"file": str(path), "limit": config.max_file_bytes},
                )
                continue
        except OSError:
            counts["unreadable"] += 1
            log.debug("file skipped: cannot stat", extra={"file": str(path)})
            continue

        suffix = path.suffix.lower()
        name = path.name
        is_env = name == ".env" or name.startswith(".env.")
        # Dependency files and lockfiles are matched by name: `requirements.txt` and `yarn.lock`
        # carry suffixes we otherwise have no reason to read.
        is_deps = is_dependency_file(name) or is_lockfile(name)
        if (
            suffix not in SOURCE_SUFFIXES
            and suffix not in TEXT_SUFFIXES
            and not is_env
            and not is_deps
        ):
            counts["not_scannable"] += 1
            continue

        rel = path.relative_to(root).as_posix()
        ctx.files.append(rel)

        if is_lockfile(name):
            ctx.lockfiles.append(rel)

        if is_dependency_file(name):
            parsed = _guarded(ctx, rel, "dependency parser", load_dependencies, path, rel)
            if parsed:
                ctx.dependencies.extend(parsed[0])
                ctx.install_scripts.extend(parsed[1])

        if is_manifest_name(name):
            manifest = _guarded(ctx, rel, "manifest parser", load_manifest, path, root)
            if manifest:
                ctx.manifests.append(manifest)

        if suffix == ".py":
            facts = _guarded(ctx, rel, "python parser", parse_python, rel, ctx.text(rel))
            if facts:
                ctx.source_facts[rel] = facts
        elif suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs"):
            facts = _guarded(ctx, rel, "javascript parser", parse_javascript, rel, ctx.text(rel))
            if facts:
                ctx.source_facts[rel] = facts

    log.info(
        "context built",
        extra={
            "files": len(ctx.files),
            "manifests": len(ctx.manifests),
            "tools": len(ctx.all_tools),
            "dependencies": len(ctx.dependencies),
            **{f"skipped_{k}": v for k, v in counts.items()},
        },
    )
    return ctx
