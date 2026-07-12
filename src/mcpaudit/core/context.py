"""ScanContext — everything the rules see. Built once per scan, read-only from a rule's view."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from ..parsers.common import SourceFacts, ToolDef
from ..parsers.js_source import parse_javascript
from ..parsers.manifest import Manifest, is_manifest_name, load_manifest
from ..parsers.python_source import parse_python
from .config import SOURCE_SUFFIXES, TEXT_SUFFIXES, ScanConfig


@dataclass
class ScanContext:
    root: Path
    config: ScanConfig
    files: list[str] = field(default_factory=list)  # repo-relative, POSIX-ish
    manifests: list[Manifest] = field(default_factory=list)
    source_facts: dict[str, SourceFacts] = field(default_factory=dict)
    _text_cache: dict[str, str] = field(default_factory=dict, repr=False)

    def text(self, rel_path: str) -> str:
        if rel_path not in self._text_cache:
            try:
                self._text_cache[rel_path] = (self.root / rel_path).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                self._text_cache[rel_path] = ""
        return self._text_cache[rel_path]

    def line(self, rel_path: str, line_no: int) -> str:
        lines = self.text(rel_path).splitlines()
        return lines[line_no - 1] if 0 < line_no <= len(lines) else ""

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

    def facts_for(self, rel_path: str) -> SourceFacts | None:
        return self.source_facts.get(rel_path)


def _is_excluded(path: Path, root: Path, excludes: tuple[str, ...]) -> bool:
    return any(part in excludes for part in path.relative_to(root).parts)


def build_context(root: Path, config: ScanConfig) -> ScanContext:
    root = root.resolve()
    ctx = ScanContext(root=root, config=config)

    if root.is_file():
        candidates = [root]
        root = root.parent
        ctx.root = root
    else:
        candidates = [p for p in root.rglob("*") if p.is_file()]

    for path in sorted(candidates):
        if _is_excluded(path, root, config.excludes):
            continue
        try:
            if path.stat().st_size > config.max_file_bytes:
                continue
        except OSError:
            continue

        suffix = path.suffix.lower()
        name = path.name
        is_env = name == ".env" or name.startswith(".env.")
        if suffix not in SOURCE_SUFFIXES and suffix not in TEXT_SUFFIXES and not is_env:
            continue

        rel = path.relative_to(root).as_posix()
        ctx.files.append(rel)

        if is_manifest_name(name):
            manifest = load_manifest(path, root)
            if manifest:
                ctx.manifests.append(manifest)

        if suffix == ".py":
            ctx.source_facts[rel] = parse_python(rel, ctx.text(rel))
        elif suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs"):
            ctx.source_facts[rel] = parse_javascript(rel, ctx.text(rel))

    return ctx
