"""Work out which Top 10 lists apply to a codebase from what it imports and depends on.

`--standard auto` (the default) uses this so an MCP server is audited against the MCP list, a Flask
app against the web list, and a LangChain agent against the LLM list -- without the user having to
know which rule sets exist. Detection is evidence-based and reports the evidence, so the choice is
never a black box.
"""

from __future__ import annotations

import re

from .context import ScanContext
from .log import get_logger

log = get_logger("detect")

# Package names (pypi / npm), matched against declared dependencies and import statements.
_SIGNALS: dict[str, tuple[str, ...]] = {
    "mcp": ("mcp", "fastmcp", "@modelcontextprotocol/sdk", "mcp-server", "mcp-use"),
    "llm": (
        "openai", "anthropic", "langchain", "langchain-core", "langchain-openai", "langgraph",
        "llama-index", "llama_index", "transformers", "huggingface-hub", "huggingface_hub", "vllm",
        "litellm", "ollama", "cohere", "mistralai", "google-generativeai", "google.generativeai",
        "google-genai", "crewai", "autogen", "pydantic-ai", "@anthropic-ai/sdk", "ai", "@langchain/core",
        "@google/generative-ai", "ollama-js",
    ),
    "web": (
        "flask", "django", "fastapi", "starlette", "aiohttp", "tornado", "sanic", "bottle", "pyramid",
        "falcon", "quart", "express", "koa", "fastify", "next", "hono", "@nestjs/core", "hapi",
        "@hapi/hapi", "restify",
    ),
}  # fmt: skip

_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*)|"
    r"(?:import|export)\b[^\n]*?from\s+[\"']([^\"']+)[\"']|"
    r"(?:const|let|var)\b[^\n]*?require\(\s*[\"']([^\"']+)[\"']\s*\))",
    re.M,
)


def _normalise(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _root_modules(module: str) -> set[str]:
    """`langchain_openai.chat_models` -> {"langchain-openai", "langchain"}; `@a/b/c` -> {"@a/b"}."""
    if module.startswith("@"):
        return {"/".join(module.split("/")[:2]).lower()}
    parts = module.split(".") if "." in module and "/" not in module else module.split("/")
    first = _normalise(parts[0])
    roots = {first}
    if "-" in first:
        roots.add(first.split("-")[0])
    if len(parts) > 1:
        roots.add(_normalise(".".join(parts[:2])))
    return roots


def detect_standards(ctx: ScanContext) -> dict[str, list[str]]:
    """Map each applicable standard id to the evidence that selected it (empty dict = nothing found)."""
    lookup = {_normalise(sig): std for std, sigs in _SIGNALS.items() for sig in sigs}
    # Names that are ordinary words are only trusted as declared dependencies, never as bare import
    # roots, so a local module called `ai` or `next` does not select a list.
    weak = {"ai", "next", "koa", "hapi"}
    evidence: dict[str, list[str]] = {}

    def add(standard: str, why: str) -> None:
        bucket = evidence.setdefault(standard, [])
        if why not in bucket and len(bucket) < 3:
            bucket.append(why)

    for dep in ctx.dependencies:
        standard = lookup.get(_normalise(dep.name))
        if standard:
            add(standard, f"depends on {dep.name}")

    if ctx.is_mcp_server:
        add("mcp", "defines MCP tools or a server")

    for rel in ctx.source_facts:
        for match in _IMPORT_RE.finditer(ctx.text(rel)):
            module = next(group for group in match.groups() if group)
            for root in _root_modules(module):
                standard = lookup.get(root)
                if standard and root not in weak:
                    add(standard, f"imports {module}")
                elif standard:
                    log.debug("import ignored: name too generic", extra={"file": rel, "imported": module})
    for standard, reasons in sorted(evidence.items()):
        log.debug("list detected", extra={"standard": standard, "evidence": "; ".join(reasons)})
    if not evidence:
        log.debug("no list recognised from imports or dependencies")
    return evidence
