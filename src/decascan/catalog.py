"""A serializable snapshot of the Top 10 lists and the rules mapped to them.

The checked-in copy is a directory, `data/top10/`, shipped inside the package, with one
self-contained file per list:

    mcp.json     the OWASP MCP Top 10 and its rules
    llm.json     the Top 10 for LLM Applications and its rules
    web.json     the web Top 10 and its rules

One file per list keeps diffs small (adding a rule touches one list's file), lets a consumer load only
the list it needs, and makes a new list a new file. There is no index: the lists are the files.

The directory is generated from the code by `decascan standards --export`, and a test fails when the
two drift apart, so it is always a faithful offline reference for what each version of the scanner
covers.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from .core.standards import STANDARDS
from .rules import all_rules

SCHEMA_VERSION = 1
DATA_DIR = "data/top10"


def _dump(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def build_catalog() -> dict:
    """All lists in one structure: {"schema": 1, "standards": {id: {name, version, risks}}}."""
    rules_by_risk: dict[str, list[dict[str, str]]] = {}
    for rule in all_rules():
        rules_by_risk.setdefault(rule.mcp_id, []).append(
            {"id": rule.id, "name": rule.name, "description": rule.description}
        )

    standards = {}
    for standard in STANDARDS.values():
        risks = []
        for risk_id, name in standard.risks.items():
            rules = rules_by_risk.get(risk_id, [])
            if rules:
                status = "covered"
            elif risk_id in standard.not_static:
                status = "not-static"
            else:
                status = "no-rules"
            risks.append({"id": risk_id, "name": name, "status": status, "rules": rules})
        standards[standard.id] = {"name": standard.name, "version": standard.version, "risks": risks}

    return {"schema": SCHEMA_VERSION, "standards": standards}


def render_catalog() -> str:
    return _dump(build_catalog())


def build_files() -> dict[str, str]:
    """The checked-in snapshot as {file name: text}: one self-contained file per list."""
    return {
        f"{standard_id}.json": _dump({"schema": SCHEMA_VERSION, "id": standard_id, **body})
        for standard_id, body in build_catalog()["standards"].items()
    }


def export_catalog(path: Path) -> list[Path]:
    """Write the snapshot. A directory gets one file per list.

    A path ending in `.json` writes the single combined file instead (the layout before the snapshot
    was split), for tools that still expect one file.
    """
    if path.suffix == ".json":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_catalog(), encoding="utf-8", newline="\n")
        return [path]
    path.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in build_files().items():
        target = path / name
        target.write_text(text, encoding="utf-8", newline="\n")
        written.append(target)
    return written


def _data():
    return resources.files("decascan").joinpath(DATA_DIR)


def cached_standard_ids() -> list[str]:
    """The lists present in the shipped snapshot: code order for known lists, then any others."""
    present = sorted(p.name.removesuffix(".json") for p in _data().iterdir() if p.name.endswith(".json"))
    known = list(STANDARDS)
    return sorted(present, key=lambda i: (known.index(i) if i in known else len(known), i))


def load_cached_standard(standard_id: str) -> dict:
    """One list from the shipped snapshot, without loading any other list or running any rule."""
    target = _data().joinpath(f"{standard_id}.json")
    available = cached_standard_ids()
    if standard_id not in available:
        raise ValueError(f"unknown standard {standard_id!r} (expected one of: {', '.join(available)})")
    return json.loads(target.read_text(encoding="utf-8"))


def load_cached_catalog() -> dict:
    """The shipped snapshot, assembled into the same shape `build_catalog` returns."""
    standards = {}
    for standard_id in cached_standard_ids():
        body = load_cached_standard(standard_id)
        standards[standard_id] = {k: v for k, v in body.items() if k not in {"schema", "id"}}
    return {"schema": SCHEMA_VERSION, "standards": standards}
