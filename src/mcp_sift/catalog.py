"""A serializable snapshot of the Top 10 lists and the rules mapped to them.

The checked-in copy lives at `data/top10.json` (shipped inside the package). It is generated from
the code by `mcp-sift standards --export`, and a test fails when the two drift apart, so the file is
always a faithful offline reference for what each version of the scanner covers.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from .core.standards import STANDARDS
from .rules import all_rules

SCHEMA_VERSION = 1


def build_catalog() -> dict:
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
    return json.dumps(build_catalog(), indent=2, ensure_ascii=False) + "\n"


def export_catalog(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_catalog(), encoding="utf-8", newline="\n")


def load_cached_catalog() -> dict:
    """The snapshot shipped with this release, without importing or running any rule."""
    text = resources.files("mcp_sift").joinpath("data/top10.json").read_text(encoding="utf-8")
    return json.loads(text)
