"""Rule registry. Importing this package registers every built-in rule."""

from __future__ import annotations

from . import (  # noqa: F401  (imported for the registration side effect)
    mcp01_secrets,
    mcp02_scope,
    mcp03_tool_poisoning,
    mcp04_supply_chain,
    mcp05_command_injection,
    mcp06_prompt_injection,
    mcp07_auth,
    mcp08_audit,
    mcp09_shadow_servers,
    mcp10_context,
)
from .base import REGISTRY, Rule, rule

__all__ = ["REGISTRY", "Rule", "rule", "all_rules"]


def all_rules() -> list[Rule]:
    return sorted(REGISTRY, key=lambda r: r.id)
