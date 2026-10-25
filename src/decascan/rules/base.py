"""Rule registry. A rule is a function from ScanContext to findings, plus metadata."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..core.context import ScanContext
from ..core.findings import Finding
from ..core.standards import RISK_STANDARD

RuleFn = Callable[[ScanContext], Iterable[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    mcp_id: str
    name: str
    description: str
    fn: RuleFn

    @property
    def standard(self) -> str:
        return RISK_STANDARD[self.mcp_id]


REGISTRY: list[Rule] = []


def rule(id: str, mcp_id: str, name: str, description: str) -> Callable[[RuleFn], RuleFn]:
    def decorate(fn: RuleFn) -> RuleFn:
        REGISTRY.append(Rule(id=id, mcp_id=mcp_id, name=name, description=description, fn=fn))
        return fn

    return decorate
