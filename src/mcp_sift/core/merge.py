"""Collapse one defect reported by several Top 10 lists into a single finding.

`os.system("ping " + host)` is command injection to the MCP list (MCP05), the web list (WEB03) and,
if the string is model output, the LLM list (LLM05). Reporting it three times triples the noise and
inflates the count without telling anyone anything new. When a scan covers several lists, findings
on the same line with the same CWE are merged: the strongest one is kept, and the others' risk ids
are recorded in `also_maps_to` so no list loses its mapping.

Only findings that agree on file, line *and* CWE are merged, and only across different lists. Two
different defects on one line, or the same defect reported twice by one list, stay separate.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace

from .findings import Finding


def _strength(finding: Finding) -> tuple:
    # Highest severity wins, then highest confidence, then the more specific (MCP) list, then id.
    return (
        finding.severity.rank,
        finding.confidence,
        finding.standard == "mcp",
        tuple(-ord(c) for c in finding.rule_id),
    )


def merge_cross_list(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    passthrough: list[Finding] = []
    for finding in findings:
        if finding.line is None or not finding.cwe_id:
            passthrough.append(finding)
        else:
            groups[(finding.file_path, finding.line, finding.cwe_id)].append(finding)

    merged: list[Finding] = list(passthrough)
    for group in groups.values():
        if len({f.standard for f in group}) < 2:
            merged.extend(group)
            continue
        primary = max(group, key=_strength)
        others = [f for f in group if f is not primary]
        also = sorted({f"{f.mcp_id} ({f.rule_id})" for f in others if f.standard != primary.standard})
        # A second finding from the primary's own list is a different rule and is kept as it was.
        same_list = [f for f in others if f.standard == primary.standard]
        merged.append(replace(primary, metadata={**primary.metadata, "also_maps_to": ", ".join(also)}))
        merged.extend(same_list)
    return merged
