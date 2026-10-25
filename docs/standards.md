# Standards and the cached catalog

`mcp-sift` scans against three OWASP lists. Each is a `Standard` in
[`core/standards.py`](../src/mcp_sift/core/standards.py).

| `--standard` | List | Version | Risk ids | Rules |
|--------------|------|---------|----------|-------|
| `mcp` | OWASP MCP Top 10 | 0.1 | `MCP01`-`MCP10` | AST-based for Python, lexical for TypeScript |
| `llm` | OWASP Top 10 for LLM Applications | 2025 | `LLM01`-`LLM10` | lexical |
| `web` | OWASP Top 10 (web application risks) | 2021 | `WEB01`-`WEB10` (A01-A10) | lexical |

Risk ids are unique across lists, so an id alone says which list a finding belongs to. A rule id is
its risk id plus a counter (`LLM05-001`).

## Choosing lists: auto-detect

`--standard auto` (the default) selects lists from evidence in the code: declared dependencies
(`requirements.txt`, `pyproject.toml`, `package.json`) and import statements, plus the presence of
MCP tools or a server. `mcp`, `fastmcp` and the MCP SDK select `mcp`; `openai`, `anthropic`,
`langchain`, `transformers` and similar select `llm`; `flask`, `django`, `fastapi`, `express`
and similar select `web`. The report prints what was detected and why.

Ordinary-word package names (`ai`, `next`) only count as declared dependencies, never as bare
imports. If nothing is recognised every list runs, since silently checking nothing is worse than
checking too much. Use `-s mcp|llm|web` (repeatable) or `-s all` to choose yourself; `auto` cannot
be mixed with explicit lists. Detection lives in `core/detect.py`.

## Coverage and what is deliberately missing

A category is one of three things:

- **covered** -- at least one rule is mapped to it;
- **not static** -- a property of data, design or model behaviour that no scan of source can
  establish (`LLM04`, `LLM08`, `LLM09`, `WEB04`, `WEB06`). It is reported as such so a clean scan
  does not imply the category was checked. `WEB06` is better served by `pip-audit` or `osv-scanner`;
- **no rules yet** -- detectable in principle, not written. None today.

`mcp-sift standards` prints this for every list.

## The cached catalog

`src/mcp_sift/data/top10.json` is a checked-in, offline snapshot of all of the above: every list,
version, risk, status and the rules mapped to it. It ships inside the wheel.

```bash
mcp-sift standards --json            # rebuilt from the code
mcp-sift standards --json --cached   # the shipped snapshot, no rules loaded
mcp-sift standards --export src/mcp_sift/data/top10.json   # refresh the snapshot
```

The snapshot is generated from the code and never edited by hand. A test
(`test_cached_catalog_matches_the_rules_in_code`) fails when they disagree, so refresh it whenever a
rule is added, renamed or re-described.

Shape (schema 1):

```json
{
  "schema": 1,
  "standards": {
    "llm": {
      "name": "OWASP Top 10 for LLM Applications",
      "version": "2025",
      "risks": [
        {
          "id": "LLM05",
          "name": "Improper Output Handling",
          "status": "covered",
          "rules": [{ "id": "LLM05-001", "name": "...", "description": "..." }]
        }
      ]
    }
  }
}
```

## Adding a list

1. Define a `Standard` in `core/standards.py` and add it to `STANDARDS`.
2. Write `rules/<list>.py` with `@rule(...)` functions and import it in `rules/__init__.py`.
3. Add fixtures and tests, document each rule in `docs/rules.md`, and refresh the snapshot.
