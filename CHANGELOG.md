# Changelog

All notable changes. The project is pre-release (v0.1); nothing has been published to PyPI yet.

## Unreleased

### Added
- **Three Top 10 lists.** Besides the OWASP MCP Top 10, the scanner covers the Top 10 for LLM
  Applications (2025) and the web Top 10 (2021) with 28 pattern-based rules. Categories no static scan
  can establish are reported as "not static" by `mcp-sift standards`.
- **`--standard auto|all|mcp|llm|web`.** `auto` (the default) picks the lists from the code's imports
  and dependencies and says why; an unrecognised codebase gets every list.
- **Cached catalog** of the lists and their rules, `src/mcp_sift/data/top10.json`
  (`standards --json --cached`, `--export`), kept in step with the code by a test.
- **CI/CD:** a composite GitHub Action (`action.yml`), `-o github` annotations, a pre-commit hook,
  a code-scanning workflow, and `docs/ci.md` with recipes for GitLab, Jenkins, Azure Pipelines and
  CircleCI. The pipeline runs the unit tests with a coverage floor, and releases are gated on them.
- **Logging:** `-v`/`-vv`, `--log-file`, `--log-format text|json`, and `MCP_SIFT_*` environment
  variables. Logs go to stderr or a file, never stdout.
- `--repo-root` / `MCP_SIFT_REPO_ROOT`, and `--keep-duplicates`.

### Changed
- **SARIF and annotation paths are repository-relative** (they were relative to the scanned
  directory, which pointed GitHub at files that do not exist when `path` was a subdirectory). The JSON
  report keeps scan-relative paths and adds `path_prefix`.
- **One finding per defect.** The same defect reported by several lists (same file, line and CWE) is
  merged into the strongest finding with an "Also maps to" note. `--keep-duplicates` restores
  per-list findings.
- **Exit code `2` for any scan failure.** A crash no longer exits `1`, which a pipeline reads as
  "findings".
- **Comments and docstrings are ignored** by the pattern rules, so examples in documentation are not
  reported.
- Excluded directories (`node_modules`, virtualenvs) are pruned instead of walked.

### Fixed
- A very long line (minified or generated code) could stall a scan for minutes; line lookups were
  quadratic in the number of matches.
- A deeply nested manifest or a huge expression crashed the scan with an uncaught `RecursionError`.
- Files and manifests with a UTF-8 byte-order mark were silently skipped.
- Symlinks inside the scanned tree were followed.
- A match after blank lines was reported on the wrong line (a `^\s*` regex spanned newlines).
- `--output-file` for the pretty format left its file handle open.
