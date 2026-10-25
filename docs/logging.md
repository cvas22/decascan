# Logging

Logging is off by default: a plain run prints only the report. Logs describe the run itself and go to
stderr (or a file), never stdout, so `-o json | jq` works with logging on.

```bash
mcp-sift -v scan .                                              # progress
mcp-sift -vv scan .                                             # plus per-file and per-rule detail
mcp-sift -vv --log-format json --log-file scan.jsonl scan . -o json -f report.json
```

| Option | Env var | |
|--------|---------|--|
| `-v` / `-vv` | `MCP_SIFT_VERBOSE` | `-v` = INFO, `-vv` = DEBUG. Warnings appear at either level. |
| `--log-file PATH` | `MCP_SIFT_LOG_FILE` | Write to a file instead of stderr (implies `-v`). |
| `--log-format text\|json` | `MCP_SIFT_LOG_FORMAT` | `text`: `time LEVEL message key=value ...`. `json`: one object per line with `ts`, `level`, `logger`, `msg` and the fields below. |

As a library, the `mcp_sift` logger is silent until you configure it (`mcp_sift.core.log.configure`).

## Events

### INFO (`-v`)

| Message | Logger | Fields |
|---------|--------|--------|
| `scan requested` | `cli` | `path`, `output`, `output_file`, `fail_on`, `no_fail`, `standards` |
| `scan started` | `scanner` | `path` |
| `context built` | `context` | `files`, `manifests`, `tools`, `dependencies`, `lockfiles`, `bytes`, `kinds`, `seconds`, `skipped_excluded`, `skipped_too_large`, `skipped_unreadable`, `skipped_not_scannable`, `skipped_symlink` |
| `lists selected` | `scanner` | `standards`, `mode` (`auto`/`explicit`), `detected` (the evidence), `rules`, `rules_skipped_other_lists`, `rules_disabled` |
| `rules finished` | `scanner` | `rules`, `failed`, `raw_findings`, `seconds`, `slowest` (the three slowest rules) |
| `findings filtered` | `scanner` | `below_min_severity`, `suppressed_inline`, `exact_duplicates`, `kept` (only when something was filtered) |
| `cross-list duplicates merged` | `scanner` | `merged` (only when something merged) |
| `scan finished` | `scanner` | `files`, `rules`, `findings`, `errors`, `seconds`, `context_seconds`, `rules_seconds`, `severity_<level>` (non-zero levels) |
| `report written` | `cli` | `format`, `destination`, `findings`, `bytes` (the size on disk for a file) |
| `exiting` | `cli` | `code`, `reason` (why the exit code is what it is) |

### WARNING (always shown once logging is on)

| Message | Fields |
|---------|--------|
| `rule failed` | `rule`, `error` (the scan continues without it) |
| `parser failed` | `file`, `parser`, `error` (that file's facts are dropped) |
| `file could not be parsed` | `file`, `error` (for example a Python syntax error) |
| `slow file` | `file`, `parser`, `seconds` (over 1 s) |
| `slow rule` | `rule`, `seconds` (over 2 s) |

An aborted scan logs `scan aborted` with the traceback at ERROR and exits with code 2.

### DEBUG (`-vv`)

| Message | Fields |
|---------|--------|
| `environment` | `version`, `python`, `platform` |
| `scan configuration` | the effective options: `standards`, `min_severity`, `only_rules`, `disabled_rules`, `extra_excludes`, `merge_duplicates`, `max_file_bytes`, `repo_root` |
| `file read` | `file`, `kind`, `bytes` |
| `file skipped: over size limit` / `file skipped: cannot stat` | `file` (and `limit`) |
| `symlinked file skipped` / `symlinked directory skipped` | `file` |
| `source facts` | `file`, `tools`, `servers`, `calls`, `taint_flows` (files that contribute any) |
| `manifest read` / `manifest ignored: not a JSON/YAML object` | `file`, `tools`, `scopes`, `servers`, `network_exposed`, `auth_declared` |
| `dependencies read` | `file`, `dependencies`, `install_hooks` |
| `lockfile found` | `file` |
| `list detected` | `standard`, `evidence` |
| `import ignored: name too generic` | `file`, `imported` |
| `no list recognised from imports or dependencies` | (every list then runs) |
| `rules disabled by option` | `rules` |
| `rule finished` | `rule`, `findings`, `ms` |
| `finding suppressed inline` | `rule`, `file`, `line` |
| `merged duplicate` | `file`, `line`, `cwe`, `kept`, `also` |
| `file skipped by pattern rules: minified or generated` | `file`, `longest_line`, `limit` (once per file) |
| `comments and docstrings masked` | `file`, `chars_blanked`, `chars` |
| `repository root resolved` | `repo_root`, `path_prefix` |
| `rule failure traceback` | the traceback of a failed rule |

## Writing a log call

Pass structured data in `extra={...}`, not in the message. Do not use a key that `logging` reserves
(`name`, `module`, `args`, `filename`, `process`, ...): `extra={"module": ...}` raises `KeyError` as soon
as DEBUG is on. A test scans the source for this.
