# Running mcp-sift in CI/CD

`mcp-sift` is offline, needs no credentials and finishes in seconds on a typical repository, so it
fits any pipeline as a plain command.

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean, or nothing at or above `--fail-on` (or `--no-fail` was given) |
| `1` | A finding at or above `--fail-on` (default `high`) |
| `2` | Bad invocation: unknown rule, bad option, missing path |

| `-o` | For |
|------|-----|
| `pretty` | Humans reading a log (default) |
| `sarif` | GitHub code scanning, GitLab, Azure DevOps and other SARIF consumers |
| `json` | Your own tooling; includes `standards` and `standards_detected` |
| `github` | Annotations on the pull-request diff and run page (GitHub Actions workflow commands) |

Lists are auto-detected from imports and dependencies (`--standard auto`, the default). Pin them in
CI if you want the gate to be stable: `-s mcp -s web`.

## GitHub Actions: the action

```yaml
name: mcp-sift
on: [push, pull_request]

permissions:
  contents: read
  security-events: write # only for upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cvas22/mcp-sift@main # pin to a tag or commit SHA once releases exist
        with:
          path: .
          standard: auto        # or: mcp llm web | all
          fail-on: high
          upload-sarif: "true"  # not available to pull requests from forks
```

Inputs: `path`, `standard`, `fail-on`, `min-severity`, `exclude`, `sarif-file`, `upload-sarif`,
`annotations`, `python-version`, `version`. Outputs: `sarif-file`, `exit-code`.

With no `version`, the action installs the copy bundled with the ref you pinned, so a tag or SHA
fully determines what runs. Set `version: 0.1.0` to install that release from PyPI instead.

Findings appear as annotations on the changed lines. With `upload-sarif: "true"` they also appear in
the repository's code scanning alerts, which deduplicate across runs.

## GitHub Actions: plain commands

```yaml
- run: pip install mcp-sift
- run: mcp-sift scan . -o sarif -f mcp-sift.sarif --no-fail
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-sift.sarif
- run: mcp-sift scan . -o github --fail-on high # annotations, and the step that gates the build
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/cvas22/mcp-sift
    rev: main # pin to a tag
    hooks:
      - id: mcp-sift
```

The hook scans the whole tree rather than only staged files: the MCP rules compare a manifest with
the code, and a per-file scan would miss those cross-file findings.

## GitLab CI

```yaml
mcp-sift:
  image: python:3.12-slim
  script:
    - pip install mcp-sift
    - mcp-sift scan . -o sarif -f mcp-sift.sarif --no-fail
    - mcp-sift scan . --fail-on high
  artifacts:
    when: always
    paths: [mcp-sift.sarif]
```

## Jenkins

```groovy
stage('mcp-sift') {
  steps {
    sh 'python3 -m venv .venv && .venv/bin/pip install mcp-sift'
    sh '.venv/bin/mcp-sift scan . -o sarif -f mcp-sift.sarif --no-fail'
    sh '.venv/bin/mcp-sift scan . --fail-on high'
  }
  post { always { archiveArtifacts artifacts: 'mcp-sift.sarif', allowEmptyArchive: true } }
}
```

## Azure Pipelines

```yaml
- script: |
    pip install mcp-sift
    mcp-sift scan . -o sarif -f $(Build.ArtifactStagingDirectory)/mcp-sift.sarif --no-fail
    mcp-sift scan . --fail-on high
  displayName: mcp-sift
```

## CircleCI

```yaml
jobs:
  mcp-sift:
    docker: [{ image: cimg/python:3.12 }]
    steps:
      - checkout
      - run: pip install mcp-sift && mcp-sift scan . --fail-on high
```

## Paths when you scan a subdirectory

Findings carry paths relative to the directory you scanned. SARIF and `-o github` output add the
directory's position inside the repository, so `path: services/api` reports
`services/api/app.py` and GitHub puts the annotation on the right file. The repository root is
`--repo-root` (or `MCP_SIFT_REPO_ROOT`), else `$GITHUB_WORKSPACE`, else the nearest `.git`. The JSON
report keeps scan-relative paths and records the offset as `path_prefix`.

## One finding per defect

When a scan covers several lists, one defect is often a risk in more than one of them: shell
injection is MCP05, WEB03 and, for model output, LLM05. Findings on the same line with the same CWE
are merged into the strongest one, which lists the others under `also_maps_to` (SARIF:
`alsoMapsTo`, terminal: "Also maps to"). Pass `--keep-duplicates` to report each list separately.

## Keeping a log of the run

Add `-vv --log-format json --log-file mcp-sift.log.jsonl` before `scan` to record which lists were
chosen and why, how long each rule took, and which files were skipped, then upload the file as a
build artifact. The report (`-o json`, `-o sarif`) is separate and unaffected. The same settings are
available as `MCP_SIFT_VERBOSE`, `MCP_SIFT_LOG_FORMAT` and `MCP_SIFT_LOG_FILE` environment variables.

## Choosing a gate

- Start with `--fail-on high` and `--no-fail` on a first run to see the baseline, then tighten.
- Suppress a reviewed finding with `mcp-sift:ignore` on its line, or skip noisy directories with
  `--exclude NAME` (repeatable). Tests, fixtures and `node_modules` are skipped by the pattern rules
  already.
- Scanning the scanner's own rule tables trips its own patterns; exclude `rules` when you scan this
  repository.
