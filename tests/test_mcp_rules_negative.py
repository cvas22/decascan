"""A firing case and a quiet case for MCP rules that were only tested against a vulnerable fixture.

Each server here is a few lines of FastMCP, written to sit just either side of a rule's line: the
variant that must fire and the closest safe variant that must not.
"""

from __future__ import annotations

import pytest

from mcp_sift.core.config import ScanConfig
from mcp_sift.core.scanner import scan

MCP_ONLY = ScanConfig(standards=frozenset({"mcp"}), merge_duplicates=False)

HEADER = (
    "import os\nimport subprocess\nfrom pathlib import Path\n"
    "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('t')\n\n"
)


def ids(tmp_path, body: str, name: str = "server.py", header: str = HEADER) -> set[str]:
    (tmp_path / name).write_text(header + body, encoding="utf-8")
    result = scan(tmp_path, MCP_ONLY)
    assert result.errors == []
    return {f.rule_id for f in result.findings}


def tool(code: str) -> str:
    return "@mcp.tool()\n" + code


# --- MCP01-002: a credential taken as a tool parameter -----------------------------------------


@pytest.mark.parametrize("param", ["api_key", "token", "password", "client_secret", "access_token"])
def test_mcp01_002_fires_for_credential_parameters(tmp_path, param):
    assert "MCP01-002" in ids(tmp_path, tool(f"def sync({param}: str) -> str:\n    return 'ok'\n"))


@pytest.mark.parametrize("param", ["query", "name", "max_tokens", "token_count", "path", "tokenizer"])
def test_mcp01_002_quiet_for_ordinary_parameters(tmp_path, param):
    assert "MCP01-002" not in ids(tmp_path, tool(f"def sync({param}: str) -> str:\n    return 'ok'\n"))


# --- MCP03-003 / MCP03-004: unvalidated parameters, tool without a schema ----------------------


def test_mcp03_003_fires_for_a_bare_risky_parameter(tmp_path):
    assert "MCP03-003" in ids(tmp_path, tool("def run(command: str) -> str:\n    return command\n"))


def test_mcp03_003_quiet_when_the_parameter_is_constrained(tmp_path):
    body = tool(
        "def run(command: Literal['status', 'version']) -> str:\n    return command\n"
    )
    assert "MCP03-003" not in ids(tmp_path, body, header=HEADER + "from typing import Literal\n")


def test_mcp03_003_quiet_for_a_harmless_parameter_name(tmp_path):
    assert "MCP03-003" not in ids(tmp_path, tool("def greet(name: str) -> str:\n    return name\n"))


def test_mcp03_004_fires_for_a_manifest_tool_with_no_schema(tmp_path):
    (tmp_path / "mcp.json").write_text('{"tools": [{"name": "do_thing"}]}', encoding="utf-8")
    assert "MCP03-004" in ids(tmp_path, tool("def a() -> str:\n    return 'x'\n"))


def test_mcp03_004_quiet_when_the_manifest_tool_declares_a_schema(tmp_path):
    manifest = '{"tools": [{"name": "do_thing", "inputSchema": {"type": "object", "properties": {}}}]}'
    (tmp_path / "mcp.json").write_text(manifest, encoding="utf-8")
    assert "MCP03-004" not in ids(tmp_path, tool("def a() -> str:\n    return 'x'\n"))


# --- MCP04-003: npm install hooks --------------------------------------------------------------


@pytest.mark.parametrize("hook", ["preinstall", "install", "postinstall", "prepare"])
def test_mcp04_003_fires_for_install_hooks(tmp_path, hook):
    (tmp_path / "package.json").write_text(
        f'{{"name": "x", "scripts": {{"{hook}": "node setup.js"}}}}', encoding="utf-8"
    )
    assert "MCP04-003" in ids(tmp_path, tool("def a() -> str:\n    return 'x'\n"))


def test_mcp04_003_quiet_for_ordinary_scripts(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "scripts": {"build": "tsc", "test": "jest", "start": "node ."}}', encoding="utf-8"
    )
    assert "MCP04-003" not in ids(tmp_path, tool("def a() -> str:\n    return 'x'\n"))


def test_mcp04_003_quiet_for_an_empty_hook(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"postinstall": ""}}', encoding="utf-8")
    assert "MCP04-003" not in ids(tmp_path, tool("def a() -> str:\n    return 'x'\n"))


# --- MCP05-002: tool input reaches an evaluator ------------------------------------------------


@pytest.mark.parametrize("call", ["eval(expr)", "exec(expr)"])
def test_mcp05_002_fires_when_input_reaches_eval_or_exec(tmp_path, call):
    assert "MCP05-002" in ids(tmp_path, tool(f"def calc(expr: str) -> str:\n    return str({call})\n"))


def test_mcp05_002_quiet_for_a_constant_expression(tmp_path):
    assert "MCP05-002" not in ids(tmp_path, tool("def calc(expr: str) -> str:\n    return str(eval('1 + 1'))\n"))


def test_mcp05_002_quiet_for_literal_eval(tmp_path):
    body = tool("def calc(expr: str) -> str:\n    return str(ast.literal_eval(expr))\n")
    assert "MCP05-002" not in ids(tmp_path, body, header=HEADER + "import ast\n")


def test_mcp05_002_quiet_when_the_parameter_is_constrained(tmp_path):
    body = tool("def calc(expr: Literal['1+1', '2+2']) -> str:\n    return str(eval(expr))\n")
    assert "MCP05-002" not in ids(tmp_path, body, header=HEADER + "from typing import Literal\n")


# --- MCP06-003: remote content returned to the model -------------------------------------------


def test_mcp06_003_fires_when_fetched_content_is_returned(tmp_path):
    body = tool("def fetch(url: str) -> str:\n    return requests.get(url).text\n")
    assert "MCP06-003" in ids(tmp_path, body, header=HEADER + "import requests\n")


def test_mcp06_003_quiet_when_a_local_string_is_returned(tmp_path):
    body = tool("def hello() -> str:\n    return 'hello'\n")
    assert "MCP06-003" not in ids(tmp_path, body, header=HEADER + "import requests\n")


def test_mcp06_003_quiet_when_the_response_is_only_used_for_its_status(tmp_path):
    body = tool("def ping(url: str) -> int:\n    return requests.get(url).status_code\n")
    assert "MCP06-003" not in ids(tmp_path, body, header=HEADER + "import requests\n")


# --- MCP08-002: swallowed exceptions in code that acts -----------------------------------------


ACTING = "def a(cmd: Literal['ls']) -> str:\n    try:\n        subprocess.run([cmd])\n    except Exception:\n        pass\n    return ''\n"
LITERAL = HEADER + "from typing import Literal\n"


def test_mcp08_002_fires_when_a_failing_command_is_ignored(tmp_path):
    assert "MCP08-002" in ids(tmp_path, tool(ACTING), header=LITERAL)


def test_mcp08_002_quiet_when_the_error_is_logged(tmp_path):
    body = tool(ACTING.replace("        pass\n", "        log.exception('failed')\n"))
    assert "MCP08-002" not in ids(tmp_path, body, header=LITERAL + "import logging\nlog = logging.getLogger()\n")


def test_mcp08_002_quiet_in_read_only_code(tmp_path):
    body = tool("def a() -> str:\n    try:\n        return Path('x').read_text()\n    except OSError:\n        pass\n    return ''\n")
    assert "MCP08-002" not in ids(tmp_path, body)


def test_mcp08_002_quiet_outside_an_mcp_server(tmp_path):
    source = "import subprocess\n\ndef run():\n    try:\n        subprocess.run(['ls'])\n    except Exception:\n        pass\n"
    assert "MCP08-002" not in ids(tmp_path, source, header="")


# --- MCP10-001: the environment returned to the model ------------------------------------------


@pytest.mark.parametrize("returned", ["dict(os.environ)", "os.environ.copy()", "str(os.environ)"])
def test_mcp10_001_fires_when_the_environment_is_returned(tmp_path, returned):
    assert "MCP10-001" in ids(tmp_path, tool(f"def env() -> str:\n    return {returned}\n"))


def test_mcp10_001_quiet_for_a_hardcoded_allowlist(tmp_path):
    body = tool("def env() -> dict:\n    return {'mode': 'prod', 'region': 'eu'}\n")
    assert "MCP10-001" not in ids(tmp_path, body)


def test_mcp10_001_quiet_when_the_environment_is_only_read_internally(tmp_path):
    body = "ROOT = os.environ.get('ROOT', '.')\n\n" + tool("def where() -> str:\n    return 'fixed'\n")
    assert "MCP10-001" not in ids(tmp_path, body)


# --- MCP10-002: credential files ---------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["~/.ssh/id_rsa", "~/.aws/credentials", "/etc/passwd", "~/.bash_history"],
)
def test_mcp10_002_fires_for_credential_paths(tmp_path, path):
    body = tool(f"def read() -> str:\n    return Path('{path}').expanduser().read_text()\n")
    assert "MCP10-002" in ids(tmp_path, body)


def test_mcp10_002_quiet_for_an_ordinary_file(tmp_path):
    body = tool("def read() -> str:\n    return Path('notes/today.md').read_text()\n")
    assert "MCP10-002" not in ids(tmp_path, body)


def test_mcp10_002_quiet_when_the_path_is_only_a_string(tmp_path):
    body = "HELP = 'keys live in ~/.ssh/id_rsa'\n\n" + tool("def read() -> str:\n    return HELP\n")
    assert "MCP10-002" not in ids(tmp_path, body)


# --- MCP10-003: file access rooted at the filesystem root --------------------------------------


@pytest.mark.parametrize("root", ["'/'", "Path.home()", "Path('~').expanduser()"])
def test_mcp10_003_fires_for_broad_roots(tmp_path, root):
    body = tool(f"def index() -> list:\n    return [str(p) for p in Path({root}).rglob('*')]\n") if root.startswith("'") else \
        tool(f"def index() -> list:\n    return [str(p) for p in {root}.rglob('*')]\n")
    assert "MCP10-003" in ids(tmp_path, body)


def test_mcp10_003_quiet_for_a_narrow_root(tmp_path):
    body = tool("def index() -> list:\n    return [str(p) for p in Path('./notes').rglob('*')]\n")
    assert "MCP10-003" not in ids(tmp_path, body)


def test_mcp10_003_quiet_for_a_root_taken_from_configuration(tmp_path):
    body = "ROOT = Path(os.environ.get('NOTES_DIR', './notes')).resolve()\n\n" + tool(
        "def index() -> list:\n    return [str(p) for p in ROOT.rglob('*')]\n"
    )
    assert "MCP10-003" not in ids(tmp_path, body)
