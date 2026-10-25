"""What counts as an MCP server in Python source.

Found on a real repository: a threat-modelling library whose own `Server` class was instantiated
over a hundred times was reported as 138 "multiple MCP servers" (MCP09-001). A name is not evidence;
where it was imported from is.
"""

from __future__ import annotations

import pytest

from decascan.core.config import ScanConfig
from decascan.core.scanner import scan
from decascan.parsers.python_source import _is_mcp_constructor, parse_python

MCP = ScanConfig(standards=frozenset({"mcp"}), merge_duplicates=False)


def servers(source: str):
    return parse_python("s.py", source).servers


@pytest.mark.parametrize(
    "source",
    [
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n",
        "from mcp.server import Server\nserver = Server('x')\n",
        "from mcp.server.lowlevel import Server\nserver = Server('x')\n",
        "from fastmcp import FastMCP\nmcp = FastMCP('x')\n",
        "import mcp.server.fastmcp as m\nmcp = m.FastMCP('x')\n",
        "from mcp.server.fastmcp import FastMCP as F\nmcp = F('x')\n",
        "mcp = FastMCP('x')\n",  # bare name nobody else uses
        "server = McpServer('x')\n",
    ],
)
def test_mcp_servers_are_recognised(source):
    assert len(servers(source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "from pytm import Server\nweb = Server('web')\n",
        "from mylib.models import Server\nserver = Server('x')\n",
        "class Server:\n    pass\n\nserver = Server('x')\n",
        "import socketserver\ns = socketserver.Server('x')\n",
        "from somewhere import FastMCP\nmcp = FastMCP('x')\n",  # imported from a non-MCP package
        "server = LowLevelServer('x')\n",
    ],
)
def test_other_classes_with_the_same_name_are_not_mcp_servers(source):
    assert servers(source) == []


def test_server_details_are_still_extracted():
    (server,) = servers("from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('notes', port=8080)\n")
    assert server.name == "notes" and server.port == 8080 and server.kind == "FastMCP"


@pytest.mark.parametrize(
    ("canonical", "raw", "expected"),
    [
        ("mcp.server.Server", "Server", True),
        ("fastmcp.FastMCP", "FastMCP", True),
        ("modelcontextprotocol.Server", "Server", True),
        ("pytm.Server", "Server", False),
        ("", "Server", False),
        ("", "FastMCP", True),
        ("", "Other", False),
        ("mcp.server.Other", "Other", False),
    ],
)
def test_constructor_decision_table(canonical, raw, expected):
    assert _is_mcp_constructor(canonical, raw) is expected


def test_a_library_that_builds_many_of_its_own_servers_is_not_flagged(tmp_path):
    body = "from pytm import Server\n" + "".join(f"s{i} = Server('s{i}')\n" for i in range(20))
    (tmp_path / "model.py").write_text(body, encoding="utf-8")
    result = scan(tmp_path, MCP)
    assert [f.rule_id for f in result.findings] == []


def test_two_real_mcp_servers_are_still_flagged_as_shadow_servers(tmp_path):
    body = (
        "from mcp.server.fastmcp import FastMCP\n"
        "primary = FastMCP('primary')\nsecond = FastMCP('second')\n"
    )
    (tmp_path / "server.py").write_text(body, encoding="utf-8")
    assert "MCP09-001" in {f.rule_id for f in scan(tmp_path, MCP).findings}


def test_auto_detection_does_not_choose_the_mcp_list_for_a_server_named_class(tmp_path):
    (tmp_path / "model.py").write_text("from pytm import Server\nweb = Server('web')\n", encoding="utf-8")
    assert "mcp" not in scan(tmp_path, ScanConfig()).detected
