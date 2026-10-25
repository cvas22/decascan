"""MCP manifests (mcp.json and friends): what the parser extracts and what MCP02/MCP07 do with it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_sift.core.config import ScanConfig
from mcp_sift.core.scanner import scan
from mcp_sift.parsers.manifest import is_manifest_name, load_manifest

MCP = ScanConfig(standards=frozenset({"mcp"}), merge_duplicates=False)


def manifest(tmp_path: Path, data, name: str = "mcp.json"):
    path = tmp_path / name
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return load_manifest(path, tmp_path)


# --- names -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["mcp.json", ".mcp.json", "mcp-config.json", "mcp_config.json", "server.json", "manifest.json",
     "claude_desktop_config.json", "mcp.yaml", "mcp.yml", ".mcp.yaml"],
)
def test_manifest_names(name):
    assert is_manifest_name(name)


@pytest.mark.parametrize("name", ["package.json", "config.json", "mcp.toml", "tsconfig.json", "MCP.JSON"])
def test_other_names_are_not_manifests(name):
    assert not is_manifest_name(name)


# --- loading -----------------------------------------------------------------------------------


def test_tools_as_a_list_with_and_without_schemas(tmp_path):
    m = manifest(tmp_path, {"tools": [
        {"name": "a", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
        {"name": "b"},
        {"name": 7},
        "not-a-dict",
    ]})
    by_name = {t.name: t for t in m.tools}
    assert set(by_name) == {"a", "b"}
    assert by_name["a"].has_schema and [p.name for p in by_name["a"].params] == ["q"]
    assert not by_name["b"].has_schema and by_name["a"].origin == "manifest"


def test_tools_as_a_mapping_and_alternate_schema_keys(tmp_path):
    m = manifest(tmp_path, {"tools": {
        "a": {"input_schema": {"type": "object", "properties": {}}},
        "b": {"parameters": {"type": "object", "properties": {"x": {"type": "string"}}}},
        "c": "ignored",
    }})
    assert {t.name: t.has_schema for t in m.tools} == {"a": True, "b": True}


def test_closed_additional_properties_is_recorded(tmp_path):
    m = manifest(tmp_path, {"tools": [
        {"name": "open", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "closed", "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
    ]})
    assert {t.name: t.additional_properties_open for t in m.tools} == {"open": True, "closed": False}


def test_tool_line_numbers_point_at_the_tool(tmp_path):
    text = '{\n  "tools": [\n    {"name": "alpha"},\n    {"name": "beta"}\n  ]\n}\n'
    m = manifest(tmp_path, text)
    assert {t.name: t.line for t in m.tools} == {"alpha": 3, "beta": 4}


@pytest.mark.parametrize("key", ["scopes", "permissions", "requiredScopes", "required_scopes", "grants"])
def test_scope_keys(tmp_path, key):
    m = manifest(tmp_path, {key: ["read:files", "write:files"]})
    assert m.scopes == ["read:files", "write:files"] and m.declares_scopes


def test_capabilities_is_not_a_scope_key(tmp_path):
    m = manifest(tmp_path, {"capabilities": {"tools": {}}})
    assert m.scopes == [] and not m.declares_scopes


def test_per_tool_scopes(tmp_path):
    m = manifest(tmp_path, {"tools": [{"name": "a", "scopes": ["read:files"]}, {"name": "b"}]})
    assert m.tool_scopes == {"a": ["read:files"]} and m.declares_scopes


def test_servers_from_mcpservers_mapping_and_servers_list(tmp_path):
    m = manifest(tmp_path, {"mcpServers": {
        "local": {"command": "python", "args": ["-m", "server.py"]},
        "remote": {"url": "https://x.test/mcp"},
        "ported": {"port": 8080},
        "typed": {"type": "SSE", "port": "nope"},
    }})
    servers = {s.name: s for s in m.servers}
    assert servers["local"].transport == "stdio" and servers["local"].entrypoint == "server.py"
    assert servers["remote"].transport == "http" and servers["ported"].transport == "http"
    assert servers["typed"].transport == "sse" and servers["typed"].port is None
    assert m.declared_ports == {8080}
    other = manifest(tmp_path, {"servers": [{"name": "s", "port": 9000, "main": "app.js"}]}, "server.json")
    assert other.servers[0].port == 9000 and other.servers[0].entrypoint == "app.js"


@pytest.mark.parametrize(
    ("spec", "exposed"),
    [
        ({"command": "node", "args": ["a.js"]}, False),
        ({"transport": "stdio"}, False),
        ({"port": 8080}, True),
        ({"transport": "sse"}, True),
        ({"transport": "streamable-http"}, True),
        ({"transport": "websocket"}, True),
    ],
)
def test_network_exposure(tmp_path, spec, exposed):
    assert manifest(tmp_path, {"servers": [spec]}).is_network_exposed is exposed


@pytest.mark.parametrize(
    ("auth", "absent"),
    [(None, True), (False, True), ("none", True), ({}, True), ([], True),
     ({"type": "bearer"}, False), ("oauth", False), (True, False)],
)
def test_auth_absence(tmp_path, auth, absent):
    m = manifest(tmp_path, {"auth": auth})
    assert m.auth_is_absent is absent and m.declares_auth_key


def test_auth_key_variants_and_per_server_auth(tmp_path):
    assert manifest(tmp_path, {"security": {"type": "oauth"}}).declares_auth_key
    nested = manifest(tmp_path, {"mcpServers": {"s": {"port": 1, "authentication": {"type": "token"}}}})
    assert nested.declares_auth_key and not nested.auth_is_absent
    assert not manifest(tmp_path, {"mcpServers": {"s": {"port": 1}}}).declares_auth_key


def test_cors_origins_flat_and_nested(tmp_path):
    assert manifest(tmp_path, {"allowedOrigins": ["*"]}).cors_origins == ["*"]
    assert manifest(tmp_path, {"cors": {"origins": ["https://a.test", "*"]}}).cors_origins == ["https://a.test", "*"]
    assert manifest(tmp_path, {"cors": "off"}).cors_origins == []


def test_yaml_manifest(tmp_path):
    m = manifest(tmp_path, "tools:\n  - name: a\nscopes: [read:files]\nport: 80\n", "mcp.yaml")
    assert [t.name for t in m.tools] == ["a"] and m.scopes == ["read:files"]


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '"just a string"', "42", ""])
def test_unparseable_or_non_object_manifests_load_as_none(tmp_path, content):
    assert manifest(tmp_path, content) is None


def test_invalid_yaml_loads_as_none(tmp_path):
    assert manifest(tmp_path, "a: [unclosed\n", "mcp.yaml") is None


def test_manifest_outside_the_root_keeps_its_full_path(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    path = other / "mcp.json"
    path.write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    assert load_manifest(path, root).path == str(path)


# --- MCP02 / MCP07 driven by manifests ---------------------------------------------------------


def ids(tmp_path, data, server: str = "") -> set[str]:
    (tmp_path / "mcp.json").write_text(json.dumps(data), encoding="utf-8")
    if server:
        (tmp_path / "server.py").write_text(server, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path, MCP).findings}


NETWORK_SERVER = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"


def test_mcp07_001_fires_for_a_network_server_without_auth(tmp_path):
    assert "MCP07-001" in ids(tmp_path, {"mcpServers": {"s": {"port": 8080}}}, NETWORK_SERVER)


def test_mcp07_001_quiet_for_stdio_servers(tmp_path):
    assert "MCP07-001" not in ids(tmp_path, {"mcpServers": {"s": {"command": "python", "args": ["s.py"]}}})


def test_mcp07_001_quiet_when_auth_is_declared(tmp_path):
    data = {"auth": {"type": "bearer"}, "mcpServers": {"s": {"port": 8080}}}
    assert "MCP07-001" not in ids(tmp_path, data, NETWORK_SERVER)


def test_mcp07_001_fires_when_auth_is_explicitly_null(tmp_path):
    assert "MCP07-001" in ids(tmp_path, {"auth": None, "mcpServers": {"s": {"port": 8080}}}, NETWORK_SERVER)


def test_mcp07_002_fires_for_wildcard_cors_in_the_manifest(tmp_path):
    assert "MCP07-002" in ids(tmp_path, {"cors": {"origins": ["*"]}})


def test_mcp07_002_quiet_for_explicit_origins(tmp_path):
    assert "MCP07-002" not in ids(tmp_path, {"cors": {"origins": ["https://app.test"]}})


ACTING_SERVER = "import subprocess\n\nsubprocess.run(['ls'])\n"


def test_mcp02_002_fires_for_tools_with_no_scopes_when_the_code_acts(tmp_path):
    data = {"tools": [{"name": "a", "inputSchema": {"type": "object", "properties": {}}}]}
    assert "MCP02-002" in ids(tmp_path, data, ACTING_SERVER)


def test_mcp02_002_quiet_when_the_code_has_no_capabilities(tmp_path):
    data = {"tools": [{"name": "a", "inputSchema": {"type": "object", "properties": {}}}]}
    assert "MCP02-002" not in ids(tmp_path, data, "x = 1\n")


def test_mcp02_002_quiet_when_scopes_are_declared(tmp_path):
    data = {"scopes": ["read:files"], "tools": [{"name": "a", "inputSchema": {"type": "object", "properties": {}}}]}
    assert "MCP02-002" not in ids(tmp_path, data, ACTING_SERVER)
