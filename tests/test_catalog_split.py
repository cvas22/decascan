"""The cached catalog is one self-contained JSON file per list, with no index."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_sift.catalog import (
    build_catalog,
    build_files,
    cached_standard_ids,
    export_catalog,
    load_cached_catalog,
    load_cached_standard,
)
from mcp_sift.cli import main
from mcp_sift.core.standards import STANDARDS

DATA = Path(__file__).parent.parent / "src" / "mcp_sift" / "data" / "top10"


def test_one_file_per_list_and_nothing_else():
    assert sorted(p.name for p in DATA.iterdir()) == sorted(f"{i}.json" for i in STANDARDS)
    assert not (DATA / "index.json").exists()
    assert not (DATA.parent / "top10.json").exists()


def test_checked_in_files_match_what_the_code_generates():
    # Refresh with: mcp-sift standards --export src/mcp_sift/data/top10
    for name, text in build_files().items():
        assert (DATA / name).read_text(encoding="utf-8") == text, name


def test_each_file_is_self_contained():
    for standard_id, standard in STANDARDS.items():
        body = json.loads((DATA / f"{standard_id}.json").read_text(encoding="utf-8"))
        assert body["schema"] == 1 and body["id"] == standard_id
        assert body["name"] == standard.name and body["version"] == standard.version
        assert [r["id"] for r in body["risks"]] == list(standard.risks)
        assert {r["status"] for r in body["risks"]} <= {"covered", "not-static", "no-rules"}


def test_list_ids_come_back_in_code_order():
    assert cached_standard_ids() == list(STANDARDS)


def test_load_one_list_without_the_others():
    llm = load_cached_standard("llm")
    assert llm["id"] == "llm" and len(llm["risks"]) == 10
    with pytest.raises(ValueError, match="unknown standard"):
        load_cached_standard("nope")


def test_assembled_catalog_equals_the_combined_build():
    assert load_cached_catalog() == build_catalog()


def test_export_to_a_directory_writes_one_file_per_list(tmp_path):
    written = export_catalog(tmp_path / "out")
    assert sorted(p.name for p in written) == sorted(f"{i}.json" for i in STANDARDS)
    for path in written:
        assert path.read_text(encoding="utf-8") == build_files()[path.name]


def test_export_to_a_json_path_writes_one_combined_file(tmp_path):
    (path,) = export_catalog(tmp_path / "catalog.json")
    assert json.loads(path.read_text(encoding="utf-8")) == build_catalog()


def test_cli_prints_a_single_list_from_the_cache():
    out = CliRunner().invoke(main, ["standards", "--json", "--cached", "-s", "web"]).output
    body = json.loads(out)
    assert body["id"] == "web" and len(body["risks"]) == 10


def test_cli_single_list_rebuilt_from_code_has_no_file_wrapper():
    out = CliRunner().invoke(main, ["standards", "--json", "-s", "mcp"]).output
    assert set(json.loads(out)) == {"name", "version", "risks"}


def test_cli_table_can_show_one_list():
    out = CliRunner().invoke(main, ["standards", "-s", "llm"]).output
    assert "Top 10 for LLM" in out and "OWASP MCP Top 10" not in out


def test_cli_export_reports_each_file(tmp_path):
    out = CliRunner().invoke(main, ["standards", "--export", str(tmp_path / "d")]).output
    assert out.count("wrote ") == len(STANDARDS)


def test_a_new_list_is_just_a_new_file(tmp_path, monkeypatch):
    import mcp_sift.catalog as catalog

    (tmp_path / "api.json").write_text(json.dumps({"schema": 1, "id": "api", "risks": []}), encoding="utf-8")
    for name in ("mcp", "llm", "web"):
        text = (DATA / f"{name}.json").read_text(encoding="utf-8")
        (tmp_path / f"{name}.json").write_text(text, encoding="utf-8")
    monkeypatch.setattr(catalog, "_data", lambda: tmp_path)
    assert cached_standard_ids() == ["mcp", "llm", "web", "api"]
