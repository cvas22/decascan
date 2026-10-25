"""Hostile or odd input must not crash the scanner, escape the scan root, or hide a file."""

from __future__ import annotations

import json
import os

import pytest
from click.testing import CliRunner

import decascan.cli as cli
from decascan.cli import main
from decascan.core.config import ScanConfig
from decascan.core.scanner import scan

WEB = ScanConfig(standards=frozenset({"web"}), merge_duplicates=False)


def ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


# --- a parser crash costs one file, not the scan -----------------------------------------------


def test_deeply_nested_manifest_does_not_crash_the_scan(tmp_path):
    (tmp_path / "mcp.json").write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    (tmp_path / "app.py").write_text("DEBUG = True\n", encoding="utf-8")
    assert "WEB05-001" in ids(scan(tmp_path, WEB))


def test_pathological_python_is_reported_and_the_rest_still_scans(tmp_path):
    (tmp_path / "bomb.py").write_text("x = " + "+".join(["1"] * 200_000) + "\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("DEBUG = True\n", encoding="utf-8")
    result = scan(tmp_path, WEB)
    assert "WEB05-001" in ids(result)
    assert any(e.startswith("bomb.py:") for e in result.errors)


def test_a_failing_parser_is_recorded_and_logged(tmp_path, monkeypatch):
    import decascan.core.context as context

    def boom(*_args):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(context, "parse_python", boom)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.js").write_text("DEBUG = true\n", encoding="utf-8")
    result = scan(tmp_path, ScanConfig())
    assert any("a.py: python parser failed (RuntimeError" in e for e in result.errors)
    assert result.files_scanned == 2


def test_an_internal_crash_exits_two_not_one(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    def boom(*_args, **_kwargs):
        raise RuntimeError("internal failure")

    monkeypatch.setattr(cli, "scan", boom)
    result = CliRunner().invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "scan aborted" in result.stderr and "internal failure" in result.stderr


def test_unwritable_output_file_exits_two(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    missing_dir = tmp_path / "nope" / "report.json"
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "-o", "json", "-f", str(missing_dir)])
    assert result.exit_code == 2


# --- byte-order marks --------------------------------------------------------------------------


def test_python_file_with_a_bom_is_still_scanned(tmp_path):
    (tmp_path / "a.py").write_bytes(b"\xef\xbb\xbfDEBUG = True\r\n")
    result = scan(tmp_path, WEB)
    assert "WEB05-001" in ids(result) and result.errors == []


def test_manifest_with_a_bom_is_still_parsed(tmp_path):
    manifest = {"name": "x", "transport": "http", "port": 8080}
    (tmp_path / "mcp.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(manifest).encode())
    (tmp_path / "server.py").write_text("from mcp.server.fastmcp import FastMCP\n", encoding="utf-8")
    assert "MCP07-001" in ids(scan(tmp_path, ScanConfig(standards=frozenset({"mcp"}))))


def test_package_json_with_a_bom_is_read(tmp_path):
    (tmp_path / "package.json").write_bytes(
        b"\xef\xbb\xbf" + json.dumps({"dependencies": {"express": "4.19.2"}}).encode()
    )
    (tmp_path / "index.js").write_text("console.log(1)\n", encoding="utf-8")
    assert "web" in scan(tmp_path, ScanConfig()).detected


# --- symlinks and the walk ---------------------------------------------------------------------


def symlink_or_skip(link, target, directory=False):
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this system")


def test_symlinked_file_outside_the_root_is_not_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("DEBUG = True\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    symlink_or_skip(root / "link.py", outside / "secret.py")
    result = scan(root, WEB)
    assert result.findings == [] and result.files_scanned == 1


def test_symlink_loop_terminates(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("DEBUG = True\n", encoding="utf-8")
    symlink_or_skip(root / "loop", root, directory=True)
    result = scan(root, WEB)
    assert ids(result) == {"WEB05-001"} and result.files_scanned == 1


def test_symlinks_are_counted_in_the_log(tmp_path, caplog):
    import logging

    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    symlink_or_skip(root / "link", root, directory=True)
    logging.getLogger("decascan").propagate = True
    with caplog.at_level(logging.INFO, logger="decascan"):
        scan(root, WEB)
    built = next(r for r in caplog.records if r.getMessage() == "context built")
    assert built.skipped_symlink == 1


def test_excluded_directories_are_pruned_not_walked(tmp_path, monkeypatch):
    (tmp_path / "node_modules" / "deep" / "deeper").mkdir(parents=True)
    (tmp_path / "node_modules" / "deep" / "deeper" / "x.py").write_text("DEBUG = True\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("DEBUG = True\n", encoding="utf-8")

    visited: list[str] = []
    real_walk = os.walk

    def spy(top, *args, **kwargs):
        for current, dirs, files in real_walk(top, *args, **kwargs):
            visited.append(current)
            yield current, dirs, files

    monkeypatch.setattr(os, "walk", spy)
    result = scan(tmp_path, WEB)
    assert result.files_scanned == 1
    assert not any("node_modules" in v for v in visited)


def test_extra_excludes_apply_to_nested_directories(tmp_path):
    (tmp_path / "a" / "vendor").mkdir(parents=True)
    (tmp_path / "a" / "vendor" / "x.py").write_text("DEBUG = True\n", encoding="utf-8")
    (tmp_path / "a" / "y.py").write_text("DEBUG = True\n", encoding="utf-8")
    config = ScanConfig(standards=frozenset({"web"}), excludes=(*ScanConfig().excludes, "vendor"))
    assert [f.file_path for f in scan(tmp_path, config).findings] == ["a/y.py"]


# --- output file handling ----------------------------------------------------------------------


def test_pretty_output_file_is_closed_and_complete(tmp_path):
    (tmp_path / "a.py").write_text("DEBUG = True\n", encoding="utf-8")
    report = tmp_path / "report.txt"
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "-s", "web", "-f", str(report), "--no-fail"])
    assert result.exit_code == 0
    text = report.read_text(encoding="utf-8")
    assert "WEB05-001" in text
    report.unlink()  # raises PermissionError on Windows if the handle was left open


def test_minified_check_is_computed_once_per_file(tmp_path):
    from decascan.core.context import build_context

    (tmp_path / "a.py").write_text("x = 1\n" + "y" * 100 + "\n", encoding="utf-8")
    ctx = build_context(tmp_path, ScanConfig())
    assert ctx.is_minified("a.py", 50) is True
    assert ctx.is_minified("a.py", 50) is True
    assert list(ctx._minified_cache) == ["a.py"]
