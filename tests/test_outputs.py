"""Output formatters: the contract other tools depend on."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decascan.core.scanner import scan
from decascan.outputs import json_out, sarif

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def result():
    return scan(FIXTURES / "vulnerable_python")


def test_json_output_is_valid_and_complete(result):
    payload = json.loads(json_out.render(result))
    assert payload["tool"] == "decascan"
    assert payload["summary"]["findings"] == len(result.findings)
    assert payload["summary"]["by_severity"]["critical"] > 0
    assert {"rule_id", "mcp_id", "severity", "file_path", "remediation"} <= set(
        payload["findings"][0]
    )


def test_sarif_is_2_1_0_and_maps_rules(result):
    payload = json.loads(sarif.render(result))
    assert payload["version"] == "2.1.0"

    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "decascan"

    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    referenced = {r["ruleId"] for r in run["results"]}
    assert referenced <= declared, "every result must reference a declared rule"

    for entry in run["results"]:
        assert entry["level"] in {"error", "warning", "note"}
        assert entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert entry["partialFingerprints"]["decascanFingerprint/v1"]
        assert entry["properties"]["security-severity"]


def test_sarif_never_leaks_a_secret(result):
    text = sarif.render(result)
    assert "sk-ant-api03-Vq7hK2mZ" not in text
