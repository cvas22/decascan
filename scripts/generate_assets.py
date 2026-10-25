"""Regenerate the README visuals that are drawn from the real tool.

    python scripts/generate_assets.py

Writes into docs/assets/:
  example-run.svg   a real scan of tests/fixtures/vulnerable_ts, rendered by the tool's own terminal output
  coverage.svg      which Top 10 categories have rules, drawn from the catalog

The logo and the banner are hand-drawn SVGs and are not touched.
"""

from __future__ import annotations

import io
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rich.console import Console  # noqa: E402

from mcp_sift.catalog import build_catalog  # noqa: E402
from mcp_sift.core.config import ScanConfig  # noqa: E402
from mcp_sift.core.scanner import scan  # noqa: E402
from mcp_sift.outputs import pretty  # noqa: E402

ASSETS = ROOT / "docs" / "assets"
FONT = "Inter, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"


def example_run() -> None:
    """The tool's real terminal output for the worked example, as an SVG 'screenshot'.

    The first two findings are printed in full, then a line saying how many were left out, then the
    real summary of the whole scan, so the picture is short but every number in it is true.
    """
    target = ROOT / "tests" / "fixtures" / "vulnerable_ts"
    result = scan(target, ScanConfig())
    console = Console(
        record=True, width=100, file=io.StringIO(), force_terminal=True, color_system="truecolor"
    )
    writer = pretty._Writer(console)
    shown = 2
    pretty._print_detection(result, writer)
    console.print()
    for finding in result.findings[:shown]:
        pretty._print_finding(finding, writer)
    writer.line(f"  ... {len(result.findings) - shown} more findings not shown ...", style="dim")
    console.print()
    pretty._print_summary(result, result.findings, writer)
    console.save_svg(str(ASSETS / "example-run.svg"), title="mcp-sift scan tests/fixtures/vulnerable_ts")


# status -> (colour, opacity, what it means)
STATUS = {
    "covered": ("#2dd4bf", 0.95, "has rules"),
    "not-static": ("#64748b", 0.55, "not statically detectable"),
    "no-rules": ("#fbbf24", 0.8, "no rules yet"),
}
SHORT_NAMES = {"mcp": "MCP Top 10", "llm": "LLM Apps Top 10", "web": "Web Top 10"}


def _square(x: int, y: int, risk: dict) -> str:
    colour, opacity, meaning = STATUS[risk["status"]]
    tip = escape(f"{risk['id']} {risk['name']}: {meaning}")
    return (
        f"<g><title>{tip}</title>"
        f'<rect x="{x}" y="{y}" width="42" height="34" rx="8" fill="{colour}" fill-opacity="{opacity}"/>'
        f'<text x="{x + 21}" y="{y + 22}" text-anchor="middle" font-size="12" font-weight="700" '
        f'fill="{"#06202b" if risk["status"] == "covered" else "#e2e8f0"}">{risk["id"][-2:]}</text></g>'
    )


def coverage() -> None:
    standards = build_catalog()["standards"]
    row, left = 54, 214
    width, height = 784, 112 + row * len(standards) + 50
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-labelledby="ct cd">',
        '<title id="ct">Top 10 coverage</title>',
        '<desc id="cd">For each list, which of its ten categories have rules, are not statically '
        "detectable, or have no rules yet.</desc>",
        '<defs><linearGradient id="cbg" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#071426"/><stop offset="1" stop-color="#12335a"/>'
        "</linearGradient></defs>",
        f'<rect width="{width}" height="{height}" rx="20" fill="url(#cbg)"/>',
        f'<g font-family="{FONT}">',
        '<text x="28" y="44" font-size="22" font-weight="700" fill="#e2e8f0">What each list covers</text>',
        '<text x="28" y="68" font-size="14" fill="#94a3b8">One square per category. Teal has rules; '
        "grey cannot be established from source code.</text>",
    ]
    for index, (sid, body) in enumerate(standards.items()):
        top = 96 + index * row
        risks = body["risks"]
        covered = sum(1 for r in risks if r["status"] == "covered")
        rules = sum(len(r["rules"]) for r in risks)
        name = SHORT_NAMES.get(sid, sid)
        parts.append(
            f'<text x="28" y="{top + 22}" font-size="17" font-weight="600" fill="#e2e8f0">{name}</text>'
        )
        parts.append(
            f'<text x="28" y="{top + 40}" font-size="13" fill="#94a3b8">'
            f"{covered} of {len(risks)} categories · {rules} rules</text>"
        )
        parts.extend(_square(left + n * 48, top + 4, risk) for n, risk in enumerate(risks))

    legend_y, x = height - 24, 28
    for key in ("covered", "not-static", "no-rules"):
        colour, _, label = STATUS[key]
        parts.append(f'<rect x="{x}" y="{legend_y - 11}" width="14" height="14" rx="4" fill="{colour}"/>')
        parts.append(f'<text x="{x + 22}" y="{legend_y + 1}" font-size="13" fill="#cbd5e1">{label}</text>')
        x += 36 + len(label) * 7
    parts += ["</g>", "</svg>"]
    (ASSETS / "coverage.svg").write_text("\n".join(parts) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    ASSETS.mkdir(parents=True, exist_ok=True)
    example_run()
    coverage()
    print(f"wrote {ASSETS / 'example-run.svg'}")
    print(f"wrote {ASSETS / 'coverage.svg'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
