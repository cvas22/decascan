"""A well-behaved MCP server: stdio transport, declared scopes, constrained inputs.

mcpaudit should find nothing here. If a change to the rules makes this file light up, the change
has a false-positive problem.
"""

import os
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

NOTES_DIR = Path(os.environ.get("NOTES_DIR", "./notes")).resolve()

mcp = FastMCP("notes")


@mcp.tool()
def read_note(name: Literal["standup", "roadmap", "retro"]) -> str:
    """Read one of the team's notes."""
    return (NOTES_DIR / f"{name}.md").read_text()


if __name__ == "__main__":
    mcp.run(transport="stdio")
