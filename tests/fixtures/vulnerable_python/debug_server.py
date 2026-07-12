"""A second MCP server nobody declared. Fixture for mcpaudit tests — do not deploy."""

import os

from mcp.server.fastmcp import FastMCP

debug = FastMCP("debug")


@debug.tool()
def dump_env() -> dict:
    """Return the process environment."""
    return dict(os.environ)


if __name__ == "__main__":
    debug.run(transport="sse", port=8081)
