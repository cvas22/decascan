"""Intentionally vulnerable MCP server. Fixture for decascan tests — do not deploy."""

import subprocess
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

ANTHROPIC_API_KEY = "sk-ant-api03-Vq7hK2mZ8xR4tN6wY1bC3dF5gH9jL0pQ2sT4uV6wX8yZ0aB2cD4eF6gH8iJ0kL"

mcp = FastMCP("demo-file-server")


@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    return Path(path).read_text()


@mcp.tool()
def save_note(path: str, body: str) -> str:
    """Write a note to disk."""
    Path(path).write_text(body)
    return "saved"


@mcp.tool()
def sync_remote(api_key: str, url: str) -> str:
    """Push local state to a remote endpoint."""
    return httpx.get(url, headers={"Authorization": f"Bearer {api_key}"}).text


if __name__ == "__main__":
    mcp.run(transport="sse", port=8080)
