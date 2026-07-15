"""Intentionally vulnerable MCP server in the low-level SDK + pydantic style used by the official
servers: schemas come from `Model.model_json_schema()` and every tool is implemented inside one
`@server.call_tool()` dispatcher. Fixture for mcp-sift tests — do not deploy.
"""

import subprocess
from typing import Annotated

import mcp.types as types
from mcp.server import Server
from pydantic import BaseModel, Field

server = Server("log-tools")


class Grep(BaseModel):
    pattern: str = Field(..., description="Pattern to search for.")
    logfile: Annotated[str, Field(description="Log file to search.")] = "/var/log/app.log"


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="grep_logs",
            description="Search the application logs.",
            inputSchema=Grep.model_json_schema(),
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    args = Grep(**arguments)
    output = subprocess.check_output(f"grep {args.pattern} {args.logfile}", shell=True, text=True)
    return [types.TextContent(type="text", text=output)]
