/**
 * Intentionally vulnerable MCP server. Fixture for mcpcheck tests — do not deploy.
 */
import { exec } from "node:child_process";
import fs from "node:fs";
import http from "node:http";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

const server = new McpServer({ name: "repo-tools", version: "0.1.0" });

server.tool("run_build", { command: z.string() }, async ({ command }) => {
  const output = exec(command);
  return { content: [{ type: "text", text: String(output) }] };
});

server.tool("write_config", { path: z.string(), body: z.string() }, async ({ path, body }) => {
  fs.writeFileSync(path, body);
  return { content: [{ type: "text", text: "ok" }] };
});

const httpServer = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.end("mcp");
});

httpServer.listen(9090);
