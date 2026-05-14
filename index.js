#!/usr/bin/env node
// secrets-audit-mcp — Node wrapper that spawns the Python stdio MCP server.
// Distribution helper; the actual server is server.py (zero-dep, Python 3.6+).

const { spawn } = require("child_process");
const path = require("path");

const server = path.join(__dirname, "server.py");
const python = process.env.PYTHON || "python3";

const proc = spawn(python, [server], {
  stdio: "inherit",
  env: process.env,
});

proc.on("error", (err) => {
  process.stderr.write(
    "secrets-audit-mcp: failed to spawn '" + python + "'. " +
    "Set PYTHON env or install Python 3.6+.\n"
  );
  process.stderr.write(String(err) + "\n");
  process.exit(1);
});

proc.on("exit", (code) => {
  process.exit(code === null ? 1 : code);
});

["SIGINT", "SIGTERM"].forEach((sig) => {
  process.on(sig, () => proc.kill(sig));
});
