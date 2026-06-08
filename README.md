# secrets-audit-mcp

[![smithery badge](https://smithery.ai/badge/eltociear/secrets-audit-mcp)](https://smithery.ai/server/eltociear/secrets-audit-mcp) [![MCP Registry](https://img.shields.io/badge/MCP_Registry-active-2da44e)](https://registry.modelcontextprotocol.io)

> MCP server that detects leaked credentials in source code. Zero dependencies. Single file.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2024--11--05-orange)](https://modelcontextprotocol.io/)
[![Sister: skill-audit-mcp](https://img.shields.io/badge/sister-skill--audit--mcp-purple)](https://github.com/eltociear/skill-audit-mcp)

Detects API keys, OAuth tokens, private keys, webhooks, and crypto wallet
secrets across 30+ providers (AWS, GCP, GitHub, Stripe, OpenAI, Anthropic,
Slack, Discord, Telegram, Twilio, SendGrid, Heroku, DigitalOcean, npm,
HuggingFace, Replicate, Cloudflare, and more).

Companion to [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp)
(behavioral patterns) — together they cover secrets + behaviors in one
MCP toolchain.

---

## Why

Most secret scanners are giant Go binaries (trufflehog, gitleaks). This is
a 500-line Python file that runs as an MCP stdio server, so any LLM agent
(Claude Desktop, Cursor, Windsurf, Cline) can ask it `scan_directory` and
get a structured report in their tool-call response.

Use cases:
- Pre-commit hook in CI
- Agent-driven code review ("did this PR leak credentials?")
- Audit a freshly-cloned repo before opening it in your shell
- Inline scan during agent file edits

---

## Install

```bash
# Python (recommended)
git clone https://github.com/eltociear/secrets-audit-mcp.git
python3 secrets-audit-mcp/server.py  # stdio MCP server

# Or via npm wrapper (TBD)
npm install -g @eltociear/secrets-audit-mcp
```

### MCP client config

```json
{
  "mcpServers": {
    "secrets-audit": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/secrets-audit-mcp/server.py"]
    }
  }
}
```

---

## Tools

| Tool | Use case |
|---|---|
| `scan` | Scan inline text/content |
| `scan_file` | Scan a single file |
| `scan_directory` | Scan a directory recursively (skips `.git`, `node_modules`, `__pycache__`, etc.) |

All return a risk score (0-100), severity bucket (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`SAFE`),
and per-finding details with line numbers and redacted matches.

---

## Coverage

**Providers** (32 rules total):

- **Cloud**: AWS access/secret, GCP API key + service-account JSON, Heroku, DigitalOcean, Cloudflare
- **Source/CI**: GitHub PAT/OAuth/App/Refresh/Fine-grained, npm tokens, Docker Hub PAT
- **Payments**: Stripe secret + restricted
- **Comms**: Slack bot/user/webhook, Discord bot/webhook, Telegram bot, Twilio, SendGrid, Mailgun
- **AI/ML**: OpenAI, Anthropic, HuggingFace, Replicate
- **Web3**: Ethereum private key (context-aware), Alchemy, Infura
- **Keys**: RSA / EC / OpenSSH / PGP / generic PEM private keys
- **Generic**: JWT, `apikey="..."` heuristic, generic secret assignments

Each match is redacted (`AKIA***MPLE`) before being returned, so the report
itself doesn't leak the secret to the next LLM hop.

---

## CI usage

```yaml
- name: Secrets audit
  run: |
    python3 server.py <<EOF | jq -r '.result.content[0].text'
    {"jsonrpc":"2.0","id":1,"method":"tools/call",
     "params":{"name":"scan_directory","arguments":{"path":"."}}}
    EOF
```

A first-class GitHub Action will ship as `eltociear/secrets-audit-action@v1`.

---

## Sister project — skill-audit-mcp

[skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp) covers
**behavioral malware patterns** (download-and-execute, prompt injection,
credential exfiltration). Run both for full coverage:

| Layer | Tool | Detects |
|---|---|---|
| Static behaviors | skill-audit-mcp | curl-pipe-sh, exfiltration, prompt injection (68 patterns) |
| Static secrets | secrets-audit-mcp | leaked keys/tokens/PEMs (32 rules) |

---

## Subscribe — security pulse

[**Polar.sh — Security Pulse Monthly**](https://polar.sh/eltociear/products/security-pulse-monthly)
ships a monthly briefing on new MCP server vulnerabilities, secrets-audit-mcp
rule updates, and mitigation playbooks. $5/mo.

[**Polar.sh — Pro Audit Stack**](https://polar.sh/eltociear/products/pro-audit-stack)
adds 50 paid scan credits + Discord + custom rule submission. $20/mo.

---

## License

MIT. See [LICENSE](LICENSE).

## Free MCP vs paid x402

This MCP server is **free**. For server-side / batch / no-install use, the same scanner is a pay-per-call **x402** HTTP API: `POST https://eltociear-secrets-audit.hf.space/audit` ($0.01 USDC on Base) and `/audit/url` ($0.03). In the official MCP Registry as `io.github.eltociear/secrets-audit-mcp`.
