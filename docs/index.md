---
title: secrets-audit-mcp — Leaked-secret scanner for MCP & AI agent code
description: 32 provider rules. AWS, GCP, Azure, GitHub, Stripe, OpenAI, Anthropic, Slack and more. CLI / GitHub Action / Docker / MCP server.
---

# secrets-audit-mcp

**Leaked-secret scanner for MCP servers, AI agent skills, and source trees.** 32 provider rules across cloud, payments, and AI APIs. Ships as a CLI, GitHub Action, multi-arch Docker image, and MCP server.

[![GitHub stars](https://img.shields.io/github/stars/eltociear/secrets-audit-mcp?style=social)](https://github.com/eltociear/secrets-audit-mcp)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/eltociear/secrets-audit-mcp/blob/main/LICENSE)

---

## Try it in 30 seconds

```bash
docker run --rm -v "$PWD:/work" ghcr.io/eltociear/secrets-audit-mcp:v1 --path /work
```

```yaml
# GitHub Action
- uses: eltociear/secrets-audit-mcp@v1
  with:
    path: .
```

---

## Provider coverage (32 rules)

| Category | Providers |
|----------|-----------|
| Cloud | AWS access key + secret, GCP service-account JSON, Azure connection string, DigitalOcean token, Linode token |
| AI APIs | OpenAI, Anthropic, Mistral, Cohere, Replicate, HuggingFace |
| Payments | Stripe live + test, Square, PayPal client secret |
| Code & infra | GitHub PAT + fine-grained, GitLab token, Bitbucket, npm token, Vercel, Netlify |
| Messaging | Slack bot + user, Discord bot, Telegram bot, Twilio |
| Databases | MongoDB Atlas, Supabase service role, PlanetScale |
| Crypto / web3 | Alchemy, Infura, Moralis, Helius |

---

## Sibling tool

- **[skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp)** — covers 68 attack patterns (prompt injection, tool poisoning, RCE, exfiltration). Same delivery surface.

Run them together for full coverage of MCP supply-chain risk.

---

[GitHub](https://github.com/eltociear/secrets-audit-mcp) · [Docker](https://github.com/eltociear/secrets-audit-mcp/pkgs/container/secrets-audit-mcp) · [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp)
