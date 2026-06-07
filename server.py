#!/usr/bin/env python3
"""
secrets-audit MCP Server v1.0.0
Detects leaked credentials and secrets in source code / configs.

Zero dependencies. Single file. Python 3.6+.
MCP protocol (JSON-RPC 2.0 over stdio).

Usage:
  Add to .mcp.json:
  {
    "secrets-audit": {
      "type": "stdio",
      "command": "python3",
      "args": ["server.py"]
    }
  }
"""

import sys
import json
import re
import os
import base64

VERSION = "1.0.1"
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "secrets-audit"

# ────────────────────────────────────────────────────────
# Secret signatures
# Each rule: id, name, severity, regex (anchored), entropy_min (optional)
# Severity: CRITICAL (active key formats), HIGH (private keys), MEDIUM (probable), LOW (heuristic)
# ────────────────────────────────────────────────────────

RULES = [
    # AWS
    {"id": "aws_access_key_id", "name": "AWS Access Key ID", "severity": "CRITICAL",
     "regex": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"},
    {"id": "aws_secret_key", "name": "AWS Secret Access Key", "severity": "CRITICAL",
     "regex": r"(?i)aws(.{0,20})?(secret|sk)(.{0,20})?[\"'`=:\s][\"'`]?([A-Za-z0-9/+=]{40})[\"'`]?"},

    # Google / GCP
    {"id": "gcp_api_key", "name": "Google API Key", "severity": "CRITICAL",
     "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b"},
    {"id": "gcp_service_account", "name": "GCP Service Account JSON", "severity": "CRITICAL",
     "regex": r"\"type\":\s*\"service_account\""},

    # GitHub
    {"id": "github_pat", "name": "GitHub Personal Access Token", "severity": "CRITICAL",
     "regex": r"\bghp_[0-9A-Za-z]{36}\b"},
    {"id": "github_oauth", "name": "GitHub OAuth Token", "severity": "CRITICAL",
     "regex": r"\bgho_[0-9A-Za-z]{36}\b"},
    {"id": "github_app", "name": "GitHub App Token", "severity": "CRITICAL",
     "regex": r"\b(ghu|ghs)_[0-9A-Za-z]{36}\b"},
    {"id": "github_refresh", "name": "GitHub Refresh Token", "severity": "CRITICAL",
     "regex": r"\bghr_[0-9A-Za-z]{36}\b"},
    {"id": "github_fine_pat", "name": "GitHub Fine-grained PAT", "severity": "CRITICAL",
     "regex": r"\bgithub_pat_[0-9A-Za-z_]{82}\b"},

    # Stripe
    {"id": "stripe_secret_key", "name": "Stripe Secret Key", "severity": "CRITICAL",
     "regex": r"\bsk_(?:live|test)_[0-9A-Za-z]{24,99}\b"},
    {"id": "stripe_restricted_key", "name": "Stripe Restricted Key", "severity": "CRITICAL",
     "regex": r"\brk_(?:live|test)_[0-9A-Za-z]{24,99}\b"},

    # Slack
    {"id": "slack_bot_token", "name": "Slack Bot Token", "severity": "CRITICAL",
     "regex": r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[0-9A-Za-z]{24,}\b"},
    {"id": "slack_user_token", "name": "Slack User Token", "severity": "CRITICAL",
     "regex": r"\bxoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[0-9A-Za-z]{32}\b"},
    {"id": "slack_webhook", "name": "Slack Webhook URL", "severity": "HIGH",
     "regex": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24,}"},

    # OpenAI / Anthropic / AI providers
    {"id": "openai_key", "name": "OpenAI API Key", "severity": "CRITICAL",
     "regex": r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"},
    {"id": "anthropic_key", "name": "Anthropic API Key", "severity": "CRITICAL",
     "regex": r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,}\b"},
    {"id": "huggingface_token", "name": "HuggingFace Token", "severity": "CRITICAL",
     "regex": r"\bhf_[A-Za-z0-9]{30,}\b"},
    {"id": "replicate_token", "name": "Replicate API Token", "severity": "CRITICAL",
     "regex": r"\br8_[A-Za-z0-9]{37}\b"},

    # Cloud / infra
    {"id": "heroku_api_key", "name": "Heroku API Key", "severity": "CRITICAL",
     "regex": r"(?i)heroku(.{0,20})?[\"'`=:\s][\"'`]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"'`]?"},
    {"id": "digitalocean_token", "name": "DigitalOcean Token", "severity": "CRITICAL",
     "regex": r"\bdop_v1_[a-f0-9]{64}\b"},
    {"id": "cloudflare_api_token", "name": "Cloudflare API Token", "severity": "CRITICAL",
     "regex": r"(?i)cf(.{0,5})?(api|token)(.{0,20})?[\"'`=:\s][\"'`]?([A-Za-z0-9_-]{40})[\"'`]?"},

    # Database / messaging
    {"id": "twilio_sid", "name": "Twilio Account SID", "severity": "HIGH",
     "regex": r"\bAC[0-9a-f]{32}\b"},
    {"id": "sendgrid_key", "name": "SendGrid API Key", "severity": "CRITICAL",
     "regex": r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"},
    {"id": "mailgun_key", "name": "Mailgun API Key", "severity": "CRITICAL",
     "regex": r"\bkey-[a-f0-9]{32}\b"},

    # Private keys
    {"id": "rsa_private_key", "name": "RSA Private Key", "severity": "HIGH",
     "regex": r"-----BEGIN RSA PRIVATE KEY-----"},
    {"id": "ec_private_key", "name": "EC Private Key", "severity": "HIGH",
     "regex": r"-----BEGIN EC PRIVATE KEY-----"},
    {"id": "openssh_private", "name": "OpenSSH Private Key", "severity": "HIGH",
     "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----"},
    {"id": "pgp_private", "name": "PGP Private Key Block", "severity": "HIGH",
     "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----"},
    {"id": "generic_private_key", "name": "Generic Private Key", "severity": "HIGH",
     "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},

    # Crypto / Web3
    {"id": "ethereum_private_key", "name": "Ethereum Private Key", "severity": "CRITICAL",
     "regex": r"\b0x[a-fA-F0-9]{64}\b", "context_terms": ["private", "secret", "mnemonic", "wallet", "PRIVATE_KEY"]},
    {"id": "alchemy_api_key", "name": "Alchemy API Key", "severity": "HIGH",
     "regex": r"(?i)alchemy(.{0,20})?[\"'`=:\s][\"'`]?([A-Za-z0-9_-]{32})[\"'`]?"},
    {"id": "infura_project_id", "name": "Infura Project ID", "severity": "MEDIUM",
     "regex": r"https://[a-z0-9-]+\.infura\.io/v3/[a-f0-9]{32}"},

    # JWT
    {"id": "jwt_token", "name": "JWT (JSON Web Token)", "severity": "MEDIUM",
     "regex": r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"},

    # Generic high-entropy
    {"id": "generic_secret_assign", "name": "Generic 'secret' Assignment", "severity": "LOW",
     "regex": r"(?i)(api[_-]?key|secret|passwd|password|token)\s*[=:]\s*[\"'`]([A-Za-z0-9_\-]{20,})[\"'`]"},

    # NPM
    {"id": "npm_token", "name": "npm Access Token", "severity": "CRITICAL",
     "regex": r"\bnpm_[A-Za-z0-9]{36}\b"},

    # Docker
    {"id": "docker_hub_pat", "name": "Docker Hub PAT", "severity": "HIGH",
     "regex": r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"},

    # Telegram
    {"id": "telegram_bot_token", "name": "Telegram Bot Token", "severity": "CRITICAL",
     "regex": r"\b[0-9]{8,12}:[A-Za-z0-9_\-]{35}\b"},

    # Discord
    {"id": "discord_bot_token", "name": "Discord Bot Token", "severity": "CRITICAL",
     "regex": r"\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"},
    {"id": "discord_webhook", "name": "Discord Webhook", "severity": "HIGH",
     "regex": r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}"},
]

# Severity weight for risk scoring
SEV_WEIGHT = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 3}


def _line_no(text, pos):
    return text.count("\n", 0, pos) + 1


def _context(text, pos, span=40):
    start = max(0, pos - span)
    end = min(len(text), pos + span)
    s = text[start:end].replace("\n", " ")
    return s


def _has_context(text, pos, terms):
    """Look backward up to 60 chars for any of the context terms (lowercase)."""
    if not terms:
        return True
    window = text[max(0, pos - 80): pos].lower()
    return any(t.lower() in window for t in terms)


def _redact(s):
    """Mask middle of secret for safe display."""
    if len(s) <= 8:
        return "***"
    return s[:4] + "***" + s[-4:]


def scan(text):
    findings = []
    for rule in RULES:
        try:
            for m in re.finditer(rule["regex"], text):
                matched = m.group(0)
                # context filter (e.g., ethereum private key needs 'private' word nearby)
                if rule.get("context_terms"):
                    if not _has_context(text, m.start(), rule["context_terms"]):
                        continue
                findings.append({
                    "rule": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "line": _line_no(text, m.start()),
                    "matched": _redact(matched),
                    "context": _context(text, m.start()),
                })
        except re.error:
            continue

    score = min(100, sum(SEV_WEIGHT.get(f["severity"], 0) for f in findings))
    if score >= 30:
        risk = "CRITICAL"
    elif score >= 15:
        risk = "HIGH"
    elif score >= 8:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"
    else:
        risk = "SAFE"

    return {
        "risk_level": risk,
        "risk_score": score,
        "findings": findings,
        "summary": (
            "%d secrets found across %d rules" % (
                len(findings),
                len(set(f["rule"] for f in findings)),
            )
            if findings else "No secrets detected"
        ),
    }


# ────────────────────────────────────────────────────────
# MCP protocol
# ────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "scan",
        "description": (
            "Scan text content for leaked credentials and secrets. "
            "Detects AWS/GCP/GitHub/Stripe/OpenAI/Anthropic/Slack/Discord tokens, "
            "private keys (RSA/EC/OpenSSH/PGP), JWTs, npm/Docker tokens, and crypto wallet keys."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Text to scan"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "scan_file",
        "description": "Scan a local file for leaked credentials and secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to file"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_directory",
        "description": (
            "Scan a directory recursively for leaked credentials. "
            "Skips .git, node_modules, __pycache__, dist, build by default."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to directory"},
                "extensions": {
                    "type": "string",
                    "description": "Comma-separated extensions (default: scan all text-ish files)",
                    "default": "",
                },
            },
            "required": ["path"],
        },
    },
]

DEFAULT_SKIP = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", ".next", ".cache", "target"}
TEXT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".go", ".java", ".php", ".sh", ".yaml", ".yml",
             ".json", ".env", ".md", ".txt", ".rs", ".cpp", ".c", ".h", ".hpp", ".kt", ".swift", ".sql",
             ".tf", ".hcl", ".toml", ".ini", ".cfg", ".conf", ".xml", ".html", ".css"}


def format_report(result, path=None):
    lines = []
    risk = result["risk_level"]
    score = result["risk_score"]
    icons = {"CRITICAL": "X", "HIGH": "!", "MEDIUM": "*", "LOW": ".", "SAFE": "OK"}
    icon = icons.get(risk, "?")
    header = "[%s] RISK: %s (score %d/100)" % (icon, risk, score)
    if path:
        header += " — %s" % path
    lines.append(header)
    lines.append("  " + result["summary"])
    lines.append("")
    for f in result["findings"]:
        sev = f["severity"]
        lines.append("  [%s] %s (line %d) rule=%s" % (sev, f["name"], f["line"], f["rule"]))
        lines.append("    match: %s" % f["matched"])
        lines.append("    > %s" % f["context"])
        lines.append("")
    return "\n".join(lines)


def handle_scan(args):
    content = args.get("content", "")
    if not content.strip():
        return {"isError": True, "content": [{"type": "text", "text": "Error: empty content"}]}
    result = scan(content)
    return {"content": [{"type": "text", "text": format_report(result)}]}


def handle_scan_file(args):
    path = args.get("path", "")
    if not path or not os.path.isfile(path):
        return {"isError": True, "content": [{"type": "text", "text": "Error: file not found: %s" % path}]}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return {"isError": True, "content": [{"type": "text", "text": "Read error: %s" % e}]}
    result = scan(content)
    return {"content": [{"type": "text", "text": format_report(result, path=path)}]}


def handle_scan_directory(args):
    path = args.get("path", "")
    if not path or not os.path.isdir(path):
        return {"isError": True, "content": [{"type": "text", "text": "Error: dir not found: %s" % path}]}

    exts_arg = (args.get("extensions") or "").strip()
    if exts_arg:
        allowed = {"." + e.strip().lstrip(".") for e in exts_arg.split(",")}
    else:
        allowed = TEXT_EXTS

    reports = []
    total_findings = 0
    files_scanned = 0
    files_with_findings = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_SKIP]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if allowed and ext not in allowed and fname != ".env":
                continue
            full = os.path.join(root, fname)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2 * 1024 * 1024)  # cap 2MB per file
            except Exception:
                continue
            files_scanned += 1
            r = scan(content)
            if r["findings"]:
                files_with_findings += 1
                total_findings += len(r["findings"])
                reports.append(format_report(r, path=full))

    summary = "Scanned %d files. %d had findings. Total findings: %d." % (
        files_scanned, files_with_findings, total_findings)
    body = summary + "\n\n" + ("\n\n".join(reports) if reports else "All clear.")
    return {"content": [{"type": "text", "text": body}]}


HANDLERS = {
    "scan": handle_scan,
    "scan_file": handle_scan_file,
    "scan_directory": handle_scan_directory,
}


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle_request(req):
    method = req.get("method")
    params = req.get("params") or {}
    rid = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": VERSION},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        h = HANDLERS.get(name)
        if not h:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": "Unknown tool: %s" % name}}
        try:
            result = h(args)
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32603, "message": "Tool error: %s" % e}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "Method not found: %s" % method}}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_request(req)
        if resp is not None:
            send(resp)


if __name__ == "__main__":
    main()
