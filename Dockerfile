FROM python:3.11-alpine

LABEL org.opencontainers.image.title="secrets-audit-mcp"
LABEL org.opencontainers.image.description="MCP server detecting leaked credentials. 32 provider rules, zero deps."
LABEL org.opencontainers.image.url="https://github.com/eltociear/secrets-audit-mcp"
LABEL org.opencontainers.image.source="https://github.com/eltociear/secrets-audit-mcp"
LABEL org.opencontainers.image.licenses="MIT"
# Required by the official MCP Registry to verify OCI image ownership (must match server.json name).
LABEL io.modelcontextprotocol.server.name="io.github.eltociear/secrets-audit-mcp"

WORKDIR /app
COPY server.py /app/server.py
COPY README.md LICENSE /app/

ENTRYPOINT ["python3", "/app/server.py"]
