"""Run a synthetic MCP stdio server; all writes fail closed."""

from __future__ import annotations

import os
from pathlib import Path

from agentproof.audit import SQLiteAudit
from agentproof.core import load_document
from agentproof.mcp_stdio import MCPStdioServer
from agentproof.runtime import RuntimeGuard, Tool


def main() -> None:
    manifest = load_document(Path(__file__).parents[1] / "runtime-demo/read-only-agent.yaml")
    # The host fixes these bindings and scopes. The MCP client cannot set them
    # through JSON-RPC parameters. This is a local demo, not authenticated ID.
    granted_scopes = {"tickets:read"}
    tickets = {"T-1": "open"}
    audit = SQLiteAudit(os.environ.get("AGENTPROOF_AUDIT_DB", "agentproof-decisions.sqlite3"))
    guard = RuntimeGuard(manifest, {
        "tickets.get": Tool("read", lambda args: {"id": args["id"], "status": tickets[args["id"]]}),
        "tickets.update": Tool("write", lambda args: tickets.__setitem__(args["id"], args["status"])),
    }, granted_scopes, audit=audit)
    definitions = {
        "tickets.get": {"name": "tickets.get", "description": "Read a synthetic ticket",
                        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": False}},
        "tickets.update": {"name": "tickets.update", "description": "Update a synthetic ticket (denied)",
                           "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "status": {"type": "string"}}, "required": ["id", "status"], "additionalProperties": False}},
    }
    try:
        MCPStdioServer(guard, definitions).serve()
    finally:
        audit.close()


if __name__ == "__main__":
    main()
