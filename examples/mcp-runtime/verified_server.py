"""Opt-in authenticated stdio pilot; configure a real RFC 7662 provider first.

All secrets and expected subject are host launch configuration, never MCP args.
The MCP client is not individually authenticated: the host token represents
the entire launched process. Use an isolated process per principal.
"""

import copy
import os
from pathlib import Path

from agentproof.approval import ApprovalStore
from agentproof.audit import SQLiteAudit
from agentproof.auth import OAuthIntrospector
from agentproof.core import load_document
from agentproof.google_identity import GoogleAgentIdentity, GoogleGuardProvider
from agentproof.mcp_stdio import MCPStdioServer
from agentproof.runtime import RuntimeGuard, Tool
from agentproof.verified import VerifiedGuardProvider


def setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing host configuration: {name}")
    return value


def main() -> None:
    manifest = copy.deepcopy(load_document(Path(__file__).parents[1] / "runtime-demo/read-only-agent.yaml"))
    use_google = os.environ.get("AGENTPROOF_IDENTITY_PROVIDER") == "google"
    google_sub = setting("AGENTPROOF_GOOGLE_AGENT_SUB") if use_google else None
    manifest["identity"]["principal"] = (
        f"google:{google_sub}" if use_google else setting("AGENTPROOF_AGENT_SUBJECT"))
    manifest["access"]["delegatedScopes"].append("tickets:write")
    manifest["capabilities"].append({"id": "tickets.write", "source": "declared",
                                      "tool": "tickets.update", "operation": "write",
                                      "risk": "high", "scopes": ["tickets:write"],
                                      "approval": "required", "rollback": "Restore prior status"})
    tickets = {"T-1": "open"}
    tools = {"tickets.get": Tool("read", lambda args: {"id": args["id"], "status": tickets[args["id"]]}),
             "tickets.update": Tool("write", lambda args: tickets.__setitem__(args["id"], args["status"]))}
    definitions = {
        name: {"name": name, "inputSchema": {"type": "object", "properties": properties,
                                              "required": list(properties), "additionalProperties": False}}
        for name, properties in {
            "tickets.get": {"id": {"type": "string"}},
            "tickets.update": {"id": {"type": "string"}, "status": {"type": "string"}},
        }.items()}
    db = setting("AGENTPROOF_APPROVAL_DB")
    approvals = ApprovalStore(db)
    audit = SQLiteAudit(setting("AGENTPROOF_AUDIT_DB"))
    if use_google:
        identity = GoogleAgentIdentity(setting("AGENTPROOF_GOOGLE_AGENT_AUDIENCE"),
                                       google_sub, {"tickets:read", "tickets:write"})
        provider = GoogleGuardProvider(manifest, tools, identity, approvals, audit)
    else:
        introspector = OAuthIntrospector(setting("AGENTPROOF_INTROSPECT_URL"),
                                         setting("AGENTPROOF_CLIENT_ID"), setting("AGENTPROOF_CLIENT_SECRET"),
                                         setting("AGENTPROOF_ISSUER"), setting("AGENTPROOF_AGENT_AUDIENCE"))
        provider = VerifiedGuardProvider(manifest, tools, setting("AGENTPROOF_AGENT_TOKEN"),
                                         introspector, approvals, audit)
    # No tools are exposed before a successful independent introspection.
    bootstrap = RuntimeGuard(manifest, tools, set(), audit=audit)
    try:
        MCPStdioServer(bootstrap, definitions, guard_provider=provider).serve()
    finally:
        approvals.close()
        audit.close()


if __name__ == "__main__":
    main()
