"""Synthetic in-process MCP tool dispatch, with no network or credentials."""

import json
from pathlib import Path

from agentproof.core import load_document
from agentproof.runtime import Denied, RuntimeGuard, Tool


def main():
    manifest = load_document(Path(__file__).with_name("read-only-agent.yaml"))
    state = {"ticket": "open"}

    def read_ticket(arguments):
        return {"id": arguments["id"], "status": state["ticket"]}

    def update_ticket(arguments):
        state["ticket"] = arguments["status"]
        return {"status": state["ticket"]}

    # The host owns these bindings and the granted scopes, not the agent.
    guard = RuntimeGuard(manifest, {
        "tickets.get": Tool("read", read_ticket),
        "tickets.update": Tool("write", update_ticket),
    }, granted_scopes={"tickets:read"})

    print("Read:", guard.call("tickets.get", {"id": "T-1"}))
    try:
        guard.call("tickets.update", {"id": "T-1", "status": "closed"})
    except Denied as exc:
        print("Write blocked:", exc)
    print("Final state:", state)
    print("Audit (no arguments or result values):")
    print(json.dumps(guard.events, indent=2))


if __name__ == "__main__":
    main()
