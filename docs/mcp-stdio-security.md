# MCP stdio security pilot

This pilot implements a small subset of the MCP **2025-11-25** stdio protocol: `initialize`, `notifications/initialized`, `ping`, `tools/list`, and `tools/call`. Messages are newline-delimited UTF-8 JSON-RPC. The server responds with MCP tool results and `isError` for denied known tools. It is not an MCP SDK, a generic upstream proxy, or a claim of full protocol compatibility. Protocol references: [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

Run after `pip install -e .`:

```bash
python examples/mcp-runtime/client_demo.py
python -m unittest discover -s tests -v
```

The host owns the tool handler registry, read/write classification, manifest and granted scopes. The MCP client can send tool names and arguments, but cannot supply trusted scopes or approval. `tools/list` hides writes and reads without grants. `tools/call` checks policy and JSON Schema immediately before the handler. A declared write is still denied because there is no independent human approval verifier. The synthetic client attempts a write anyway and the ticket remains open.

The demo stores only UTC time, manifest name/revision, tool name, decision and reason in a local SQLite file. It stores no arguments or tool results. If the audit write fails, the handler does not run. **SQLite is durable locally but not tamper-resistant:** an operator with file access can edit or delete it. The manifest revision is a declared field, not an independently verified content digest.

## Threat checks and boundaries

| Scenario | Pilot evidence | Remaining risk |
| --- | --- | --- |
| Agent invokes an undeclared write | MCP `tools/call` returns a denial; state remains open | Direct access to the handler or another connection bypasses this process |
| Client forges `approved` or `granted_scopes` in arguments | Values do not become trusted context; schema can reject unexpected fields | Host must obtain real identity and grants independently |
| Manifest declares a write | Still denied without a trusted approval integration | No approval workflow is implemented |
| Audit storage fails | Read handler does not execute | The local DB can be altered later; no remote anchor |
| Host mislabels a mutating handler as read | Not detected | Requires independent tool review or stronger isolation |
| Prompt injection induces an allowed read | Read may still execute | No content-level prompt defense or data loss prevention |

These checks partially address **OWASP Agentic Top 10 ASI02 (Tool Misuse)** and **ASI03 (Identity and Privilege Abuse)**; they do not certify compliance. The [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/) describes portable runtime hooks; AgentProof does not implement that interface. The AAM remains an independent experimental manifest, not an official MCP or OWASP standard.

## Production design gaps

1. Use an actual protected MCP deployment, ideally with the official SDK and interoperability tests. For remote Streamable HTTP, verify tokens and scopes according to the MCP authorization specification; stdio launch configuration is not proof of a human or workload identity.
2. Put all handlers and credentials behind an exclusive enforcement point. Bind policy to an independently verified manifest digest and compare the served tool definitions against reviewed bindings.
3. Implement one-time, action-specific approval from an authenticated reviewer through a separate service. Bind it to principal, tool, canonical argument digest, policy version and expiry. Recheck atomically immediately before execution; reject replay and revocation.
4. Export privacy-limited decision events to a protected, externally anchored audit store, and test failures, retries, concurrency and tampering.
5. Commission an external review before making claims of production enforcement.
