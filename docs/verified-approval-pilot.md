# Verified identity and one-use approval pilot

This opt-in **local stdio** integration obtains identity and scopes from an external OAuth authorization server through [RFC 7662 token introspection](https://www.rfc-editor.org/rfc/rfc7662). It is an application-level host integration, **not** the MCP HTTP authorization protocol. An MCP JSON-RPC request cannot provide a trusted token, scope or approval. The host launches one isolated server process per agent principal with a host-owned access token. Each `tools/list` and `tools/call` re-introspects that token over HTTPS and requires `active`, exact issuer, audience, subject, non-expired `exp` and scope string. The subject must match the host-configured manifest principal. Provider errors fail closed.

For Google accounts, use the separate [Google sign-in adapter](google-signin.md). Google ID tokens identify a service account and an allowlisted person; Google OAuth API scopes are not AgentProof tool grants. The RFC 7662 configuration below applies to providers that actually support introspection.

The [reviewer program](../examples/mcp-runtime/review_approval.py) runs in a separate terminal/process. It reads a pending request directly from SQLite and displays the exact JSON arguments, subject, tool, policy digest and expiry. It obtains a reviewer OAuth token without command-line echo, introspects it against a **separate reviewer audience**, requires `agentproof:approve`, and refuses self-approval. The request is bound to agent subject, tool, SHA-256 of canonical arguments and the full manifest digest. Approval lasts at most five minutes or until the agent credential expires, and is consumed atomically before the handler. A changed call or policy needs a new review; a replay is denied. The approval decision is never taken from model text or MCP arguments.

## Configure an actual identity provider

The provider must support RFC 7662 introspection and return `active`, `iss`, `aud`, `sub`, `exp`, `scope`. Provision an agent access token with `tickets:read tickets:write` for the `AGENTPROOF_AGENT_AUDIENCE`, and a **different human** reviewer token with `agentproof:approve` for `AGENTPROOF_REVIEWER_AUDIENCE`. Securely configure the host environment, outside an agent-controlled MCP config:

| Host variable | Meaning |
| --- | --- |
| `AGENTPROOF_INTROSPECT_URL` | HTTPS introspection endpoint |
| `AGENTPROOF_CLIENT_ID`, `AGENTPROOF_CLIENT_SECRET` | Introspection client credentials |
| `AGENTPROOF_ISSUER` | Exact expected issuer string returned by introspection |
| `AGENTPROOF_AGENT_AUDIENCE` | Expected agent resource audience |
| `AGENTPROOF_REVIEWER_AUDIENCE` | Expected reviewer approval audience |
| `AGENTPROOF_AGENT_SUBJECT` | Host-approved exact agent `sub` |
| `AGENTPROOF_AGENT_TOKEN` | Host-owned access token, never an MCP argument |
| `AGENTPROOF_APPROVAL_DB`, `AGENTPROOF_AUDIT_DB` | Separate local SQLite paths accessible to trusted processes |

Run `python examples/mcp-runtime/verified_server.py` as the MCP stdio server. With verified write scope, `tools/list` advertises the write tool. A write first returns `approval_required:<id>` without changing the ticket. The reviewer independently runs `python examples/mcp-runtime/review_approval.py <id>`, checks the displayed structured operation and types `APPROVE` and their own access token. An identical retry can execute once. Keep both processes alive and the databases accessible. The example's ticket state is memory-only and synthetic; production deployment requires a real handler and provider-specific configuration. The original `server.py` demo remains read-only.

## Threats and limits

| Attack | Enforced behavior | Residual risk |
| --- | --- | --- |
| MCP client supplies fake scopes, approval or token in arguments | Ignored as authority; host-owned token is introspected for each operation | A compromised host or leaked host token can impersonate the process |
| Wrong issuer, audience, subject, inactive or expired token | Deny before tool visibility or execution | Trust rests on TLS, introspection provider and correct host configuration |
| Agent approves its own write | Reviewer must have separate subject, audience and scope | Stolen reviewer credential or compromised review process defeats this |
| Agent changes arguments or manifest after approval | Digest mismatch; new review required | Reviewer must understand side effects and the handler must use the reviewed arguments |
| Agent retries the same approval or races another process | SQLite transaction consumes it once before execution | A crash after consume loses approval; no automatic retry or exactly-once side effect guarantee |
| Audit storage fails | Handler does not run | SQLite logs and approvals can be edited by a privileged local operator |
| Malicious prompt hides context from reviewer | Reviewer reads database values in independent terminal | The demo stores plaintext arguments in SQLite and cannot judge semantic harm |

Security boundaries remain conditional: protect the host launch environment, restrict DB file permissions and filesystem access, make the guarded process the **only** path to handler credentials, pin a reviewed manifest and tool registry, use a real identity provider, and review how the provider issues reviewer tokens. The reviewer approval authorizes one operation, not a session. The code does not provide a browser approval UI, deploy an identity provider, verify MFA, support a multi-tenant HTTP MCP gateway or attest that an external deployment actually enforces the policy. Commission an independent review before claiming production-grade enforcement.
