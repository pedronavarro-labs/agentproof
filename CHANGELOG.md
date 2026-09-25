# Changelog

## Unreleased

- Add an experimental in-process tool-dispatch gate and synthetic read/write demo. The gate blocks writes and undeclared tools on its own path; it is not an MCP server or production enforcement boundary.
- Add a narrow MCP 2025-11-25 stdio server, local SQLite decision journal and adversarial tests.
- Add an opt-in RFC 7662 introspection hook and separate one-use human approval workflow for the local stdio pilot. A real identity-provider deployment, tamper-resistant evidence and independent review remain future work.
- Add an optional Google identity adapter: service-account ID token verification and fresh Google account login for a separate allowlisted reviewer. Live Google Cloud integration remains a deployment task.

## 0.1.0a1 — experimental source release

Initial AAM draft, MCP config scanner, baseline report, fixtures, RFC and composite Action. No signed release or public package publication is claimed.
