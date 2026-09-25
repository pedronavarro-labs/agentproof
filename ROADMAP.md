# Roadmap

- **v0.1.0a1:** AAM schema, YAML/JSON CLI, conservative MCP config discovery, AP-001–AP-010 static findings, synthetic fixtures, reports and a composite GitHub Action. Public RFC review is open.
- **v0.1 stable (planned):** incorporate external fixture feedback, improve policy configuration and harden a signed, reproducible release process with a software bill of materials. No date promised.
- **Later:** A2A Agent Card discovery and signature verification, manifest diff and signed provenance/attestations. These are not current features.
- **Experimental runtime pilot:** an in-process dispatch gate and synthetic read/write example are available for feedback. No production enforcement claim.
- **MCP stdio pilot:** a narrow local server handles `tools/call` with a durable SQLite decision journal. An opt-in host integration introspects agent and reviewer OAuth tokens and consumes exact-operation approvals once. Next: real identity-provider integration testing, SDK interoperability, protected Streamable HTTP, externally anchored audit, bypass testing and independent review.
- **Google adapter:** service-account ID token validation and an interactive Google reviewer login are available as an optional local example. Next: test against a real Google Cloud project and a hosted enforcement point. No Google account or credential is bundled.

Compatibility is experimental until v0.1 stable. Each schema change requires fixtures, migration notes and public rationale.
