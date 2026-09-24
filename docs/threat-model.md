# Threat model (v0alpha1)

The assets are delegated credentials, protected data, state-changing tool actions, and the integrity of manifests and review reports. Boundaries exist between repository content and CI, between agent runtime and MCP servers, and between tools and protected systems.

An attacker can edit a manifest in a pull request, plant misleading text in a tool description, or submit a synthetic fixture to a public issue. AgentProof treats input as data and never executes MCP server commands during scanning. It drops URL strings, arguments, headers and environment values to avoid copying secrets into reports. The JSON/YAML parser rejects duplicate keys and files larger than 1 MB. Markdown output escapes table delimiters and HTML brackets in finding content.

The most important residual risk is **evidence forgery**: the author can claim `source: verified` and cite a fabricated evidence ID. v0alpha1 checks internal consistency only, not authenticity. An auditor needs independent evidence and a later signed attestation design. A passing report does not prove runtime approval, least privilege or prompt-injection resistance. CI runs third-party code via `pip install` and should pin this Action to a reviewed commit and use minimal token permissions.

Prompt injection can still cause an agent to call a dangerous tool even when a manifest is complete. AAM describes expected action boundaries; runtime authorization and human approval must be enforced by their actual components. The baseline is intended to reveal review gaps before merge, not substitute for those components.
