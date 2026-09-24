# RFC 0001: Agent Assurance Manifest (AAM) v0alpha1

Status: public experimental draft. Maintainer: Pedro Navarro. Feedback welcome through GitHub Issues.

## Problem

Agent applications can acquire MCP tools and broad credentials without one reviewable record connecting identities, scopes, individual operations, approvals and evidence. AAM provides a portable **description** and local review, not a security guarantee.

## Vocabulary

- **Principal:** the workload identity used by an agent. `user:` identifies a human and triggers a baseline finding.
- **Capability:** a named operation, risk and scope mapping. An MCP client config does not reveal capabilities by itself.
- **Source:** `discovered` means extracted from a supported config; `declared` is an author's statement; `verified` means the author links a verification record. AgentProof does not validate the record's authenticity in v0alpha1.
- **Approval enforcement point:** the component named by the author as enforcing human authorization.
- **Evidence:** a reference ID and description that make a claim reviewable. A link alone is not proof.
- **Finding:** an actionable baseline observation with severity and remediation, not a certification outcome.

## Format and compatibility

`apiVersion: agentproof.dev/v0alpha1` and `kind: AgentAssuranceManifest` identify this draft. JSON Schema is canonical and YAML is a convenient serialization; duplicate mapping keys and unknown fields fail validation to prevent ambiguous security assertions. The v0alpha1 format is expected to change based on public review. Consumers must reject unknown `apiVersion` values rather than silently assuming compatible semantics.

Three valid examples are in `fixtures/secure/`: a write-capable support agent, a read-only agent and an explicitly documented exception. Five intentionally risky examples are in `fixtures/insecure/`. They use synthetic identities and `.invalid` endpoints. Each can be checked with `agentproof verify`.

## Trust and scope

The MCP scanner extracts server names and whether an Authorization header key exists. It does not connect to a server, discover tools, execute configuration, or retain secrets. A manifest's identity, scopes, approval and control entries require separate human or automated evidence. The static baseline detects missing or inconsistent declarations; actual enforcement, token audience validation and A2A signatures must be verified outside this alpha. We will not label such checks as completed by the CLI.

## Open questions

1. What is the smallest cross-runtime identity representation that can map one capability to one delegated scope?
2. Which evidence fields are necessary to make a `verified` claim independently checkable without publishing sensitive configuration?
3. Should an approval exception be allowed for `payment`, or require an explicit policy override?
4. How should a future A2A adapter represent an Agent Card signature and its verification time without conflating a published card with trusted identity?
5. What compatibility rules would let another project consume AAM without adopting the AgentProof CLI?

Please suggest concrete changes with synthetic fixtures and expected findings. Schema and baseline changes should have an RFC discussion, migration notes and tests.
