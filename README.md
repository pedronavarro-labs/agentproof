# AgentProof

AgentProof is an experimental, local-first tool for reviewing an AI agent's stated identity, permissions and approval boundaries. It turns an **Agent Assurance Manifest (AAM)** into a deterministic report that a developer can inspect in a pull request. Its current scanner reads MCP configuration without retaining secret values. This project is independent and is **not** an MCP or A2A standard, compliance certification or runtime security boundary.

## Try the demo

Requires Python 3.10+.

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/agentproof verify fixtures/insecure/broad-scope.yaml --format markdown --fail-on none
.venv/bin/agentproof verify fixtures/secure/support-agent.yaml
.venv/bin/agentproof scan --input examples/mcp-server/mcp.json --output /tmp/agentproof-scanned.yaml
.venv/bin/agentproof verify /tmp/agentproof-scanned.yaml --fail-on none
```

The insecure example reports missing approval, unmapped `admin:*` scope, long-lived credentials and other review gaps. The secure example has no baseline findings, but its evidence is illustrative, so that result does **not** establish that any deployed agent is safe. The scanner intentionally discards URL strings, command arguments, environment values and header values; it retains server names, which should also be reviewed before sharing. It cannot infer tool permissions from an MCP client config; edit the generated manifest with verified information before relying on it.

## Use in CI

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: pedronavarro-labs/agentproof@<reviewed-commit-sha>
    with:
      manifest: path/to/agentproof.yaml
      fail-on: high
```

Pin to a reviewed commit SHA for production use. The composite Action installs its own source locally on the runner, writes Markdown and JSON reports and uploads a report artifact. It does not require an AgentProof cloud account. The Action has not been independently security-audited; inspect third-party actions and CI permissions before use.

The AAM JSON Schema lives in [`schemas/`](schemas/), with a packaged mirror used by the CLI. Fields distinguish `discovered`, `declared` and `verified`. A `verified` value is still a claim supplied by the manifest author; this alpha checks that evidence IDs exist, not the authenticity or enforcement of that evidence. Reports always state this limit.

## Experimental runtime pilot

An optional [in-process tool gate](docs/runtime-pilot.md) lets a trusted host route synthetic MCP-style tool calls through the manifest. The demo permits a declared read and denies an undeclared write **before** its handler runs:

```bash
python examples/runtime-demo/demo.py
```

The gate is a library example, not a general MCP server, proxy or automatic interception mechanism. It requires the host to own the tool bindings and scope information and to route all calls through it. It currently denies every state-changing action, including declared writes, because there is no trusted approval integration. It does not authenticate the caller, verify real token scopes, detect bypasses or prove deployed enforcement. The static CI report remains a declaration review.

An additional [MCP stdio pilot](docs/mcp-stdio-security.md) processes real JSON-RPC `initialize`, `tools/list` and `tools/call` messages. Try `python examples/mcp-runtime/client_demo.py` after installing the package. It exposes only authorized read tools and writes decision metadata to a local SQLite file. The client and ticket are synthetic; this is not an authenticated or production-ready gateway.

The baseline includes AP-001 through AP-010. Rules apply when relevant: for example, A2A signature evidence is evaluated only if an A2A protocol entry exists. A2A discovery, signature verification and signed attestations are planned, not implemented. See the [RFC](docs/rfc/0001-agent-assurance-manifest.md), [threat model](docs/threat-model.md), [roadmap](ROADMAP.md) and [contribution guide](CONTRIBUTING.md).

## Give useful feedback

The most valuable early feedback is a **synthetic, redacted fixture** that the AAM cannot represent, or a specific policy finding that is misleading. Please avoid posting real tokens, private repository names, internal hostnames or production MCP configuration. Open an issue using the RFC feedback template; we will discuss compatibility changes in public before changing the schema.

License: Apache-2.0. Copyright 2026 Pedro Navarro.
