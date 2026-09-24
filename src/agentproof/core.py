"""Offline manifest parsing, MCP discovery and deterministic baseline checks."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

SCHEMA_NAME = "agent-assurance-manifest.v0alpha1.schema.json"
MAX_INPUT_BYTES = 1_000_000
SEVERITIES = {"low": 1, "medium": 2, "high": 3}


class ManifestError(ValueError):
    """A document cannot safely be interpreted as a supported manifest."""


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping(loader: UniqueKeyLoader, node: yaml.MappingNode) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ManifestError("mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _no_aliases(self: UniqueKeyLoader, parent, index):
    if self.check_event(yaml.AliasEvent):
        raise ManifestError("YAML aliases are not supported in security manifests")
    return yaml.SafeLoader.compose_node(self, parent, index)


UniqueKeyLoader.compose_node = _no_aliases


def _json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_document(path: str | Path) -> dict:
    file = Path(path)
    if file.stat().st_size > MAX_INPUT_BYTES:
        raise ManifestError("input exceeds 1 MB")
    content = file.read_text(encoding="utf-8")
    try:
        data = json.loads(content, object_pairs_hook=_json_pairs) if file.suffix.lower() == ".json" else yaml.load(content, Loader=UniqueKeyLoader)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ManifestError(f"invalid document: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("document must be a mapping")
    return data


def validate(manifest: dict) -> None:
    schema = json.loads(files("agentproof").joinpath("schemas", SCHEMA_NAME).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda e: (list(map(str, e.absolute_path)), e.message))
    if errors:
        error = errors[0]
        location = "/".join(map(str, error.absolute_path)) or "root"
        raise ManifestError(f"schema at {location}: {error.message}")
    ids = [c["id"] for c in manifest["capabilities"]]
    if len(ids) != len(set(ids)):
        raise ManifestError("capability IDs must be unique")
    evidence_ids = [e["id"] for e in manifest.get("evidence", [])]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ManifestError("evidence IDs must be unique")


def scan_mcp(path: str | Path, name: str = "scanned-agent") -> dict:
    """Read an MCP JSON config. No environment values, arguments or headers are retained."""
    config = load_document(path)
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        raise ManifestError("expected an MCP JSON config with an mcpServers object")
    protocols = []
    for server_name, server in sorted(servers.items()):
        if not isinstance(server_name, str) or not isinstance(server, dict):
            raise ManifestError("every MCP server needs a name and object configuration")
        endpoint = server.get("url")
        command = server.get("command")
        if endpoint is not None and not isinstance(endpoint, str):
            raise ManifestError(f"MCP server {server_name}: url must be a string")
        if command is not None and not isinstance(command, str):
            raise ManifestError(f"MCP server {server_name}: command must be a string")
        if not endpoint and not command:
            raise ManifestError(f"MCP server {server_name}: expected url or command")
        # URL query strings, userinfo and command strings may contain secrets.
        # The scanner keeps only the server name and transport category.
        headers = server.get("headers")
        authorization = isinstance(headers, dict) and any(str(key).lower() == "authorization" for key in headers)
        protocols.append({"type": "mcp", "source": "discovered", "name": server_name,
                          "authorization": authorization})
    return {
        "apiVersion": "agentproof.dev/v0alpha1", "kind": "AgentAssuranceManifest",
        "metadata": {"name": name},
        "identity": {"source": "declared"},
        "protocols": protocols,
        "capabilities": [],
        "access": {"source": "declared", "delegatedScopes": [], "networkEgress": []},
        "controls": {},
    }


def evaluate(manifest: dict) -> dict:
    """Assess declarations and linked evidence; no runtime enforcement is tested."""
    validate(manifest)
    findings = []
    def add(rule: str, severity: str, message: str, remediation: str) -> None:
        findings.append({"id": rule, "severity": severity, "message": message, "remediation": remediation})

    identity = manifest["identity"]
    caps = manifest["capabilities"]
    access = manifest["access"]
    controls = manifest["controls"]
    evidence = {item["id"] for item in manifest.get("evidence", [])}

    if not identity.get("principal") or identity["principal"].startswith("user:"):
        add("AP-001", "high", "Workload identity is missing or appears to be a human user", "Declare a distinct workload principal")
    lifetime = identity.get("credentialLifetimeMinutes")
    if lifetime is None or lifetime > 60:
        add("AP-002", "medium", "Credential lifetime is unknown or exceeds 60 minutes", "Document a short credential lifetime")
    for cap in caps:
        name = cap["id"]
        if cap["operation"] in {"write", "delete", "payment"}:
            if cap.get("approval") != "required" and not (cap.get("approval") == "exception" and cap.get("exceptionReason")):
                add("AP-003", "high", f"{name}: state-changing action lacks approval or a documented exception", "Declare approval or explain an exception")
        if cap["risk"] == "high" and not cap.get("rollback"):
            add("AP-006", "high", f"{name}: high-risk action lacks a rollback declaration", "Document how to reverse or compensate the action")
    mapped = {scope for cap in caps for scope in cap["scopes"]}
    for scope in access["delegatedScopes"]:
        if scope not in mapped:
            add("AP-004", "high", f"Delegated scope {scope} has no capability mapping", "Map every delegated scope to an explicit capability")
    if not access["networkEgress"] or "*" in access["networkEgress"]:
        add("AP-005", "medium", "Network egress is unknown or unrestricted", "Declare explicit destination hosts")

    def supported(control: dict | None) -> bool:
        return bool(control and control.get("status") == "pass" and control.get("source") == "verified"
                    and control.get("evidenceRef") in evidence)

    if any(p["type"] == "mcp" and p.get("authorization") for p in manifest["protocols"]):
        if not supported(controls.get("tokenAudienceBinding")):
            add("AP-007", "high", "MCP authorization audience binding lacks linked verification evidence", "Link a verification record for audience binding")
    if any(p["type"] == "a2a" for p in manifest["protocols"]):
        if not supported(controls.get("a2aCardSignature")):
            add("AP-008", "medium", "A2A card signature lacks linked verification evidence", "Verify the card signature and link its evidence")
    if not manifest["metadata"].get("revision"):
        add("AP-009", "low", "Manifest has no source revision", "Record the Git commit revision reviewed")
    if any(c.get("approval") == "required" for c in caps):
        if not controls.get("humanApproval", {}).get("enforcementPoint"):
            add("AP-010", "high", "Required approval has no named enforcement point", "Name the component enforcing approval")
    return {
        "apiVersion": manifest["apiVersion"], "policy": "agentproof-baseline/0.1",
        "subject": manifest["metadata"]["name"], "findings": findings,
        "summary": {"high": sum(f["severity"] == "high" for f in findings),
                    "medium": sum(f["severity"] == "medium" for f in findings),
                    "low": sum(f["severity"] == "low" for f in findings)},
        "limitations": "Static declaration and evidence-link review only; no runtime controls or evidence authenticity verified",
    }


def markdown(report: dict) -> str:
    def safe(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;").replace(">", "&gt;")
    lines = ["# AgentProof report", "", f"Subject: {safe(report['subject'])}",
             f"Policy: `{report['policy']}`", "", "| ID | Severity | Finding | Remediation |",
             "| --- | --- | --- | --- |"]
    for f in report["findings"]:
        lines.append(f"| {f['id']} | {f['severity']} | {safe(f['message'])} | {safe(f['remediation'])} |")
    if not report["findings"]:
        lines.append("| — | — | No baseline findings | — |")
    lines.extend(["", f"Limit: {safe(report['limitations'])}", ""])
    return "\n".join(lines)
