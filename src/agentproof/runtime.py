"""Experimental in-process MCP tool gate for a trusted host application.

The host must route every tool invocation through this object. It does not
intercept network traffic, authenticate callers or attest the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .approval import ApprovalStore, digest
from .auth import Principal
from .core import ManifestError, validate


@dataclass(frozen=True)
class Tool:
    operation: str
    handler: Callable[[dict[str, Any]], Any]


class Denied(PermissionError):
    """The gate refused a tool invocation before calling its handler."""


class RuntimeGuard:
    """Compare real tool dispatches with a manifest and trusted host bindings.

    ``granted_scopes`` and ``tools`` come from the host, never from an agent's
    tool-call arguments. This pilot supports read operations only; writes fail
    closed until a trusted approval integration is designed.
    """

    def __init__(self, manifest: dict, tools: Mapping[str, Tool], granted_scopes: set[str], audit: Callable[[dict[str, str]], None] | None = None,
                 *, principal: Principal | None = None, approvals: ApprovalStore | None = None):
        validate(manifest)
        if principal is not None and (principal.subject != manifest["identity"].get("principal")
                                      or set(granted_scopes) != set(principal.scopes)):
            raise Denied("verified principal or scopes do not match manifest binding")
        self.tools = dict(tools)
        self.granted_scopes = frozenset(granted_scopes)
        self.declared_scopes = frozenset(manifest["access"]["delegatedScopes"])
        self.subject = manifest["metadata"]["name"]
        self.revision = manifest["metadata"]["revision"]
        self.audit = audit
        self.principal = principal
        self.approvals = approvals
        self.policy_digest = digest(manifest)
        self.events: list[dict[str, str]] = []
        self.capabilities = {}
        for capability in manifest["capabilities"]:
            tool_name = capability.get("tool")
            if not tool_name:
                continue
            if tool_name in self.capabilities:
                raise ManifestError(f"multiple capabilities map to tool {tool_name}")
            self.capabilities[tool_name] = capability

    def call(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if not isinstance(tool_name, str) or not isinstance(arguments, dict):
            raise TypeError("tool name and arguments must be a string and mapping")
        capability = self.capabilities.get(tool_name)
        binding = self.tools.get(tool_name)
        if capability is None:
            return self._deny(tool_name, "undeclared_tool")
        if binding is None or binding.operation != capability["operation"]:
            return self._deny(tool_name, "missing_or_mismatched_binding")
        if binding.operation not in ("read", "write"):
            return self._deny(tool_name, "unsupported_operation")
        if binding.operation != "read" and (self.principal is None or self.approvals is None
                                            or capability.get("approval") != "required"):
            return self._deny(tool_name, "write_requires_trusted_approval")
        required = set(capability["scopes"])
        if not required or not required.issubset(self.granted_scopes) or not required.issubset(self.declared_scopes):
            return self._deny(tool_name, "scope_not_granted")
        if binding.operation != "read":
            allowed, request_id = self.approvals.request_or_consume(
                self.principal.subject, tool_name, arguments, self.policy_digest,
                self.principal.expires_at)
            if not allowed:
                return self._deny(tool_name, f"approval_required:{request_id}")
            self._record(tool_name, "allow", "approved_once")
        else:
            self._record(tool_name, "allow", "declared_read_with_scope")
        # Neither arguments nor return values are copied into the audit trail.
        return binding.handler(arguments)

    def _deny(self, tool_name: str, reason: str) -> None:
        self._record(tool_name, "deny", reason)
        raise Denied(f"{tool_name}: {reason}")

    def reject(self, tool_name: str, reason: str) -> None:
        """Record a transport-level denial before a handler is considered."""
        self._deny(tool_name, reason)

    def _record(self, tool_name: str, decision: str, reason: str) -> None:
        event = {"subject": self.subject, "revision": self.revision,
                 "tool": tool_name, "decision": decision, "reason": reason}
        # A configured durable audit must succeed before any handler executes.
        if self.audit is not None:
            self.audit(event)
        self.events.append(event)

    def listed_reads(self) -> set[str]:
        """Expose only tools that this instance could dispatch as reads."""
        allowed = set()
        for name, cap in self.capabilities.items():
            binding = self.tools.get(name)
            required = set(cap["scopes"])
            if (binding is not None and binding.operation == cap["operation"] == "read"
                    and required and required <= self.granted_scopes
                    and required <= self.declared_scopes):
                allowed.add(name)
        return allowed

    def listed_tools(self) -> set[str]:
        """Advertise writes only when an authenticated approval path exists."""
        allowed = self.listed_reads()
        if self.principal is None or self.approvals is None:
            return allowed
        for name, cap in self.capabilities.items():
            binding = self.tools.get(name)
            required = set(cap["scopes"])
            if (binding is not None and binding.operation == cap["operation"] == "write"
                    and cap.get("approval") == "required" and required
                    and required <= self.granted_scopes and required <= self.declared_scopes):
                allowed.add(name)
        return allowed
