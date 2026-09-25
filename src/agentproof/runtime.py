"""Experimental in-process MCP tool gate for a trusted host application.

The host must route every tool invocation through this object. It does not
intercept network traffic, authenticate callers or attest the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

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

    def __init__(self, manifest: dict, tools: Mapping[str, Tool], granted_scopes: set[str]):
        validate(manifest)
        self.tools = dict(tools)
        self.granted_scopes = frozenset(granted_scopes)
        self.declared_scopes = frozenset(manifest["access"]["delegatedScopes"])
        self.subject = manifest["metadata"]["name"]
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
        if binding.operation != "read":
            return self._deny(tool_name, "write_requires_trusted_approval")
        required = set(capability["scopes"])
        if not required or not required.issubset(self.granted_scopes) or not required.issubset(self.declared_scopes):
            return self._deny(tool_name, "scope_not_granted")
        self.events.append({"tool": tool_name, "decision": "allow", "reason": "declared_read_with_scope"})
        # Neither arguments nor return values are copied into the audit trail.
        return binding.handler(arguments)

    def _deny(self, tool_name: str, reason: str) -> None:
        self.events.append({"tool": tool_name, "decision": "deny", "reason": reason})
        raise Denied(f"{tool_name}: {reason}")
