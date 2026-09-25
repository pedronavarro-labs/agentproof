"""Host-owned wiring for live introspection on every MCP tool operation."""

from __future__ import annotations

from typing import Callable, Mapping

from .approval import ApprovalStore
from .auth import OAuthIntrospector
from .runtime import RuntimeGuard, Tool


class VerifiedGuardProvider:
    def __init__(self, manifest: dict, tools: Mapping[str, Tool], token: str,
                 introspector: OAuthIntrospector, approvals: ApprovalStore,
                 audit: Callable[[dict[str, str]], None]):
        self.manifest, self.tools, self.token = manifest, tools, token
        self.introspector, self.approvals, self.audit = introspector, approvals, audit

    def __call__(self) -> RuntimeGuard:
        principal = self.introspector.verify(self.token)
        return RuntimeGuard(self.manifest, self.tools, set(principal.scopes),
                            audit=self.audit, principal=principal, approvals=self.approvals)
