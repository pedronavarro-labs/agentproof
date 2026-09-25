"""Opt-in Google OIDC identities for an isolated agent and its human reviewer.

Google ID tokens identify principals; AgentProof tool scopes are host policy,
not Google API scopes or claims taken from MCP request arguments.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Callable, Mapping

from .approval import ApprovalStore
from .auth import AuthenticationError, Principal
from .runtime import RuntimeGuard, Tool


def _verify_token(token: str, audience: str) -> dict:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token

    return id_token.verify_oauth2_token(token, Request(), audience=audience)


def _claims(claims: dict, audience: str, now: float) -> tuple[str, float]:
    if not isinstance(claims, dict):
        raise AuthenticationError("invalid Google identity")
    exp = claims.get("exp")
    if (claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com")
            or claims.get("aud") != audience
            or not isinstance(claims.get("sub"), str) or not claims["sub"]
            or isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp <= now):
        raise AuthenticationError("invalid Google identity")
    return claims["sub"], exp


class GoogleAgentIdentity:
    """Mint and verify a Google Cloud service-account ID token per operation."""

    def __init__(self, audience: str, expected_sub: str, grants: set[str], *,
                 token_supplier: Callable[[str], str] | None = None,
                 verifier: Callable[[str, str], dict] = _verify_token,
                 clock: Callable[[], float] = time.time):
        if not audience or not expected_sub or not grants:
            raise ValueError("expected service identity, audience and grants required")
        self.audience, self.expected_sub = audience, expected_sub
        self.grants = frozenset(grants)
        self.token_supplier = token_supplier or self._fetch
        self.verifier, self.clock = verifier, clock

    @staticmethod
    def _fetch(audience: str) -> str:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token

        return id_token.fetch_id_token(Request(), audience)

    def verify(self) -> Principal:
        try:
            claims = self.verifier(self.token_supplier(self.audience), self.audience)
            subject, expires_at = _claims(claims, self.audience, self.clock())
        except Exception as exc:
            raise AuthenticationError("Google agent identity unavailable") from exc
        if subject != self.expected_sub:
            raise AuthenticationError("unexpected Google service identity")
        return Principal(f"google:{subject}", self.grants, expires_at)


class GoogleGuardProvider:
    def __init__(self, manifest: dict, tools: Mapping[str, Tool], identity: GoogleAgentIdentity,
                 approvals: ApprovalStore, audit: Callable[[dict[str, str]], None]):
        self.manifest, self.tools, self.identity = manifest, tools, identity
        self.approvals, self.audit = approvals, audit

    def __call__(self) -> RuntimeGuard:
        principal = self.identity.verify()
        return RuntimeGuard(self.manifest, self.tools, set(principal.scopes),
                            audit=self.audit, principal=principal, approvals=self.approvals)


class GoogleReviewerLogin:
    """Interactive desktop OAuth code+PKCE flow; never stores refresh tokens."""

    def __init__(self, client_config_file: str | Path, allowed_sub: str | None,
                 *, flow_factory: Callable | None = None,
                 verifier: Callable[[str, str], dict] = _verify_token,
                 clock: Callable[[], float] = time.time):
        config = json.loads(Path(client_config_file).read_text(encoding="utf-8"))
        installed = config.get("installed", {})
        if (not isinstance(installed, dict) or not installed.get("client_id")
                or installed.get("auth_uri") not in (
                    "https://accounts.google.com/o/oauth2/auth",
                    "https://accounts.google.com/o/oauth2/v2/auth")
                or installed.get("token_uri") != "https://oauth2.googleapis.com/token"):
            raise ValueError("expected Google OAuth Desktop client configuration")
        self.client_config, self.client_id = config, installed["client_id"]
        self.allowed_sub = allowed_sub
        self.flow_factory, self.verifier, self.clock = flow_factory, verifier, clock

    def login(self) -> Principal:
        from google_auth_oauthlib.flow import InstalledAppFlow

        factory = self.flow_factory or InstalledAppFlow.from_client_config
        nonce = secrets.token_urlsafe(32)
        flow = factory(self.client_config, scopes=["openid", "email"],
                       autogenerate_code_verifier=True)
        try:
            credentials = flow.run_local_server(
                host="127.0.0.1", port=0, timeout_seconds=120,
                authorization_prompt_message=None, access_type="online",
                prompt="select_account login", max_age=0, nonce=nonce)
            if not credentials.id_token:
                raise AuthenticationError("Google returned no ID token")
            claims = self.verifier(credentials.id_token, self.client_id)
            subject, expires_at = _claims(claims, self.client_id, self.clock())
        except Exception as exc:
            raise AuthenticationError("Google reviewer login failed") from exc
        auth_time = claims.get("auth_time")
        now = self.clock()
        if (claims.get("nonce") != nonce or claims.get("email_verified") is not True
                or isinstance(auth_time, bool) or not isinstance(auth_time, (int, float))
                or auth_time > now + 30 or now - auth_time > 120):
            raise AuthenticationError("Google reviewer freshness check failed")
        if self.allowed_sub is not None and subject != self.allowed_sub:
            raise AuthenticationError("Google account is not an approved reviewer")
        return Principal(f"google:{subject}", frozenset({"agentproof:approve"}),
                         min(expires_at, now + 300))
