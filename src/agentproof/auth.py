"""Fail-closed OAuth token introspection for a host-controlled MCP credential.

The access token is never accepted from MCP JSON-RPC parameters. An RFC 7662
endpoint supplies the identity and grants; the caller does not parse JWT claims.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class AuthenticationError(PermissionError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    expires_at: float


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise AuthenticationError("introspection redirect refused")


class OAuthIntrospector:
    def __init__(self, endpoint: str, client_id: str, client_secret: str,
                 issuer: str, audience: str, *, opener: Callable | None = None,
                 clock: Callable[[], float] = time.time):
        parts = urlsplit(endpoint)
        if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                or parts.fragment or not all((client_id, client_secret, issuer, audience))):
            raise ValueError("HTTPS endpoint and explicit client, issuer, audience required")
        self.endpoint, self.issuer, self.audience = endpoint, issuer, audience
        self.basic = base64.b64encode(
            f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}".encode()).decode()
        self.opener = opener or build_opener(_NoRedirect()).open
        self.clock = clock

    def verify(self, token: str) -> Principal:
        if not isinstance(token, str) or not token or len(token) > 8192:
            raise AuthenticationError("invalid credential")
        request = Request(self.endpoint, data=urlencode({"token": token}).encode(), method="POST",
                          headers={"Authorization": f"Basic {self.basic}",
                                   "Content-Type": "application/x-www-form-urlencoded",
                                   "Accept": "application/json"})
        try:
            with self.opener(request, timeout=5) as response:
                if response.status != 200:
                    raise AuthenticationError("introspection failed")
                raw = response.read(65537)
            if len(raw) > 65536:
                raise AuthenticationError("introspection response too large")
            claims = json.loads(raw)
        except (AuthenticationError, ValueError, OSError) as exc:
            raise AuthenticationError("identity unavailable") from exc
        if not isinstance(claims, dict) or claims.get("active") is not True:
            raise AuthenticationError("inactive credential")
        aud = claims.get("aud")
        if (claims.get("iss") != self.issuer or
                self.audience not in ([aud] if isinstance(aud, str) else aud if isinstance(aud, list) else [])
                or not isinstance(claims.get("sub"), str) or not claims["sub"]
                or isinstance(claims.get("exp"), bool)
                or not isinstance(claims.get("exp"), (int, float))
                or claims["exp"] <= self.clock()
                or not isinstance(claims.get("scope"), str)):
            raise AuthenticationError("unverified identity or grants")
        return Principal(claims["sub"], frozenset(claims["scope"].split()), claims["exp"])
