import copy
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentproof.approval import ApprovalStore
from agentproof.auth import AuthenticationError, OAuthIntrospector, Principal
from agentproof.core import load_document
from agentproof.mcp_stdio import MCPStdioServer
from agentproof.runtime import Denied, RuntimeGuard, Tool
from agentproof.verified import VerifiedGuardProvider


MANIFEST = Path(__file__).resolve().parents[1] / "examples/runtime-demo/read-only-agent.yaml"


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, limit):
        return self.body[:limit]


class OAuthTests(unittest.TestCase):
    def verifier(self, claims, captured=None):
        def opener(request, timeout):
            if captured is not None:
                captured.append((request.full_url, request.data, request.headers))
            return FakeResponse(json.dumps(claims).encode())
        return OAuthIntrospector("https://idp.example/introspect", "client", "secret",
                                 "https://idp.example/", "agentproof", opener=opener, clock=lambda: 1000)

    def test_requires_active_matching_issuer_audience_expiry_and_subject(self):
        good = {"active": True, "iss": "https://idp.example/", "aud": ["agentproof"],
                "sub": "agent-1", "scope": "tickets:read tickets:write", "exp": 1100}
        captured = []
        principal = self.verifier(good, captured).verify("opaque-secret")
        self.assertEqual(principal.scopes, {"tickets:read", "tickets:write"})
        self.assertIn(b"opaque-secret", captured[0][1])
        self.assertEqual(captured[0][0], "https://idp.example/introspect")
        for change in ({"active": False}, {"iss": "https://evil.example/"},
                       {"aud": "elsewhere"}, {"exp": 1000}, {"sub": ""},
                       {"scope": ["tickets:read"]}):
            with self.subTest(change=change), self.assertRaises(AuthenticationError):
                self.verifier({**good, **change}).verify("opaque-secret")

    def test_refuses_http_and_provider_outage(self):
        with self.assertRaises(ValueError):
            OAuthIntrospector("http://idp.example", "x", "y", "issuer", "aud")
        def outage(*_args, **_kwargs):
            raise OSError("private endpoint detail")
        verifier = OAuthIntrospector("https://idp.example/introspect", "x", "y", "issuer", "aud", opener=outage)
        with self.assertRaises(AuthenticationError) as raised:
            verifier.verify("token")
        self.assertNotIn("private", str(raised.exception))


class VerifiedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.approvals = ApprovalStore(Path(self.tmp.name) / "approvals.db", clock=lambda: 1000)
        self.addCleanup(self.approvals.close)
        self.manifest = copy.deepcopy(load_document(MANIFEST))
        self.manifest["identity"]["principal"] = "agent-1"
        self.manifest["access"]["delegatedScopes"].append("tickets:write")
        self.manifest["capabilities"].append({"id": "tickets.write", "source": "declared",
            "tool": "tickets.update", "operation": "write", "risk": "high",
            "scopes": ["tickets:write"], "approval": "required", "rollback": "Restore"})
        self.state = {"status": "open"}
        self.tools = {"tickets.get": Tool("read", lambda _: self.state.copy()),
                      "tickets.update": Tool("write", lambda args: self.state.update(status=args["status"]))}
        self.definitions = {name: {"name": name, "inputSchema": {"type": "object"}}
                            for name in self.tools}
        self.agent = Principal("agent-1", frozenset({"tickets:read", "tickets:write"}), 1200)
        self.reviewer = Principal("human-1", frozenset({"agentproof:approve"}), 1200)
        self.audit = []

    def guard(self, principal=None, manifest=None, audit=None):
        p = principal or self.agent
        return RuntimeGuard(manifest or self.manifest, self.tools, set(p.scopes),
                            audit=audit if audit is not None else self.audit.append,
                            principal=p, approvals=self.approvals)

    def test_exact_one_time_approval_and_replay_denial(self):
        guard = self.guard()
        args = {"id": "T-1", "status": "closed"}
        with self.assertRaises(Denied) as raised:
            guard.call("tickets.update", args)
        request_id = str(raised.exception).split("approval_required:")[1]
        self.assertEqual(self.approvals.get(request_id)["arguments"],
                         '{"id":"T-1","status":"closed"}')
        self.assertEqual(self.state["status"], "open")
        self.approvals.review(request_id, self.reviewer, True)
        with self.assertRaises(Denied):
            guard.call("tickets.update", {**args, "status": "other"})
        guard.call("tickets.update", args)
        self.assertEqual(self.state["status"], "closed")
        with self.assertRaises(Denied):
            guard.call("tickets.update", args)
        self.assertEqual(self.approvals.get(request_id)["state"], "consumed")
        self.assertEqual([e["decision"] for e in self.audit], ["deny", "deny", "allow", "deny"])

    def test_self_approval_scope_expiry_and_policy_change(self):
        guard = self.guard()
        with self.assertRaises(Denied) as raised:
            guard.call("tickets.update", {"status": "closed"})
        request_id = str(raised.exception).split("approval_required:")[1]
        for reviewer in (self.agent, Principal("human-1", frozenset(), 1200),
                         Principal("human-1", frozenset({"agentproof:approve"}), 1000)):
            with self.assertRaises(PermissionError):
                self.approvals.review(request_id, reviewer, True)
        self.approvals.review(request_id, self.reviewer, True)
        changed = copy.deepcopy(self.manifest)
        changed["metadata"]["name"] = "changed-policy"
        with self.assertRaises(Denied):
            self.guard(manifest=changed).call("tickets.update", {"status": "closed"})
        self.assertEqual(self.approvals.get(request_id)["state"], "approved")

    def test_mcp_reintrospects_and_refuses_forged_grants(self):
        class Source:
            calls = 0
            def verify(inner, token):
                inner.calls += 1
                if token != "host-credential" or inner.calls == 3:
                    raise AuthenticationError("revoked")
                return self.agent
        source = Source()
        provider = VerifiedGuardProvider(self.manifest, self.tools, "host-credential", source,
                                         self.approvals, self.audit.append)
        server = MCPStdioServer(RuntimeGuard(self.manifest, self.tools, set()),
                                self.definitions, guard_provider=provider)
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        def message(method, params=None):
            return server.handle({"jsonrpc": "2.0", "id": 2, "method": method, "params": params or {}})
        self.assertEqual([t["name"] for t in message("tools/list")["result"]["tools"]],
                         ["tickets.get", "tickets.update"])
        denied = message("tools/call", {"name": "tickets.update", "arguments": {
            "status": "closed", "approved": True, "granted_scopes": ["tickets:write"]}})
        self.assertTrue(denied["result"]["isError"])
        self.assertEqual(message("tools/list")["error"]["message"], "Authorization unavailable")
        self.assertEqual(self.state["status"], "open")

    def test_identity_mismatch_and_audit_failure_deny_execution(self):
        with self.assertRaises(Denied):
            self.guard(principal=Principal("other", self.agent.scopes, 1200))
        def broken(_):
            raise sqlite3.OperationalError("unavailable")
        guard = self.guard(audit=broken)
        with self.assertRaises(sqlite3.OperationalError):
            guard.call("tickets.get", {})
        self.assertEqual(self.state["status"], "open")

    def test_separate_reviewer_process_and_expired_request(self):
        with self.assertRaises(Denied) as raised:
            self.guard().call("tickets.update", {"status": "closed"})
        request_id = str(raised.exception).split("approval_required:")[1]
        second = ApprovalStore(Path(self.tmp.name) / "approvals.db", clock=lambda: 1000)
        try:
            second.review(request_id, self.reviewer, True)
            self.guard().call("tickets.update", {"status": "closed"})
            self.assertEqual(second.get(request_id)["state"], "consumed")
        finally:
            second.close()

        expired = ApprovalStore(Path(self.tmp.name) / "expired.db", clock=lambda: 1000)
        try:
            allowed, request_id = expired.request_or_consume("agent-1", "tickets.update",
                                                              {"status": "closed"}, "policy", 1001)
            self.assertFalse(allowed)
            expired.clock = lambda: 1002
            with self.assertRaises(PermissionError):
                expired.review(request_id, self.reviewer, True)
            allowed, fresh_id = expired.request_or_consume("agent-1", "tickets.update",
                                                            {"status": "closed"}, "policy", 1200)
            self.assertFalse(allowed)
            self.assertNotEqual(fresh_id, request_id)
        finally:
            expired.close()

    def test_private_database_and_second_consumer_cannot_reuse_approval(self):
        path = Path(self.tmp.name) / "approvals.db"
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with self.assertRaises(Denied) as raised:
            self.guard().call("tickets.update", {"status": "closed"})
        request_id = str(raised.exception).split("approval_required:")[1]
        self.approvals.review(request_id, self.reviewer, True)
        other = ApprovalStore(path, clock=lambda: 1000)
        try:
            first = self.approvals.request_or_consume("agent-1", "tickets.update",
                {"status": "closed"}, self.guard().policy_digest, 1200)
            second = other.request_or_consume("agent-1", "tickets.update",
                {"status": "closed"}, self.guard().policy_digest, 1200)
            self.assertTrue(first[0])
            self.assertFalse(second[0])
            self.assertNotEqual(first[1], second[1])
        finally:
            other.close()
        unsafe = Path(self.tmp.name) / "unsafe.db"
        unsafe.touch(mode=0o644)
        with self.assertRaises(PermissionError):
            ApprovalStore(unsafe)


if __name__ == "__main__":
    unittest.main()
