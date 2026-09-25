import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from agentproof.approval import ApprovalStore
from agentproof.auth import AuthenticationError
from agentproof.core import load_document
from agentproof.google_identity import GoogleAgentIdentity, GoogleGuardProvider, GoogleReviewerLogin
from agentproof.runtime import Denied, Tool


class GoogleIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / "client.json"
        self.config.write_text(json.dumps({"installed": {
            "client_id": "desktop.apps.googleusercontent.com",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"}}))

    def test_google_agent_checks_signed_token_claims_and_configured_grants(self):
        calls = []
        claims = {"iss": "https://accounts.google.com", "aud": "agentproof-agent",
                  "sub": "service-123", "exp": 1200}
        def supplier(audience):
            calls.append(audience)
            return "signed-token"
        def verify(token, audience):
            self.assertEqual((token, audience), ("signed-token", "agentproof-agent"))
            return claims
        identity = GoogleAgentIdentity("agentproof-agent", "service-123",
                                       {"tickets:read"}, token_supplier=supplier,
                                       verifier=verify, clock=lambda: 1000)
        self.assertEqual(identity.verify().subject, "google:service-123")
        self.assertEqual(identity.verify().scopes, {"tickets:read"})
        self.assertEqual(len(calls), 2)
        for key, value in (("iss", "https://attacker.invalid"), ("aud", "other"),
                           ("sub", "attacker"), ("exp", 1000)):
            with self.subTest(key=key):
                changed = {**claims, key: value}
                rejected = GoogleAgentIdentity("agentproof-agent", "service-123",
                    {"tickets:read"}, token_supplier=supplier,
                    verifier=lambda _token, _audience: changed, clock=lambda: 1000)
                with self.assertRaises(AuthenticationError):
                    rejected.verify()

    def reviewer(self, change=None, allowed_sub="human-456"):
        flow_calls = []
        def factory(_config, **kwargs):
            self.assertEqual(kwargs["scopes"], ["openid", "email"])
            self.assertTrue(kwargs["autogenerate_code_verifier"])
            class Flow:
                def run_local_server(self, **options):
                    flow_calls.append(options)
                    return SimpleNamespace(id_token="signed-reviewer-token")
            return Flow()
        def verify(token, audience):
            self.assertEqual((token, audience),
                             ("signed-reviewer-token", "desktop.apps.googleusercontent.com"))
            claims = {"iss": "https://accounts.google.com",
                      "aud": "desktop.apps.googleusercontent.com", "sub": "human-456",
                      "exp": 1500, "email_verified": True, "auth_time": 1000,
                      "nonce": flow_calls[-1]["nonce"]}
            return {**claims, **(change or {})}
        return GoogleReviewerLogin(self.config, allowed_sub, flow_factory=factory,
                                   verifier=verify, clock=lambda: 1000), flow_calls

    def test_review_uses_fresh_google_signin_nonce_pkce_and_allowlist(self):
        login, calls = self.reviewer()
        principal = login.login()
        self.assertEqual(principal.subject, "google:human-456")
        self.assertEqual(principal.scopes, {"agentproof:approve"})
        self.assertEqual(principal.expires_at, 1300)
        self.assertEqual(calls[0]["host"], "127.0.0.1")
        self.assertEqual(calls[0]["port"], 0)
        self.assertEqual(calls[0]["max_age"], 0)
        self.assertEqual(calls[0]["access_type"], "online")
        self.assertEqual(calls[0]["timeout_seconds"], 120)

    def test_reviewer_wrong_account_replay_unverified_email_and_stale_login_fail(self):
        for change, allowed in (({"sub": "other"}, "human-456"),
                                ({"nonce": "replayed"}, "human-456"),
                                ({"email_verified": False}, "human-456"),
                                ({"auth_time": 800}, "human-456"),
                                ({"exp": 1000}, "human-456")):
            with self.subTest(change=change):
                login, _ = self.reviewer(change, allowed)
                with self.assertRaises(AuthenticationError):
                    login.login()

    def test_google_agent_and_reviewer_complete_one_write(self):
        manifest = load_document(Path(__file__).resolve().parents[1]
                                 / "examples/runtime-demo/read-only-agent.yaml")
        manifest["identity"]["principal"] = "google:service-123"
        manifest["access"]["delegatedScopes"].append("tickets:write")
        manifest["capabilities"].append({"id": "tickets.write", "source": "declared",
            "tool": "tickets.update", "operation": "write", "risk": "high",
            "scopes": ["tickets:write"], "approval": "required", "rollback": "Restore"})
        state = {"status": "open"}
        identity = GoogleAgentIdentity("agentproof-agent", "service-123",
            {"tickets:read", "tickets:write"}, token_supplier=lambda _: "signed",
            verifier=lambda *_: {"iss": "https://accounts.google.com", "aud": "agentproof-agent",
                                 "sub": "service-123", "exp": 1200}, clock=lambda: 1000)
        store = ApprovalStore(Path(self.tmp.name) / "google-approval.db", clock=lambda: 1000)
        self.addCleanup(store.close)
        guard = GoogleGuardProvider(manifest, {"tickets.update": Tool(
            "write", lambda args: state.update(status=args["status"]))},
            identity, store, lambda _: None)()
        self.assertIn("tickets.update", guard.listed_tools())
        with self.assertRaises(Denied) as raised:
            guard.call("tickets.update", {"status": "closed"})
        request_id = str(raised.exception).split("approval_required:")[1]
        reviewer, _ = self.reviewer()
        store.review(request_id, reviewer.login(), True)
        guard.call("tickets.update", {"status": "closed"})
        self.assertEqual(state["status"], "closed")
        with self.assertRaises(Denied):
            guard.call("tickets.update", {"status": "closed"})


if __name__ == "__main__":
    unittest.main()
