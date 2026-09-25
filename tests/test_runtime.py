import copy
import unittest
from pathlib import Path

from agentproof.core import ManifestError, load_document
from agentproof.runtime import Denied, RuntimeGuard, Tool


DEMO = Path(__file__).resolve().parents[1] / "examples/runtime-demo/read-only-agent.yaml"


class RuntimeGuardTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_document(DEMO)
        self.calls = []

        def read(args):
            self.calls.append(("read", args))
            return {"status": "open"}

        def write(args):
            self.calls.append(("write", args))
            return {"status": "closed"}

        self.tools = {"tickets.get": Tool("read", read), "tickets.update": Tool("write", write)}

    def guard(self, scopes=None):
        return RuntimeGuard(self.manifest, self.tools, {"tickets:read"} if scopes is None else scopes)

    def test_read_allowed_and_write_denied_before_side_effect(self):
        guard = self.guard()
        self.assertEqual(guard.call("tickets.get", {"id": "T-1"}), {"status": "open"})
        with self.assertRaisesRegex(Denied, "undeclared_tool"):
            guard.call("tickets.update", {"id": "T-1", "status": "closed"})
        self.assertEqual(self.calls, [("read", {"id": "T-1"})])
        self.assertEqual([event["decision"] for event in guard.events], ["allow", "deny"])
        self.assertNotIn("T-1", str(guard.events))

    def test_missing_scope_or_mismatched_binding_denied(self):
        with self.assertRaisesRegex(Denied, "scope_not_granted"):
            self.guard(set()).call("tickets.get", {})
        self.assertEqual(self.calls, [])
        guard = RuntimeGuard(self.manifest, {"tickets.get": Tool("write", self.tools["tickets.get"].handler)}, {"tickets:read"})
        with self.assertRaisesRegex(Denied, "missing_or_mismatched_binding"):
            guard.call("tickets.get", {})
        manifest = copy.deepcopy(self.manifest)
        manifest["access"]["delegatedScopes"] = []
        with self.assertRaisesRegex(Denied, "scope_not_granted"):
            RuntimeGuard(manifest, self.tools, {"tickets:read"}).call("tickets.get", {})

    def test_declared_write_still_requires_trusted_approval(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["capabilities"].append({"id": "tickets.write", "source": "declared", "tool": "tickets.update",
                                         "operation": "write", "risk": "high", "scopes": ["tickets:write"],
                                         "approval": "required", "rollback": "Restore prior status"})
        guard = RuntimeGuard(manifest, self.tools, {"tickets:read", "tickets:write"})
        with self.assertRaisesRegex(Denied, "write_requires_trusted_approval"):
            guard.call("tickets.update", {"status": "closed"})
        self.assertEqual(self.calls, [])

    def test_ambiguous_mapping_fails_closed(self):
        manifest = copy.deepcopy(self.manifest)
        another = copy.deepcopy(manifest["capabilities"][0])
        another["id"] = "other.read"
        manifest["capabilities"].append(another)
        with self.assertRaises(ManifestError):
            RuntimeGuard(manifest, self.tools, {"tickets:read"})


if __name__ == "__main__":
    unittest.main()
