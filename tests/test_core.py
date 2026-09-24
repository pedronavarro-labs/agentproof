import copy
import json
import tempfile
import unittest
from pathlib import Path

from agentproof.core import ManifestError, evaluate, load_document, markdown, scan_mcp, validate

ROOT = Path(__file__).resolve().parents[1]


class AgentProofTests(unittest.TestCase):
    def setUp(self):
        self.good = load_document(ROOT / "fixtures/secure/support-agent.yaml")

    def test_all_fixtures_validate_and_report(self):
        for path in (ROOT / "fixtures").glob("*/*"):
            with self.subTest(path=path):
                manifest = load_document(path)
                validate(manifest)
                findings = evaluate(manifest)["findings"]
                self.assertEqual(bool(findings), path.parent.name == "insecure")

    def test_ten_policy_ids_are_exercised(self):
        all_ids = set()
        for path in (ROOT / "fixtures/insecure").glob("*"):
            all_ids.update(f["id"] for f in evaluate(load_document(path))["findings"])
        self.assertEqual(all_ids, {f"AP-{i:03}" for i in range(1, 11)})

    def test_scanner_never_copies_credentials_urls_or_command_arguments(self):
        manifest = scan_mcp(ROOT / "examples/mcp-server/mcp.json")
        text = json.dumps(manifest)
        self.assertNotIn("FAKE_DO_NOT_USE", text)
        self.assertNotIn("https://", text)
        self.assertNotIn("fake_server.py", text)
        self.assertEqual([p["name"] for p in manifest["protocols"]], ["sample-local", "sample-tickets"])
        self.assertIn("AP-001", [f["id"] for f in evaluate(manifest)["findings"]])

    def test_claimed_pass_without_evidence_is_not_verified(self):
        manifest = copy.deepcopy(self.good)
        manifest["controls"]["tokenAudienceBinding"] = {"source": "declared", "status": "pass"}
        self.assertIn("AP-007", [f["id"] for f in evaluate(manifest)["findings"]])

    def test_unmapped_scope_and_approval_exception(self):
        manifest = copy.deepcopy(self.good)
        manifest["access"]["delegatedScopes"].append("admin:all")
        ids = [f["id"] for f in evaluate(manifest)["findings"]]
        self.assertIn("AP-004", ids)
        manifest["capabilities"][1]["approval"] = "exception"
        self.assertIn("AP-003", [f["id"] for f in evaluate(manifest)["findings"]])

    def test_unknown_properties_and_duplicate_keys_are_rejected(self):
        manifest = copy.deepcopy(self.good)
        manifest["controls"]["humanApproval"]["secret"] = "should-not-be-here"
        with self.assertRaises(ManifestError):
            validate(manifest)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text("name: one\nname: two\n")
            with self.assertRaises(ManifestError):
                load_document(path)
            path.write_text("name: &alias original\ncopy: *alias\n")
            with self.assertRaises(ManifestError):
                load_document(path)

    def test_markdown_escapes_untrusted_cell_content(self):
        manifest = copy.deepcopy(self.good)
        manifest["capabilities"][1]["id"] = "tickets|<img>"
        manifest["capabilities"][1].pop("rollback")
        rendered = markdown(evaluate(manifest))
        self.assertNotIn("|<img>", rendered)
        self.assertIn("tickets\\|&lt;img&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
