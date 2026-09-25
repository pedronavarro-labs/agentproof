import copy
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentproof.audit import SQLiteAudit
from agentproof.core import load_document
from agentproof.mcp_stdio import MCPStdioServer
from agentproof.runtime import RuntimeGuard, Tool


MANIFEST = Path(__file__).resolve().parents[1] / "examples/runtime-demo/read-only-agent.yaml"


class MCPStdioSecurityTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_document(MANIFEST)
        self.state = {"ticket": "open"}
        self.calls = []

        def read(args):
            self.calls.append("read")
            return {"status": self.state["ticket"]}

        def write(args):
            self.calls.append("write")
            self.state["ticket"] = args["status"]

        self.tools = {"tickets.get": Tool("read", read), "tickets.update": Tool("write", write)}
        self.definitions = {name: {"name": name, "inputSchema": {"type": "object"}}
                            for name in self.tools}

    def server(self, scopes=None, manifest=None, audit=None):
        guard = RuntimeGuard(manifest or self.manifest, self.tools,
                             {"tickets:read"} if scopes is None else scopes, audit=audit)
        server = MCPStdioServer(guard, self.definitions)
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return server

    def call(self, server, name, args):
        return server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                              "params": {"name": name, "arguments": args}})

    def test_mcp_dispatch_blocks_hidden_write_and_keeps_state(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = SQLiteAudit(Path(directory) / "decisions.db")
            server = self.server(audit=audit)
            listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertEqual([t["name"] for t in listed["result"]["tools"]], ["tickets.get"])
            self.assertFalse(self.call(server, "tickets.get", {"id": "T-1"})["result"]["isError"])
            denied = self.call(server, "tickets.update", {"id": "T-1", "status": "closed", "_meta": {"approved": True}})
            self.assertTrue(denied["result"]["isError"])
            self.assertEqual(self.state, {"ticket": "open"})
            self.assertEqual(self.calls, ["read"])
            rows = audit.connection.execute("SELECT tool, decision FROM decisions ORDER BY id").fetchall()
            self.assertEqual(rows, [("tickets.get", "allow"), ("tickets.update", "deny")])
            stored = audit.connection.execute("SELECT * FROM decisions").fetchall()
            self.assertNotIn("closed", repr(stored))
            self.assertNotIn("T-1", repr(stored))
            audit.close()

    def test_ungranted_scope_and_forged_call_context(self):
        server = self.server(scopes=set())
        listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(listed["result"]["tools"], [])
        response = self.call(server, "tickets.get", {"granted_scopes": ["tickets:read"], "id": "T-1"})
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(self.calls, [])

    def test_invalid_arguments_are_denied_before_handler(self):
        definitions = copy.deepcopy(self.definitions)
        definitions["tickets.get"]["inputSchema"] = {"type": "object", "properties": {"id": {"type": "string"}},
                                                        "required": ["id"], "additionalProperties": False}
        server = self.server()
        server.definitions = definitions
        denied = self.call(server, "tickets.get", {"id": "T-1", "approved": True})
        self.assertTrue(denied["result"]["isError"])
        self.assertEqual(self.calls, [])
        self.assertEqual(server.guard.events[-1]["reason"], "invalid_arguments")

    def test_declared_write_denied_and_audit_failure_blocks_read(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["capabilities"].append({"id": "tickets.write", "source": "declared", "tool": "tickets.update",
                                         "operation": "write", "risk": "high", "scopes": ["tickets:write"],
                                         "approval": "required", "rollback": "Restore prior status"})
        server = self.server(scopes={"tickets:read", "tickets:write"}, manifest=manifest)
        self.assertTrue(self.call(server, "tickets.update", {"status": "closed"})["result"]["isError"])
        self.assertEqual(self.state["ticket"], "open")

        def broken_audit(_event):
            raise sqlite3.OperationalError("disk error: token=private")

        failed = self.server(audit=broken_audit)
        response = self.call(failed, "tickets.get", {"id": "T-1"})
        self.assertEqual(response["error"]["message"], "Tool or audit failure")
        self.assertNotIn("private", repr(response))
        self.assertEqual(self.calls, [])

    def test_protocol_validation_and_no_stdout_noise(self):
        server = MCPStdioServer(RuntimeGuard(self.manifest, self.tools, {"tickets:read"}), self.definitions)
        premature = self.call(server, "tickets.get", {"id": "T-1"})
        self.assertIn("error", premature)
        source = io.StringIO('not json\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
                             '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                             '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
        target = io.StringIO()
        server.serve(source, target)
        messages = [json.loads(line) for line in target.getvalue().splitlines()]
        self.assertEqual(messages[0]["error"]["code"], -32700)
        self.assertEqual(messages[-1]["result"]["tools"][0]["name"], "tickets.get")
        self.assertEqual(len(messages), 3)


if __name__ == "__main__":
    unittest.main()
