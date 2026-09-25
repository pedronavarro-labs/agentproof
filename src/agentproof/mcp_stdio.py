"""Small MCP 2025-11-25 stdio server for host-owned tool handlers.

Only initialize, ping, tools/list and tools/call are implemented. This is an
experimental server, not an arbitrary upstream proxy or complete MCP SDK.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Mapping, TextIO

from jsonschema import Draft202012Validator

from .runtime import Denied, RuntimeGuard


class MCPStdioServer:
    def __init__(self, guard: RuntimeGuard, definitions: Mapping[str, dict[str, Any]],
                 *, guard_provider: Callable[[], RuntimeGuard] | None = None):
        self.guard = guard
        self.guard_provider = guard_provider
        self.definitions = dict(definitions)
        for name, definition in self.definitions.items():
            if definition.get("name") != name or not isinstance(definition.get("inputSchema"), dict):
                raise ValueError("host tool definition mismatch")
            Draft202012Validator.check_schema(definition["inputSchema"])
        self.initialized = False
        self.ready = False

    def handle(self, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return self._error(request, -32600, "Invalid Request")
        method = request.get("method")
        has_id = "id" in request
        if not isinstance(method, str) or (has_id and (isinstance(request["id"], bool)
                                              or not isinstance(request["id"], (str, int)))):
            return self._error(request, -32600, "Invalid Request")
        if not has_id:
            if method == "notifications/initialized" and self.initialized:
                self.ready = True
            return None
        if method == "initialize":
            if self.initialized or not isinstance(request.get("params"), dict):
                return self._error(request, -32602, "Invalid initialization")
            self.initialized = True
            return self._result(request, {"protocolVersion": "2025-11-25",
                                          "capabilities": {"tools": {}},
                                          "serverInfo": {"name": "agentproof-runtime-pilot", "version": "0.1.0a1"}})
        if not self.ready:
            return self._error(request, -32000, "Not initialized")
        if method == "ping":
            return self._result(request, {})
        if method in ("tools/list", "tools/call"):
            try:
                guard = self.guard_provider() if self.guard_provider else self.guard
            except Exception:
                return self._error(request, -32001, "Authorization unavailable")
        if method == "tools/list":
            if request.get("params", {}) not in ({}, None):
                return self._error(request, -32602, "Invalid params")
            tools = [self.definitions[name] for name in sorted(guard.listed_tools())
                     if name in self.definitions]
            return self._result(request, {"tools": tools})
        if method == "tools/call":
            params = request.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str) or not isinstance(params.get("arguments", {}), dict):
                return self._error(request, -32602, "Invalid params")
            name = params["name"]
            if name not in self.definitions:
                # Still record a denial in the guard; no handler can run.
                try:
                    guard.call(name, params.get("arguments", {}))
                except Denied:
                    pass
                except Exception:
                    return self._error(request, -32603, "Audit unavailable")
                return self._error(request, -32602, "Unknown tool")
            try:
                args = params.get("arguments", {})
                if not Draft202012Validator(self.definitions[name]["inputSchema"]).is_valid(args):
                    guard.reject(name, "invalid_arguments")
                value = guard.call(name, args)
            except Denied as exc:
                return self._result(request, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
            except Exception:
                # No exception details or argument values cross the protocol boundary.
                return self._error(request, -32603, "Tool or audit failure")
            return self._result(request, {"content": [{"type": "text", "text": json.dumps(value)}], "isError": False})
        return self._error(request, -32601, "Method not found")

    @staticmethod
    def _result(request: dict, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    @staticmethod
    def _error(request: Any, code: int, message: str) -> dict:
        req_id = request.get("id") if isinstance(request, dict) else None
        if isinstance(req_id, bool) or not isinstance(req_id, (str, int)):
            req_id = None
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def serve(self, source: TextIO = sys.stdin, target: TextIO = sys.stdout) -> None:
        for line in source:
            try:
                request = json.loads(line)
            except (ValueError, UnicodeError):
                response = self._error(None, -32700, "Parse error")
            else:
                response = self.handle(request)
            if response is not None:
                target.write(json.dumps(response, separators=(",", ":")) + "\n")
                target.flush()
