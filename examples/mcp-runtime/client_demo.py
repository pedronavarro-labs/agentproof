"""Exercise the real stdio JSON-RPC boundary with a subprocess."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    with tempfile.TemporaryDirectory() as directory:
        env = dict(os.environ, AGENTPROOF_AUDIT_DB=str(Path(directory) / "decisions.sqlite3"))
        with subprocess.Popen([sys.executable, str(Path(__file__).with_name("server.py"))],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=env) as process:
            def request(method, params=None):
                request.number += 1
                message = {"jsonrpc": "2.0", "id": request.number, "method": method}
                if params is not None:
                    message["params"] = params
                process.stdin.write(json.dumps(message) + "\n")
                process.stdin.flush()
                return json.loads(process.stdout.readline())

            request.number = 0
            print("Initialize:", request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                                       "clientInfo": {"name": "synthetic-demo", "version": "1"}})["result"]["protocolVersion"])
            process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            process.stdin.flush()
            print("Tools:", [tool["name"] for tool in request("tools/list")["result"]["tools"]])
            print("Read:", request("tools/call", {"name": "tickets.get", "arguments": {"id": "T-1"}})["result"])
            print("Write:", request("tools/call", {"name": "tickets.update", "arguments": {"id": "T-1", "status": "closed"}}))
            print("Read again:", request("tools/call", {"name": "tickets.get", "arguments": {"id": "T-1"}})["result"])
            process.stdin.close()
            process.wait(timeout=5)
            if process.returncode:
                raise RuntimeError(process.stderr.read())
        print("Local decision journal:", Path(env["AGENTPROOF_AUDIT_DB"]).name)


if __name__ == "__main__":
    main()
