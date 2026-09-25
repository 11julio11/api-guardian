"""Integration tests for the real Model Context Protocol (MCP) server over stdio."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


class TestMCPServerIntegration(unittest.TestCase):
    """Verifies that the MCP server communicates authentically via JSON-RPC 2.0 over stdio."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.server_script = cls.repo_root / "examples" / "agent_ready_api" / "app" / "mcp_server.py"

    def _send_and_receive(self, proc: subprocess.Popen, req: dict) -> dict:
        """Sends a single JSON-RPC message line and reads the response line from stdout."""
        msg_str = json.dumps(req) + "\n"
        proc.stdin.write(msg_str)
        proc.stdin.flush()

        response_line = proc.stdout.readline()
        self.assertTrue(bool(response_line), "Expected a response line from MCP server on stdout")
        return json.loads(response_line)

    def test_full_mcp_lifecycle_over_stdio(self):
        """Runs the MCP server in a live subprocess and performs end-to-end JSON-RPC exchange."""
        env = os.environ.copy()
        env["CURRENT_TENANT_ID"] = "tenant-audit-corp-123"
        env["PYTHONUNBUFFERED"] = "1"

        proc = subprocess.Popen(
            [sys.executable, str(self.server_script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(self.repo_root),
            env=env,
        )

        try:
            # 1. Test 'initialize'
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-agent", "version": "1.0.0"},
                },
            }
            init_resp = self._send_and_receive(proc, init_req)
            self.assertEqual(init_resp.get("id"), 1)
            self.assertIn("result", init_resp)
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "Enterprise Agent-Ready API")
            self.assertTrue(init_resp["result"]["capabilities"]["tools"])

            # 2. Test 'notifications/initialized'
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            # 3. Test 'ping'
            ping_resp = self._send_and_receive(proc, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
            self.assertEqual(ping_resp.get("id"), 2)
            self.assertEqual(ping_resp.get("result"), {})

            # 4. Test 'tools/list'
            tools_resp = self._send_and_receive(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            self.assertIn("result", tools_resp)
            tools = tools_resp["result"]["tools"]
            tool_names = {t["name"] for t in tools}
            self.assertIn("create_document", tool_names)
            self.assertIn("list_documents", tool_names)
            self.assertIn("process_payment_transaction", tool_names)

            # Check schema generation for create_document
            create_tool = next(t for t in tools if t["name"] == "create_document")
            self.assertIn("title", create_tool["inputSchema"]["properties"])
            self.assertIn("content", create_tool["inputSchema"]["properties"])
            self.assertEqual(create_tool["inputSchema"]["required"], ["title", "content"])

            # 5. Test 'tools/call' for create_document
            call_create_req = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "create_document",
                    "arguments": {
                        "title": "Arquitectura de Seguridad 2026",
                        "content": "Lineamientos para integración de agentes LLM en APIs corporativas.",
                    },
                },
            }
            call_create_resp = self._send_and_receive(proc, call_create_req)
            self.assertFalse(call_create_resp["result"]["isError"])
            content_text = call_create_resp["result"]["content"][0]["text"]
            self.assertIn("Arquitectura de Seguridad 2026", content_text)

            # 6. Test 'tools/call' for list_documents
            call_list_req = {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "list_documents", "arguments": {}},
            }
            call_list_resp = self._send_and_receive(proc, call_list_req)
            self.assertFalse(call_list_resp["result"]["isError"])
            list_text = call_list_resp["result"]["content"][0]["text"]
            self.assertIn("Arquitectura de Seguridad 2026", list_text)

            # 7. Test 'tools/call' for process_payment_transaction with Idempotency
            call_pay_req = {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "process_payment_transaction",
                    "arguments": {
                        "amount": 2500.50,
                        "currency": "USD",
                        "idempotency_key": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                    },
                },
            }
            call_pay_resp = self._send_and_receive(proc, call_pay_req)
            self.assertFalse(call_pay_resp["result"]["isError"])
            pay_text = call_pay_resp["result"]["content"][0]["text"]
            self.assertIn("completed", pay_text)
            self.assertIn("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", pay_text)

            # 8. Test error handling for non-existent tool
            call_unknown_req = {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "unauthorized_delete_all", "arguments": {}},
            }
            call_unknown_resp = self._send_and_receive(proc, call_unknown_req)
            self.assertIn("error", call_unknown_resp)
            self.assertEqual(call_unknown_resp["error"]["code"], -32601)

        finally:
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()
            proc.terminate()
            proc.wait(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
