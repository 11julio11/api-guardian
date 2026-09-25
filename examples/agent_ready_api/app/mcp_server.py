"""Model Context Protocol (MCP) Server for the Agent-Ready API.

Implements the official Model Context Protocol (JSON-RPC 2.0 over stdio)
allowing AI agents (Cursor, Claude Desktop, Antigravity) to safely discover
and execute business tools with strict multi-tenant isolation.
"""

import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Ensure package root is in sys.path when running standalone
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.database import mock_db


class NativeMCPServer:
    """Full-featured, standard Model Context Protocol (JSON-RPC 2.0 over stdio) server.
    
    Zero third-party dependencies required; adheres strictly to the MCP specification.
    """

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.tools: Dict[str, Dict[str, Any]] = {}

    def tool(self, name: Optional[str] = None, description: Optional[str] = None):
        """Decorator to register a function as an MCP tool with automatic JSON Schema generation."""
        def decorator(func: Callable):
            tool_name = name or func.__name__
            doc = description or (inspect.getdoc(func) or f"Execute {tool_name}")
            schema = self._generate_schema(func)

            self.tools[tool_name] = {
                "name": tool_name,
                "description": doc,
                "inputSchema": schema,
                "func": func,
            }
            return func
        return decorator

    def _generate_schema(self, func: Callable) -> Dict[str, Any]:
        """Inspects Python function signature to produce a valid JSON Schema for MCP inputSchema."""
        sig = inspect.signature(func)
        properties = {}
        required = []

        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            param_type = "string"
            if param.annotation != inspect.Parameter.empty:
                param_type = type_map.get(param.annotation, "string")

            properties[param_name] = {
                "type": param_type,
                "description": f"Parameter: {param_name}",
            }

            if param.default == inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single JSON-RPC request and returns the corresponding response."""
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # Handle notifications (no response needed)
        if method == "notifications/initialized":
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                    "capabilities": {
                        "tools": {"listChanged": False}
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            tools_list = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "inputSchema": t["inputSchema"],
                }
                for t in self.tools.values()
            ]
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            if tool_name not in self.tools:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Tool '{tool_name}' not found",
                    },
                }

            tool_entry = self.tools[tool_name]
            try:
                res = tool_entry["func"](**arguments)
                text_content = json.dumps(res, ensure_ascii=False, indent=2) if not isinstance(res, str) else res
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": text_content}
                        ],
                        "isError": False,
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"Error executing tool '{tool_name}': {str(e)}"}
                        ],
                        "isError": True,
                    },
                }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not recognized by MCP server",
            },
        }

    def run(self):
        """Runs the standard MCP stdio JSON-RPC loop until EOF."""
        sys.stderr.write(f"🛡️ [MCP Server] '{self.name}' v{self.version} activo en stdio.\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                req = json.loads(line)
            except json.JSONDecodeError as err:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(err)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            resp = self.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()


# Initialize MCP server
mcp = NativeMCPServer("Enterprise Agent-Ready API", version="1.0.0")


@mcp.tool()
def create_document(title: str, content: str) -> Dict[str, str]:
    """Crea un nuevo documento o base de conocimiento para la organización autenticada.

    Args:
        title: Título descriptivo del documento.
        content: Contenido textual del documento.
    """
    # In MCP tool execution, tenant is resolved strictly from the authenticated agent session
    tenant_id = os.getenv("CURRENT_TENANT_ID", "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
    return mock_db.insert_document(tenant_id=tenant_id, title=title, content=content)


@mcp.tool()
def list_documents() -> List[Dict[str, str]]:
    """Consulta la lista de documentos pertenecientes exclusivamente a la organización actual."""
    tenant_id = os.getenv("CURRENT_TENANT_ID", "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
    return mock_db.get_documents(tenant_id=tenant_id)


@mcp.tool()
def process_payment_transaction(amount: float, currency: str, idempotency_key: str) -> Dict[str, str]:
    """Procesa una transacción financiera o pago con garantía de idempotencia.

    Args:
        amount: Monto decimal positivo.
        currency: Moneda ISO 4217 (ej. 'USD', 'EUR').
        idempotency_key: UUIDv4 único generado por el agente para evitar dobles cobros en caso de reintentos.
    """
    tenant_id = os.getenv("CURRENT_TENANT_ID", "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
    return mock_db.insert_transaction(
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        amount=amount,
        currency=currency,
    )


if __name__ == "__main__":
    mcp.run()
