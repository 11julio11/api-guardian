"""Model Context Protocol (MCP) Server for the Agent-Ready API."""

import os
from typing import Dict, List
from app.database import mock_db

# Try to initialize FastMCP if installed
try:
    from fastmcp import FastMCP
    mcp = FastMCP("Enterprise Agent-Ready API", dependencies=["pydantic", "asyncpg"])
except ImportError:
    # Graceful fallback shim if fastmcp is not yet installed in local environment
    class FastMCPShim:
        def __init__(self, name: str, **kwargs):
            self.name = name
            self.tools = {}

        def tool(self):
            def decorator(func):
                self.tools[func.__name__] = func
                return func
            return decorator

        def run(self):
            print(f"Running MCP Server Shim: {self.name}")

    mcp = FastMCPShim("Enterprise Agent-Ready API")


@mcp.tool()
def create_document(title: str, content: str) -> Dict[str, str]:
    """Crea un nuevo documento o base de conocimiento para la organización autenticada.

    Args:
        title: Título descriptivo del documento.
        content: Contenido textual del documento.
    """
    # In MCP tool execution, tenant is resolved from the agent session
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
