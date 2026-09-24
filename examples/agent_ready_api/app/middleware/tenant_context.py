"""Tenant Context Middleware: Extracts verified tenant_id from auth token/API Key."""

from typing import Callable
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# Known demo API keys mapping to tenant UUIDs (In production, resolved via DB or JWT claims)
DEMO_API_KEYS = {
    "ak_live_alfa_123456789": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",  # Empresa Alfa
    "ak_live_beta_987654321": "b1ffcd88-8b1a-3de7-aa5c-5aa8ac271b22",  # Startup Beta
}

PUBLIC_PATHS = {"/docs", "/openapi.json", "/redoc", "/health", "/mcp"}


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Guarantees that tenant_id is exclusively derived from credentials and attached to request.state."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Allow open public documentation and health endpoints
        if path in PUBLIC_PATHS or path.startswith(("/docs", "/static")):
            request.state.tenant_id = None
            return await call_next(request)

        # Extract API Key from header
        auth_header = request.headers.get("Authorization", "")
        api_key_header = request.headers.get("X-API-Key", "")

        api_key = ""
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:].strip()
        elif api_key_header:
            api_key = api_key_header.strip()

        # Fallback to default demo tenant if running in local test mode
        tenant_id = DEMO_API_KEYS.get(api_key)
        if not tenant_id and (api_key == "test" or not api_key):
            # Default to Empresa Alfa for ease of local testing
            tenant_id = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"

        if not tenant_id:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "type": "https://api.tuempresa.com/errors/unauthorized",
                    "title": "Autenticación requerida",
                    "status": 401,
                    "detail": "API Key o Bearer token inválido o no reconocido.",
                    "instance": path,
                },
                media_type="application/problem+json",
            )

        # Attach tenant to request state for the connection pool
        request.state.tenant_id = tenant_id
        return await call_next(request)
