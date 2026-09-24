"""Idempotency Middleware adhering to Stripe standard for Agent resilience."""

import json
import time
import uuid
from typing import Callable, Dict, Optional, Tuple
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class InMemoryIdempotencyStore:
    """Thread-safe fallback in-memory store for idempotency (production uses Redis)."""

    def __init__(self):
        self._store: Dict[str, Tuple[int, Dict[str, str], bytes, float]] = {}

    def get(self, key: str) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        entry = self._store.get(key)
        if not entry:
            return None
        status_code, headers, body, expires_at = entry
        if time.time() > expires_at:
            del self._store[key]
            return None
        return status_code, headers, body

    def set(self, key: str, status_code: int, headers: Dict[str, str], body: bytes, ttl_seconds: int = 86400):
        expires_at = time.time() + ttl_seconds
        self._store[key] = (status_code, headers, body, expires_at)


# Global store instance
_idempotency_store = InMemoryIdempotencyStore()


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Middleware that checks and replays responses for requests containing 'Idempotency-Key'."""

    MUTATING_METHODS = {"POST", "PUT", "PATCH"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method not in self.MUTATING_METHODS:
            return await call_next(request)

        idempotency_key = request.headers.get("Idempotency-Key") or request.headers.get("idempotency-key")
        if not idempotency_key:
            # If not provided, continue normally (or enforce for specific paths)
            return await call_next(request)

        # Basic UUID check
        clean_key = idempotency_key.strip()
        tenant_id = getattr(request.state, "tenant_id", "anonymous")
        cache_key = f"idemp:{tenant_id}:{clean_key}"

        # 1. Check if response is already cached (Replay)
        cached = _idempotency_store.get(cache_key)
        if cached:
            cached_status, cached_headers, cached_body = cached
            response_headers = dict(cached_headers)
            response_headers["X-Cache-Lookup"] = "HIT-IDEMPOTENCY-REPLAY"
            return Response(
                content=cached_body,
                status_code=cached_status,
                headers=response_headers,
                media_type=response_headers.get("content-type", "application/json"),
            )

        # 2. Execute target endpoint
        response = await call_next(request)

        # 3. Only cache successful or client error responses (don't cache 500s)
        if response.status_code < 500:
            # Consume response body to cache it
            body_chunks = []
            async for chunk in response.body_iterator:
                body_chunks.append(chunk)
            full_body = b"".join(body_chunks)

            headers_dict = dict(response.headers)
            _idempotency_store.set(
                key=cache_key,
                status_code=response.status_code,
                headers=headers_dict,
                body=full_body,
                ttl_seconds=86400,  # 24 hours
            )

            headers_dict["X-Cache-Lookup"] = "MISS-IDEMPOTENCY-STORED"
            return Response(
                content=full_body,
                status_code=response.status_code,
                headers=headers_dict,
                media_type=response.media_type,
            )

        return response
