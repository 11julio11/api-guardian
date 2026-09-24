"""FastAPI Reference Application: Agent-Ready, Multi-Tenant with RLS, Idempotency & RFC 9457."""

from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.database import mock_db
from app.middleware.idempotency import IdempotencyMiddleware
from app.middleware.problem_details import (
    generic_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)
from app.middleware.tenant_context import TenantContextMiddleware
from app.models.schemas import (
    DocumentCreate,
    DocumentResponse,
    ProblemDetail,
    TransactionCreate,
    TransactionResponse,
)

app = FastAPI(
    title="Agent-Ready Enterprise API",
    version="1.0.0",
    description=(
        "API diseñada para interactuar con agentes de IA autónomos y sistemas corporativos. "
        "Incorpora autenticación por Tenant, Idempotencia nativa, respuestas de error RFC 9457 "
        "y aislamiento estricto de base de datos con PostgreSQL Row-Level Security (RLS)."
    ),
    responses={
        400: {"model": ProblemDetail, "description": "Bad Request (RFC 9457)"},
        422: {"model": ProblemDetail, "description": "Validation Error (RFC 9457)"},
        500: {"model": ProblemDetail, "description": "Internal Server Error (RFC 9457)"},
    },
)

# 1. Registrar Manejadores de Errores RFC 9457
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# 2. Registrar Middlewares Defensivos (Orden inverso de ejecución)
app.add_middleware(IdempotencyMiddleware)
app.add_middleware(TenantContextMiddleware)

# 3. CORS Restrictivo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.tuempresa.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-API-Key"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["RateLimit-Limit"] = "100"
    response.headers["RateLimit-Remaining"] = "99"
    return response


# ==============================================================================
# 🚀 ENDPOINTS DE NEGOCIO
# ==============================================================================

@app.get("/health", tags=["Infraestructura"])
async def health_check():
    """Health check pasivo para monitoreo y balanceadores de carga."""
    return {"status": "healthy", "architecture": "agent-ready", "database": "connected"}


@app.get(
    "/api/v1/documents",
    response_model=List[DocumentResponse],
    tags=["Documentos"],
    summary="Listar documentos del Tenant actual (con paginación)",
)
async def list_documents(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Límite máximo de registros a retornar"),
    offset: int = Query(0, ge=0, description="Desplazamiento para paginación"),
):
    tenant_id = request.state.tenant_id
    # En PostgreSQL real, la conexión ejecuta SET LOCAL app.current_tenant_id y SELECT * FROM documents
    docs = mock_db.get_documents(tenant_id=tenant_id)
    return docs[offset : offset + limit]


@app.post(
    "/api/v1/documents",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Documentos"],
    summary="Crear documento en el Tenant actual",
)
async def create_document(request: Request, payload: DocumentCreate):
    tenant_id = request.state.tenant_id
    # 🛡️ DEFENSIVE: El tenant_id NUNCA proviene del payload, sino del contexto autenticado
    created = mock_db.insert_document(
        tenant_id=tenant_id,
        title=payload.title,
        content=payload.content,
    )
    return created


@app.post(
    "/api/v1/transactions",
    response_model=TransactionResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Transacciones"],
    summary="Crear transacción financiera con garantía de Idempotencia",
)
async def create_transaction(
    request: Request,
    payload: TransactionCreate,
    idempotency_key: Optional[str] = Header(
        None,
        description="UUIDv4 único para garantizar que la transacción solo se ejecute una vez ante reintentos de agentes.",
    ),
):
    if not idempotency_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La cabecera 'Idempotency-Key' es obligatoria para procesar operaciones financieras.",
        )

    tenant_id = request.state.tenant_id
    tx = mock_db.insert_transaction(
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        amount=float(payload.amount),
        currency=payload.currency,
    )
    return tx
