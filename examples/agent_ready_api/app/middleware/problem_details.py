"""RFC 9457 Problem Details Exception Handlers for FastAPI."""

from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Transforms FastAPI Pydantic validation errors into RFC 9457 Problem Details with JSON Pointers."""
    errors = []
    for err in exc.errors():
        # Formulate JSON pointer: ('body', 'amount') -> '#/amount'
        loc = err.get("loc", ())
        pointer_parts = [str(part) for part in loc if part != "body"]
        pointer = "#/" + "/".join(pointer_parts) if pointer_parts else "#"

        errors.append({
            "pointer": pointer,
            "detail": f"{err.get('msg', 'Invalid value')}. Input received: {err.get('input', 'N/A')!r}"
        })

    problem_body = {
        "type": "https://api.tuempresa.com/errors/validation-error",
        "title": "Error de validación en la solicitud del agente",
        "status": status.HTTP_422_UNPROCESSABLE_ENTITY,
        "detail": "Uno o más parámetros no cumplen con el esquema de validación estricto.",
        "instance": str(request.url.path),
        "errors": errors,
    }

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem_body,
        media_type="application/problem+json",
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    problem_body = {
        "type": f"https://api.tuempresa.com/errors/http-{exc.status_code}",
        "title": exc.detail if isinstance(exc.detail, str) else "Error HTTP",
        "status": exc.status_code,
        "detail": str(exc.detail),
        "instance": str(request.url.path),
    }

    return JSONResponse(
        status_code=exc.status_code,
        content=problem_body,
        media_type="application/problem+json",
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # 🛡️ DEFENSIVE: Never leak internal stack trace to agent/client
    problem_body = {
        "type": "https://api.tuempresa.com/errors/internal-server-error",
        "title": "Error interno del servidor",
        "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "detail": "Ha ocurrido un error inesperado al procesar la operación. El equipo de ingeniería ha sido notificado.",
        "instance": str(request.url.path),
    }

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=problem_body,
        media_type="application/problem+json",
    )
