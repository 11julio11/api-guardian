"""Pydantic schemas for Agent-Ready API."""

from decimal import Decimal
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ==============================================================================
# 🛡️ DEFENSIVE DESIGN: tenant_id NO está expuesto en los schemas de entrada
# El tenant se resuelve exclusivamente desde el token/API Key del agente
# ==============================================================================

class DocumentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Título del documento")
    content: str = Field(..., min_length=1, description="Contenido en texto o markdown")

    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "Políticas de Seguridad Q3",
                "content": "Todos los endpoints deben usar HTTPS y RLS."
            }
        }
    }


class DocumentResponse(BaseModel):
    id: str
    title: str
    content: str
    created_at: str


class TransactionCreate(BaseModel):
    amount: Decimal = Field(..., gt=0, decimal_places=2, description="Monto numérico positivo")
    currency: str = Field("USD", min_length=3, max_length=3, description="Código de moneda ISO 4217 (ej. USD, EUR)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "amount": "150.00",
                "currency": "USD"
            }
        }
    }


class TransactionResponse(BaseModel):
    id: str
    amount: Decimal
    currency: str
    status: str
    idempotency_key: str
    created_at: str


# ==============================================================================
# 📋 RFC 9457 / Problem Details Error Schema
# Proporciona a los LLMs la semántica estructurada para auto-corregir sus llamados
# ==============================================================================

class ErrorItem(BaseModel):
    pointer: str = Field(..., description="JSON Pointer exacto al campo defectuoso (ej: #/body/amount)")
    detail: str = Field(..., description="Causa exacta y sugerencia de corrección")


class ProblemDetail(BaseModel):
    type: str = Field("https://api.tuempresa.com/errors/validation-error", description="URI del tipo de error")
    title: str = Field(..., description="Resumen legible del problema")
    status: int = Field(..., description="Código de estado HTTP")
    detail: str = Field(..., description="Explicación detallada de la ocurrencia específica")
    instance: Optional[str] = Field(None, description="URI de la petición que originó el problema")
    errors: Optional[List[ErrorItem]] = Field(None, description="Lista de errores por campo con punteros JSON")
