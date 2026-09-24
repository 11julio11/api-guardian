# 🌟 Agent-Ready & Multi-Tenant Enterprise Reference API

Esta es la implementación de referencia recomendada por **API Guardian**. Sirve como plantilla arquitectónica tanto para **proyectos independientes** como para **entornos corporativos de gran escala**, garantizando que cualquier agente de inteligencia artificial (Claude, OpenAI, Cursor, Antigravity, CrewAI) pueda interactuar de forma segura y autónoma con la API.

---

## 🏛️ Los 4 Pilares Arquitectónicos Implementados

```mermaid
flowchart TD
    subgraph Entrada["1. Entrada del Agente"]
        Req[Petición del Agente IA]
    end

    subgraph Middleware["2. Frontera Defensiva"]
        Auth[TenantContextMiddleware: Resuelve tenant_id desde API Key]
        Idemp[IdempotencyMiddleware: Bloqueo atómico y replay de 24h]
    end

    subgraph App["3. Capa de Aplicación"]
        FastAPI[FastAPI Endpoints / FastMCP Server]
        RFCError[Manejador RFC 9457 con JSON Pointers]
    end

    subgraph DB["4. Base de Datos"]
        RLS["PostgreSQL Row-Level Security (SET LOCAL app.current_tenant_id)"]
    end

    Req --> Auth
    Auth --> Idemp
    Idemp --> FastAPI
    FastAPI --> RFCError
    FastAPI --> RLS
```

1. **Aislamiento Multi-Tenant Estricto (PostgreSQL RLS):**
   * El `tenant_id` **nunca se expone en el schema de entrada del cliente** (evita alucinaciones del LLM y ataques de BOLA).
   * La sesión transaccional inyecta `SET LOCAL app.current_tenant_id = :id`. Si el endpoint olvida un filtro, la base de datos bloquea el acceso a nivel de fila.
2. **Idempotencia Nativa para Reintentos de Agentes:**
   * La cabecera `Idempotency-Key` (UUIDv4) almacena en caché la respuesta durante 24 horas para evitar duplicar cargos financieros o registros cuando el agente reintenta una llamada ante latencia.
3. **Semántica de Errores para Auto-Corrección (RFC 9457 Problem Details):**
   * Respuestas estructuradas bajo el media type `application/problem+json` con punteros JSON (`pointer: "#/amount"`) que permiten al agente corregir el parámetro exacto en el siguiente turno.
4. **Interoperabilidad Dual (REST OpenAPI 3.1 + FastMCP):**
   * Exposición como API REST tradicional (`/docs`) y como servidor MCP (`mcp_server.py`) para que los agentes invoquen herramientas directamente sobre JSON-RPC.

---

## 🚀 Puesta en Marcha

### Opción A: Ejecución con Docker Compose (PostgreSQL 16 + Redis)
```bash
# Levantar PostgreSQL con las políticas RLS inicializadas y Redis
docker compose up -d

# Instalar dependencias locales y correr el servidor
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Opción B: Modo Ligero / Independiente (Sin Docker)
La plantilla incluye un simulador multi-tenant en memoria con aislamiento estricto que se activa automáticamente si PostgreSQL no está levantado:
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

---

## 🧪 Pruebas de Funcionamiento

### 1. Creación de Documento en el Tenant
```bash
curl -X POST http://localhost:8000/api/v1/documents \
  -H "Authorization: Bearer ak_live_alfa_123456789" \
  -H "Content-Type: application/json" \
  -d '{"title": "Políticas Q3", "content": "Aislamiento garantizado con RLS."}'
```

### 2. Prueba de Idempotencia (Simulación de Reintento de Agente)
```bash
# Primera llamada: procesa y almacena
curl -i -X POST http://localhost:8000/api/v1/transactions \
  -H "Authorization: Bearer ak_live_alfa_123456789" \
  -H "Idempotency-Key: 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d" \
  -H "Content-Type: application/json" \
  -d '{"amount": "250.00", "currency": "USD"}'

# Segunda llamada inmediata con la misma clave:
# Retorna la respuesta en caché instantáneamente (X-Cache-Lookup: HIT-IDEMPOTENCY-REPLAY)
```

### 3. Prueba de Auto-Corrección de Errores (RFC 9457)
Si un agente envía un monto inválido:
```bash
curl -i -X POST http://localhost:8000/api/v1/transactions \
  -H "Authorization: Bearer ak_live_alfa_123456789" \
  -H "Idempotency-Key: c9a646d3-9c61-4cc9-bc9c-9c98b671ef3b" \
  -H "Content-Type: application/json" \
  -d '{"amount": "-50.00"}'
```
Respuesta HTTP 422:
```json
{
  "type": "https://api.tuempresa.com/errors/validation-error",
  "title": "Error de validación en la solicitud del agente",
  "status": 422,
  "detail": "Uno o más parámetros no cumplen con el esquema de validación estricto.",
  "instance": "/api/v1/transactions",
  "errors": [
    {
      "pointer": "#/amount",
      "detail": "Input should be greater than 0. Input received: Decimal('-50.00')"
    }
  ]
}
```

---

## 🤖 Uso con el Servidor MCP

Para que Claude Desktop, Antigravity o Cursor utilicen esta API directamente:
```bash
python3 app/mcp_server.py
```
O agregando la configuración en el cliente MCP:
```json
{
  "mcpServers": {
    "agent-ready-api": {
      "command": "python3",
      "args": ["/ruta/absoluta/examples/agent_ready_api/app/mcp_server.py"],
      "env": {
        "CURRENT_TENANT_ID": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
      }
    }
  }
}
```
