# Estándares para APIs Agent-Ready y Multi-Tenant Empresariales

Este documento describe la especificación técnica que garantiza que una API pueda ser consumida con seguridad tanto por **usuarios humanos** como por **agentes autónomos de IA** en entornos corporativos.

---

## 1. Interoperabilidad con Agentes (Model Context Protocol & OpenAPI 3.1)

Los modelos de lenguaje (LLMs) procesan contratos de API como parte de su ventana de contexto.
* **OpenAPI 3.1:** Las descripciones de endpoints y schemas (`description`, `example`, `enum`, `minimum`, `maximum`) actúan como system prompts directos para el modelo.
* **Model Context Protocol (MCP):** Estándar abierto (Linux Foundation / Anthropic) que permite a clientes como Claude Desktop, Cursor y Antigravity descubrir y ejecutar herramientas sobre JSON-RPC sin necesidad de código pegamento específico por proveedor.

---

## 2. Aislamiento Multi-Tenant & Seguridad de Agentes

### La Regla Inviolable del Tenant
> [!CAUTION]
> **El `tenant_id` jamás debe ser un parámetro que el agente invente o envíe en el cuerpo de la petición.**
> Si se permite `{ "tenant_id": "...", "data": "..." }`, una alucinación del LLM o un ataque de Prompt Injection provocará cruces de datos entre organizaciones.

* **Resolución en Perímetro:** El `tenant_id` se extrae exclusivamente del token (API Key o JWT) verificado en el middleware de autenticación.
* **Row-Level Security (RLS) en PostgreSQL:**
  ```sql
  ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
  ALTER TABLE documents FORCE ROW LEVEL SECURITY;

  CREATE POLICY tenant_isolation ON documents
      FOR ALL
      USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::UUID);
  ```
* **Ámbito Transaccional:** En cada conexión adquirida del pool, el middleware ejecuta:
  ```sql
  SET LOCAL app.current_tenant_id = '$tenant_id';
  ```
  La instrucción `SET LOCAL` asegura que la variable expire automáticamente cuando termine la transacción, evitando fugas en conexiones reutilizadas del pool.

---

## 3. Resiliencia ante Bucles de Agentes (Idempotencia)

Los agentes reintentan peticiones cuando experimentan latencia o dudas en su razonamiento.
* **Cabecera obligatoria en mutaciones:** `Idempotency-Key: <UUIDv4>`.
* **Flujo Record & Replay:**
  1. Si la clave no existe, se bloquea y procesa la transacción.
  2. Si la clave ya fue procesada, se devuelve la respuesta en caché (código HTTP y cuerpo JSON) durante 24 horas (`X-Cache-Lookup: HIT-IDEMPOTENCY-REPLAY`).
  3. Previene cobros duplicados o creación masiva de registros por bucles infinitos del agente.

---

## 4. Semántica de Errores para Auto-Corrección (RFC 9457)

Cuando un agente envía parámetros incorrectos, necesita saber exactamente qué falló para corregir su llamada en el siguiente turno.
* **Media Type:** `application/problem+json`
* **Campos Requeridos:** `type`, `title`, `status`, `detail`, `instance`.
* **Extensión `errors` con JSON Pointers:**
  ```json
  {
    "type": "https://api.tuempresa.com/errors/validation-error",
    "title": "Error de validación",
    "status": 422,
    "detail": "Parámetro inválido",
    "instance": "/api/v1/transactions",
    "errors": [
      {
        "pointer": "#/amount",
        "detail": "El monto debe ser superior a 0"
      }
    ]
  }
  ```
  El puntero JSON (`#/amount`) guía al LLM directamente al nodo que debe enmendar.
