"""Spec Auditor module: Evaluates OpenAPI (v2, v3, v3.1) contracts for OWASP API Security risks."""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from api_guardian.core.models import AuditReport, Finding, Severity


class SpecAuditor:
    """Audits OpenAPI / Swagger specifications for security vulnerabilities and governance."""

    SENSITIVE_PARAM_NAMES = {"token", "auth", "key", "api_key", "apikey", "password", "secret", "access_token"}
    PRIVILEGED_PROPERTIES = {"role", "is_admin", "isadmin", "admin", "permissions", "balance", "verified", "account_type"}
    PAGINATION_KEYWORDS = {"limit", "page", "pagesize", "page_size", "offset", "cursor", "take", "skip"}
    SSRF_PARAM_KEYWORDS = {"url", "webhook", "callback", "redirect", "target_url", "dest", "endpoint", "feed_url", "image_url", "avatar_url"}

    def __init__(self, spec_path: str):
        self.spec_path = Path(spec_path)
        self.raw_content = ""
        self.spec: Dict[str, Any] = {}

    def load_spec(self) -> None:
        if not self.spec_path.exists():
            raise FileNotFoundError(f"Spec file not found: {self.spec_path}")

        self.raw_content = self.spec_path.read_text(encoding="utf-8")
        
        # Try JSON first
        try:
            self.spec = json.loads(self.raw_content)
            return
        except json.JSONDecodeError:
            pass

        # Try PyYAML if installed
        try:
            import yaml
            self.spec = yaml.safe_load(self.raw_content)
            return
        except ImportError:
            pass

        # Fallback basic YAML parser for common OpenAPI structure if PyYAML is missing
        self.spec = self._parse_simple_yaml(self.raw_content)
        if not self.spec:
            raise ValueError(
                "Unable to parse spec as JSON and PyYAML is not installed. "
                "Please save the specification as JSON or run: pip install pyyaml"
            )

    def _parse_simple_yaml(self, text: str) -> Dict[str, Any]:
        """Minimal fallback for standard YAML openapi files when PyYAML is not present."""
        # Simple extraction for core keys if JSON fails and yaml not installed
        try:
            import json
            # Check if it was json-like or simple
            return {}
        except Exception:
            return {}

    def audit(self) -> AuditReport:
        self.load_spec()
        report = AuditReport(
            target=str(self.spec_path),
            mode="spec",
            metadata={
                "openapi_version": self.spec.get("openapi") or self.spec.get("swagger", "Unknown"),
                "title": self.spec.get("info", {}).get("title", "Untitled API"),
                "version": self.spec.get("info", {}).get("version", "1.0"),
            },
        )

        self._check_servers_and_schemes(report)
        self._check_global_security(report)
        self._check_paths(report)

        return report

    def _check_servers_and_schemes(self, report: AuditReport) -> None:
        # Check v3 servers
        servers = self.spec.get("servers", [])
        for server in servers:
            url = server.get("url", "")
            if url.startswith("http://") and not ("localhost" in url or "127.0.0.1" in url):
                report.add_finding(
                    Finding(
                        id="API-SPEC-001",
                        title="Servidor configurado sin cifrado TLS (HTTP no seguro)",
                        severity=Severity.HIGH,
                        category="Seguridad de Transporte",
                        location=f"servers: {url}",
                        description="La especificación define una URL base de servidor utilizando HTTP en lugar de HTTPS.",
                        impact="Las comunicaciones pueden ser interceptadas o alteradas mediante ataques Man-in-the-Middle (MitM).",
                        remediation="Actualizar la URL del servidor para que utilice estrictamente `https://`.",
                        cwe="CWE-319",
                        owasp_api_id="API8:2023",
                    )
                )

        # Check v2 schemes
        schemes = self.spec.get("schemes", [])
        if schemes and "http" in schemes and "https" not in schemes:
            report.add_finding(
                Finding(
                    id="API-SPEC-001",
                    title="Esquema Swagger v2 solo permite HTTP no seguro",
                    severity=Severity.HIGH,
                    category="Seguridad de Transporte",
                    location="schemes",
                    description="El contrato solo declara HTTP como esquema de transporte permitido.",
                    impact="Tráfico no cifrado en tránsito.",
                    remediation="Agregar `https` en el arreglo `schemes` y remover `http` para entornos externos.",
                    cwe="CWE-319",
                    owasp_api_id="API8:2023",
                )
            )

    def _check_global_security(self, report: AuditReport) -> None:
        global_security = self.spec.get("security")
        components = self.spec.get("components", {}) or self.spec.get("securityDefinitions", {})
        security_schemes = components.get("securitySchemes", {}) if "components" in self.spec else components

        if not global_security and not security_schemes:
            report.add_finding(
                Finding(
                    id="API-SPEC-002",
                    title="No se declararon esquemas de seguridad ni autenticación global",
                    severity=Severity.HIGH,
                    category="Autenticación",
                    location="components.securitySchemes / security",
                    description="El contrato no define ningún mecanismo de autenticación global (OAuth2, Bearer JWT, API Keys).",
                    impact="Endpoints sensibles podrían quedar públicos o sin autenticación verificable por defecto.",
                    remediation="Definir `components.securitySchemes` (ej. HTTP Bearer JWT) y aplicarlo globalmente en `security`.",
                    cwe="CWE-306",
                    owasp_api_id="API2:2023",
                )
            )

    def _check_paths(self, report: AuditReport) -> None:
        paths = self.spec.get("paths", {})
        global_security = self.spec.get("security", [])

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in ("get", "post", "put", "delete", "patch"):
                operation = path_item.get(method)
                if not operation or not isinstance(operation, dict):
                    continue

                op_location = f"{method.upper()} {path}"
                op_security = operation.get("security")

                # 1. Chequeo de autenticación en operaciones de mutación (POST, PUT, DELETE, PATCH)
                is_mutation = method in ("post", "put", "delete", "patch")
                is_auth_disabled = op_security == [] or (op_security is None and not global_security)
                is_login_path = any(kw in path.lower() for kw in ("login", "register", "signup", "auth", "token", "forgot-password"))

                if is_mutation and is_auth_disabled and not is_login_path:
                    report.add_finding(
                        Finding(
                            id="API-SPEC-003",
                            title="Operación de modificación sin autenticación declarada",
                            severity=Severity.HIGH,
                            category="Autenticación Rota",
                            location=op_location,
                            description=f"La ruta {op_location} permite alterar o crear datos pero no requiere credenciales ni autenticación.",
                            impact="Cualquier actor anónimo puede ejecutar mutaciones en el sistema.",
                            remediation="Configurar `security: [{ bearerAuth: [] }]` en la operación o a nivel global.",
                            cwe="CWE-306",
                            owasp_api_id="API2:2023",
                        )
                    )

                # 2. Chequeo de parámetros sensibles en query string
                parameters = operation.get("parameters", []) + path_item.get("parameters", [])
                for param in parameters:
                    if not isinstance(param, dict):
                        continue
                    p_name = param.get("name", "").lower()
                    p_in = param.get("in", "").lower()

                    if p_in == "query" and any(sens in p_name for sens in self.SENSITIVE_PARAM_NAMES):
                        report.add_finding(
                            Finding(
                                id="API-SPEC-004",
                                title="Credencial o secreto transmitido como parámetro de Query",
                                severity=Severity.HIGH,
                                category="Gestión de Credenciales",
                                location=f"{op_location} (query: {param.get('name')})",
                                description=f"El parámetro '{param.get('name')}' se envía en la query string de la URL.",
                                impact="Las URLs de query se registran en logs de proxy, servidores web, historial de navegadores y cabeceras Referer.",
                                remediation="Enviar credenciales en cabeceras de autorización (`Authorization: Bearer ...`) o en el cuerpo cifrado POST.",
                                cwe="CWE-598",
                                owasp_api_id="API2:2023",
                            )
                        )

                    # Chequeo de parámetros propensos a SSRF (API-SPEC-007)
                    if any(kw in p_name for kw in self.SSRF_PARAM_KEYWORDS):
                        p_schema = param.get("schema", {})
                        if not p_schema.get("pattern") and not p_schema.get("enum"):
                            report.add_finding(
                                Finding(
                                    id="API-SPEC-007",
                                    title="Parámetro receptor de URL externa sin validación de destino (Riesgo SSRF)",
                                    severity=Severity.HIGH,
                                    category="Server-Side Request Forgery (SSRF)",
                                    location=f"{op_location} (param: {param.get('name')})",
                                    description=(
                                        f"El parámetro '{param.get('name')}' recibe una dirección web sin definir un patrón regex estricto "
                                        "o lista blanca de dominios permitidos."
                                    ),
                                    impact="Un atacante puede suministrar URLs de localhost o servicios internos de nube (AWS/GCP metadata) provocando SSRF.",
                                    remediation="Validar el esquema (`https`), bloquear dominios/IPs privadas (RFC 1918) y definir un `pattern` estricto en la especificación.",
                                    cwe="CWE-918",
                                    owasp_api_id="API7:2023",
                                )
                            )

                # 3. Falta de paginación en listas (GET)
                if method == "get" and not path.endswith("}"):
                    # Endpoint probable de colección (ej: /users, /orders)
                    param_names = {p.get("name", "").lower() for p in parameters if isinstance(p, dict)}
                    has_pagination = bool(param_names.intersection(self.PAGINATION_KEYWORDS))

                    # Revisar si retorna array
                    responses = operation.get("responses", {})
                    ok_resp = responses.get("200") or responses.get(200)
                    returns_array = False
                    if isinstance(ok_resp, dict):
                        content = ok_resp.get("content", {}).get("application/json", {}).get("schema", {})
                        if content.get("type") == "array":
                            returns_array = True

                    if returns_array and not has_pagination:
                        report.add_finding(
                            Finding(
                                id="API-SPEC-005",
                                title="Endpoint de colección sin parámetros de paginación",
                                severity=Severity.MEDIUM,
                                category="Consumo Ilimitado de Recursos",
                                location=op_location,
                                description=f"La consulta {op_location} retorna una lista sin parámetros para limitar registros (`limit`, `page`, `offset`).",
                                impact="Un atacante puede solicitar listas completas de miles de registros agotando la memoria del servidor o base de datos (DoS).",
                                remediation="Añadir parámetros de paginación con un límite máximo (ej. `max: 100`) y paginado por cursor o página.",
                                cwe="CWE-770",
                                owasp_api_id="API4:2023",
                            )
                        )

                # 4. Chequeo de Mass Assignment en request body
                request_body = operation.get("requestBody", {})
                if isinstance(request_body, dict):
                    content = request_body.get("content", {}).get("application/json", {}).get("schema", {})
                    props = content.get("properties", {})
                    if isinstance(props, dict):
                        for prop_name in props.keys():
                            p_lower = prop_name.lower()
                            if p_lower in self.PRIVILEGED_PROPERTIES:
                                report.add_finding(
                                    Finding(
                                        id="API-SPEC-006",
                                        title=f"Propiedad sensible expuesta en Request Body ({prop_name})",
                                        severity=Severity.HIGH,
                                        category="Asignación Masiva / BOPLA",
                                        location=f"{op_location} (body.{prop_name})",
                                        description=f"El esquema del body permite que el cliente envíe directamente `{prop_name}`.",
                                        impact="Un usuario puede elevar privilegios o alterar estados críticos (ej. `role: admin`, `is_admin: true`).",
                                        remediation="Usar DTOs exclusivos para creación/edición pública que excluyan atributos administrativos.",
                                        cwe="CWE-915",
                                        owasp_api_id="API3:2023",
                                    )
                                )

                            # 5. [AGENT-READY] Chequeo de exposición insegura de tenant_id en body
                            if p_lower in ("tenant_id", "tenantid", "org_id", "organization_id", "account_id") and not is_login_path:
                                report.add_finding(
                                    Finding(
                                        id="API-AGENT-002",
                                        title=f"Identificador de Tenant ({prop_name}) expuesto en el Request Body",
                                        severity=Severity.HIGH,
                                        category="Aislamiento Multi-Tenant & Agent Safety",
                                        location=f"{op_location} (body.{prop_name})",
                                        description=(
                                            f"El schema permite que el cliente o agente envíe explícitamente `{prop_name}` en el JSON. "
                                            "Los agentes de IA no deben decidir ni enviar el tenant_id por riesgo de alucinación o Prompt Injection."
                                        ),
                                        impact="Un agente o atacante puede cruzar datos o mutar registros en otra organización alterando el ID.",
                                        remediation="Eliminar el campo del Request Body. El backend debe resolver el tenant_id exclusivamente desde el token/API Key autenticado.",
                                        owasp_api_id="API1:2023",
                                        cwe="CWE-639",
                                    )
                                )

                            # 6. [OWASP API7:2023] SSRF en request body
                            if any(kw in p_lower for kw in self.SSRF_PARAM_KEYWORDS):
                                prop_schema = props[prop_name] if isinstance(props[prop_name], dict) else {}
                                if not prop_schema.get("pattern") and not prop_schema.get("enum"):
                                    report.add_finding(
                                        Finding(
                                            id="API-SPEC-007",
                                            title=f"Campo receptor de URL externa sin validación estricta en Request Body ({prop_name})",
                                            severity=Severity.HIGH,
                                            category="Server-Side Request Forgery (SSRF)",
                                            location=f"{op_location} (body.{prop_name})",
                                            description=(
                                                f"La propiedad `{prop_name}` recibe una dirección URL sin definir un patrón de validación "
                                                "o lista blanca de dominios."
                                            ),
                                            impact="Vulnerabilidad a Server-Side Request Forgery (SSRF) si el backend consume este destino sin filtros de IP interna.",
                                            remediation="Restringir dominios mediante validación en backend y definir `pattern` estricto en OpenAPI.",
                                            cwe="CWE-918",
                                            owasp_api_id="API7:2023",
                                        )
                                    )

                            # 7. [OWASP API4:2023] Falta de límite de longitud en strings o elementos en arrays
                            prop_schema = props[prop_name] if isinstance(props[prop_name], dict) else {}
                            if prop_schema.get("type") == "string":
                                fmt = prop_schema.get("format", "")
                                if fmt not in ("date", "date-time", "uuid", "binary", "byte") and "maxLength" not in prop_schema and "enum" not in prop_schema:
                                    report.add_finding(
                                        Finding(
                                            id="API-SPEC-008",
                                            title=f"Propiedad string sin límite de longitud máxima (maxLength) en Request Body ({prop_name})",
                                            severity=Severity.MEDIUM,
                                            category="Consumo Ilimitado de Recursos",
                                            location=f"{op_location} (body.{prop_name})",
                                            description=f"El campo `{prop_name}` no declara `maxLength` en el esquema OpenAPI.",
                                            impact="Un atacante o bot puede enviar payloads masivos agotando la memoria del servidor o base de datos (DoS).",
                                            remediation="Definir `maxLength` acorde a la necesidad del negocio (ej. `maxLength: 255`).",
                                            cwe="CWE-770",
                                            owasp_api_id="API4:2023",
                                        )
                                    )
                            elif prop_schema.get("type") == "array" and "maxItems" not in prop_schema:
                                report.add_finding(
                                    Finding(
                                        id="API-SPEC-008",
                                        title=f"Colección array sin límite de elementos (maxItems) en Request Body ({prop_name})",
                                        severity=Severity.MEDIUM,
                                        category="Consumo Ilimitado de Recursos",
                                        location=f"{op_location} (body.{prop_name})",
                                        description=f"La colección `{prop_name}` no define la restricción `maxItems`.",
                                        impact="Riesgo de procesamiento masivo no controlado y agotamiento de recursos computacionales.",
                                        remediation="Definir `maxItems` (ej. `maxItems: 100`) para acotar la carga procesable por petición.",
                                        cwe="CWE-770",
                                        owasp_api_id="API4:2023",
                                    )
                                )

                # 8. [AGENT-READY] Chequeo de soporte de Idempotencia en mutaciones
                if method in ("post", "put", "patch") and not is_login_path:
                    header_params = [
                        p.get("name", "").lower()
                        for p in parameters
                        if isinstance(p, dict) and p.get("in", "").lower() == "header"
                    ]
                    has_idempotency = any("idempotency" in h for h in header_params)
                    is_critical_mutation = any(kw in path.lower() for kw in ("order", "pay", "checkout", "transact", "bill", "transfer", "charge", "invoice"))

                    if not has_idempotency:
                        report.add_finding(
                            Finding(
                                id="API-AGENT-001",
                                title="Operación de mutación sin cabecera de Idempotencia (Idempotency-Key)",
                                severity=Severity.HIGH if is_critical_mutation else Severity.MEDIUM,
                                category="Interoperabilidad con Agentes & Idempotencia",
                                location=op_location,
                                description=(
                                    f"La operación {op_location} modifica recursos pero no declara soporte para la cabecera `Idempotency-Key`. "
                                    "Los agentes autónomos reintentan llamadas automáticamente ante dudas o latencia."
                                ),
                                impact="Riesgo de transacciones o registros duplicados (dobles cargos, compras repetidas) provocados por reintentos de agentes.",
                                remediation="Añadir la cabecera opcional `Idempotency-Key: <UUIDv4>` al endpoint y almacenar la respuesta en caché (Redis) durante 24h.",
                                owasp_api_id="API4:2023",
                                cwe="CWE-674",
                            )
                        )

                # 9. [AGENT-READY] Chequeo de formato de error RFC 9457 (Problem Details)
                responses = operation.get("responses", {})
                for status_code in ("400", "422", "500"):
                    err_resp = responses.get(status_code)
                    if isinstance(err_resp, dict):
                        content_types = err_resp.get("content", {})
                        has_problem_json = "application/problem+json" in content_types
                        has_rfc_fields = False
                        json_schema = content_types.get("application/json", {}).get("schema", {})
                        if json_schema.get("properties"):
                            props_keys = set(json_schema["properties"].keys())
                            if {"type", "title", "detail"}.issubset(props_keys):
                                has_rfc_fields = True

                        if not has_problem_json and not has_rfc_fields:
                            report.add_finding(
                                Finding(
                                    id="API-AGENT-003",
                                    title=f"Respuesta de error {status_code} no estandarizada con RFC 9457 (Problem Details)",
                                    severity=Severity.LOW,
                                    category="Semántica de Errores para Agentes (RFC 9457)",
                                    location=f"{op_location} (responses.{status_code})",
                                    description=(
                                        f"El error {status_code} no define el media type `application/problem+json` ni los campos estructurados "
                                        "(`type`, `title`, `detail`, `errors` con JSON Pointers)."
                                    ),
                                    impact="Los agentes de IA no podrán inferir la causa exacta del error semántico para auto-corregir sus llamados.",
                                    remediation="Definir las respuestas de error bajo RFC 9457 (`application/problem+json`) con campos detallados de validación.",
                                    owasp_api_id="API8:2023",
                                )
                            )

                # 10. [AGENT-READY] Chequeo de semántica y descripciones para Agentes LLM
                summary = (operation.get("summary") or "").strip()
                description = (operation.get("description") or "").strip()
                if is_mutation and len(summary) < 5 and len(description) < 5:
                    report.add_finding(
                        Finding(
                            id="API-SPEC-009",
                            title="Operación de mutación sin descripción semántica para Agentes de IA",
                            severity=Severity.MEDIUM,
                            category="Interoperabilidad con Agentes & Semántica",
                            location=op_location,
                            description=(
                                f"La operación {op_location} carece de los campos `summary` o `description` descriptivos. "
                                "Los agentes de IA (Cursor, Antigravity, MCP) utilizan estas descripciones como prompt del sistema "
                                "para decidir cuándo y cómo ejecutar herramientas."
                            ),
                            impact="Llamadas imprecisas, parámetros malinterpretados o alucinaciones por parte de agentes autónomos.",
                            remediation="Añadir `summary` conciso y `description` detallada explicando el propósito del endpoint y restricciones.",
                            owasp_api_id="API8:2023",
                            cwe="CWE-1059",
                        )
                    )

                # 11. [INVENTORY] Chequeo de versionado y obsolescencia (OWASP API9:2023)
                is_versioned = bool(re.search(r"/(v\d+|api/v\d+)(/|$)", path, re.IGNORECASE))
                if not is_versioned and not any(kw in path.lower() for kw in ("health", "status", "metrics", "docs", "openapi")):
                    report.add_finding(
                        Finding(
                            id="API-SPEC-010",
                            title="Ruta de API sin identificador de versionado explícito",
                            severity=Severity.LOW,
                            category="Gestión Inadecuada de Inventario",
                            location=op_location,
                            description=f"La ruta '{path}' no incluye un prefijo de versión estándar (ej. `/v1/` o `/api/v1/`).",
                            impact="Dificulta la retirada controlada de endpoints (deprecation) y favorece la existencia de endpoints zombies o desactualizados.",
                            remediation="Estructurar los endpoints bajo prefijos versionados (ej. `/api/v1/...`) para asegurar un ciclo de vida gobernable.",
                            owasp_api_id="API9:2023",
                            cwe="CWE-1059",
                        )
                    )

                if operation.get("deprecated") is True:
                    report.add_finding(
                        Finding(
                            id="API-SPEC-010",
                            title="Operación marcada como obsoleta (deprecated: true) aún expuesta",
                            severity=Severity.LOW,
                            category="Gestión Inadecuada de Inventario",
                            location=op_location,
                            description=f"La ruta {op_location} está marcada como deprecada en el contrato OpenAPI.",
                            impact="Los clientes o agentes antiguos pueden seguir invocando código legado que no recibe parches de seguridad activos.",
                            remediation="Establecer un cronograma de retiro (`Sunset` header RFC 8594) y migrar los consumidores a la versión vigente.",
                            owasp_api_id="API9:2023",
                            cwe="CWE-1059",
                        )
                    )

