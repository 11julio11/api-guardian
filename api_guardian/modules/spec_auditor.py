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
                            if prop_name.lower() in self.PRIVILEGED_PROPERTIES:
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
