"""Production Inspector module: Strictly passive and safe auditing for live APIs."""

import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional
from api_guardian.core.models import AuditReport, Finding, Severity


class ProdInspector:
    """Non-destructive, passive inspector for live production/staging API endpoints."""

    SENSITIVE_ENDPOINTS = [
        {"path": "/.env", "name": "Archivo de entorno .env", "severity": Severity.CRITICAL},
        {"path": "/.git/HEAD", "name": "Repositorio Git expuesto (.git/HEAD)", "severity": Severity.CRITICAL},
        {"path": "/actuator/env", "name": "Spring Boot Actuator Env", "severity": Severity.CRITICAL},
        {"path": "/actuator", "name": "Spring Boot Actuator raíz", "severity": Severity.MEDIUM},
        {"path": "/metrics", "name": "Métricas Prometheus o internas", "severity": Severity.LOW},
        {"path": "/server-status", "name": "Apache Server Status", "severity": Severity.MEDIUM},
        {"path": "/_profiler", "name": "Profiler de framework expuesto", "severity": Severity.HIGH},
    ]

    def __init__(self, base_url: str, timeout: float = 4.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = f"https://{self.base_url}"

    def inspect(self) -> AuditReport:
        report = AuditReport(
            target=self.base_url,
            mode="prod",
            metadata={"base_url": self.base_url},
        )

        headers, status_code = self._fetch_headers(self.base_url)
        if headers is None:
            report.add_finding(
                Finding(
                    id="API-PROD-CONN",
                    title="No se pudo establecer conexión con el objetivo",
                    severity=Severity.HIGH,
                    category="Conectividad",
                    location=self.base_url,
                    description="No fue posible conectar con el servidor para inspeccionar cabeceras y configuración.",
                    impact="Imposible verificar postura de seguridad en vivo.",
                    remediation="Verificar que el host esté accesible y el firewall permita peticiones HTTP/HTTPS.",
                )
            )
            return report

        self._check_transport_and_tls(report)
        self._check_security_headers(headers, report)
        self._check_cors_policy(report)
        self._check_sensitive_endpoints(report)
        self._check_rate_limiting(headers, report)

        return report

    def _fetch_headers(self, url: str) -> tuple[Optional[Dict[str, str]], int]:
        req = urllib.request.Request(
            url=url,
            headers={"User-Agent": "Mozilla/5.0 (API-Guardian-Auditor/1.0; PassiveSecurityCheck)"},
            method="GET",
        )
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return headers, resp.status
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            return headers, e.code
        except Exception:
            return None, 0

    def _check_transport_and_tls(self, report: AuditReport) -> None:
        if self.base_url.startswith("http://") and not ("localhost" in self.base_url or "127.0.0.1" in self.base_url):
            report.add_finding(
                Finding(
                    id="API-PROD-001",
                    title="Producción en protocolo HTTP no cifrado",
                    severity=Severity.CRITICAL,
                    category="Seguridad de Transporte",
                    location=self.base_url,
                    description="El servicio en producción opera sobre HTTP plano sin cifrado TLS.",
                    impact="Todas las peticiones (tokens de auth, datos privados, contraseñas) viajan en texto claro.",
                    remediation="Habilitar certificados TLS/SSL (HTTPS) y forzar redirección 301 permanente desde HTTP a HTTPS.",
                    owasp_api_id="API8:2023",
                    cwe="CWE-319",
                )
            )

    def _check_security_headers(self, headers: Dict[str, str], report: AuditReport) -> None:
        # HSTS
        if "strict-transport-security" not in headers:
            report.add_finding(
                Finding(
                    id="API-PROD-002",
                    title="Cabecera HSTS (Strict-Transport-Security) ausente",
                    severity=Severity.MEDIUM,
                    category="Cabeceras de Seguridad",
                    location="HTTP Response Headers",
                    description="El servidor no incluye la cabecera HSTS para obligar a los clientes a usar conexiones HTTPS seguras.",
                    impact="Permite ataques de degradación de protocolo (SSL Stripping).",
                    remediation="Agregar cabecera: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                    owasp_api_id="API8:2023",
                    cwe="CWE-523",
                )
            )

        # X-Content-Type-Options
        if headers.get("x-content-type-options") != "nosniff":
            report.add_finding(
                Finding(
                    id="API-PROD-003",
                    title="Cabecera X-Content-Type-Options ausente o incorrecta",
                    severity=Severity.LOW,
                    category="Cabeceras de Seguridad",
                    location="HTTP Response Headers",
                    description="Falta la directiva `nosniff`, lo que permite MIME-type sniffing en navegadores.",
                    impact="Posible ejecución no intencionada de scripts en navegadores ante descargas de archivos.",
                    remediation="Agregar cabecera: `X-Content-Type-Options: nosniff`.",
                    owasp_api_id="API8:2023",
                    cwe="CWE-79",
                )
            )

        # Leaks de versión de software (Server, X-Powered-By)
        powered_by = headers.get("x-powered-by")
        server = headers.get("server")
        if powered_by:
            report.add_finding(
                Finding(
                    id="API-PROD-004",
                    title="Fuga de tecnología en cabecera X-Powered-By",
                    severity=Severity.LOW,
                    category="Fuga de Información",
                    location=f"X-Powered-By: {powered_by}",
                    description=f"El servidor expone públicamente el framework o runtime utilizado ({powered_by}).",
                    impact="Facilita el reconocimiento de vulnerabilidades específicas de esa versión por parte de atacantes.",
                    remediation="Ocultar o deshabilitar la cabecera (ej. en Express: `app.disable('x-powered-by')`).",
                    owasp_api_id="API8:2023",
                    cwe="CWE-200",
                )
            )

    def _check_cors_policy(self, report: AuditReport) -> None:
        """Passive CORS test checking for wildcards and arbitrary origin reflection."""
        req = urllib.request.Request(
            url=self.base_url,
            headers={
                "Origin": "https://api-guardian-security-audit.com",
                "User-Agent": "API-Guardian/1.0",
            },
            method="OPTIONS",
        )
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                allow_origin = headers.get("access-control-allow-origin")
                allow_creds = headers.get("access-control-allow-credentials", "").lower() == "true"

                if allow_origin == "https://api-guardian-security-audit.com" and allow_creds:
                    report.add_finding(
                        Finding(
                            id="API-PROD-005",
                            title="Reflejo arbitrario de Origin con credenciales en CORS (Crítico)",
                            severity=Severity.CRITICAL,
                            category="Mala Configuración de CORS",
                            location="Access-Control-Allow-Origin",
                            description="El servidor refleja el Origin arbitrario del atacante y permite credenciales (cookies/tokens).",
                            impact="Cualquier sitio web malicioso puede realizar peticiones autenticadas y leer respuestas privadas del usuario.",
                            remediation="Configurar una lista blanca estricta de dominios autorizados y nunca reflejar el Origin dinámicamente con allow-credentials.",
                            owasp_api_id="API8:2023",
                            cwe="CWE-942",
                        )
                    )
                elif allow_origin == "*":
                    report.add_finding(
                        Finding(
                            id="API-PROD-006",
                            title="CORS permisivo con comodín (Access-Control-Allow-Origin: *)",
                            severity=Severity.INFO,
                            category="Configuración de CORS",
                            location="Access-Control-Allow-Origin: *",
                            description="La API permite solicitudes desde cualquier origen web.",
                            impact="Normal si la API es 100% pública; riesgoso si gestiona datos privados de usuarios.",
                            remediation="Restringir los orígenes permitidos si la API no está pensada como servicio público abierto.",
                            owasp_api_id="API8:2023",
                        )
                    )
        except Exception:
            pass

    def _check_sensitive_endpoints(self, report: AuditReport) -> None:
        """Non-intrusive probe for common exposed configuration/debug endpoints."""
        ctx = ssl.create_default_context()
        for ep in self.SENSITIVE_ENDPOINTS:
            url = f"{self.base_url}{ep['path']}"
            req = urllib.request.Request(
                url=url,
                headers={"User-Agent": "API-Guardian/1.0"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    if resp.status == 200:
                        content_sample = resp.read()[:150].decode("utf-8", errors="ignore")
                        report.add_finding(
                            Finding(
                                id="API-PROD-007",
                                title=f"Ruta sensible o administrativa expuesta públicamente ({ep['name']})",
                                severity=ep["severity"],
                                category="Mala Configuración de Seguridad",
                                location=ep["path"],
                                description=f"La ruta {ep['path']} respondió con HTTP 200 OK y está expuesta en internet.",
                                impact="Exposición de variables de entorno, código fuente, métricas internas o credenciales de la infraestructura.",
                                remediation=f"Bloquear el acceso a {ep['path']} en el API Gateway / Reverse Proxy (Nginx/Cloudflare) o restringir por IP interna.",
                                evidence=f"Muestra de contenido: {content_sample!r}",
                                owasp_api_id="API8:2023",
                                cwe="CWE-200",
                            )
                        )
            except Exception:
                pass

    def _check_rate_limiting(self, headers: Dict[str, str], report: AuditReport) -> None:
        rate_headers = [
            "ratelimit-limit",
            "ratelimit-remaining",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
        ]
        has_rate_limit = any(h in headers for h in rate_headers)
        if not has_rate_limit:
            report.add_finding(
                Finding(
                    id="API-PROD-008",
                    title="Sin cabeceras de límite de tasa detectables (Rate Limiting)",
                    severity=Severity.LOW,
                    category="Consumo Ilimitado de Recursos",
                    location="HTTP Response Headers",
                    description="No se identificaron cabeceras estándar de control de cuotas o límites de peticiones.",
                    impact="Potencial vulnerabilidad a ataques de fuerza bruta o saturación de peticiones (DoS).",
                    remediation="Configurar políticas de Rate Limiting a nivel de Gateway (Kong, AWS API Gateway, Cloudflare, Traefik) o middleware de aplicación.",
                    owasp_api_id="API4:2023",
                    cwe="CWE-770",
                )
            )
