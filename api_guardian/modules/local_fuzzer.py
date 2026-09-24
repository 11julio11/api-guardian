"""Safe Local Fuzzer module: Performs boundary and edge-case testing against local APIs."""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional
from api_guardian.core.models import AuditReport, Finding, Severity


class LocalFuzzer:
    """Safe fuzzer for localhost/staging APIs to detect unhandled exceptions and robustness bugs."""

    SAFE_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

    # Boundary test payloads
    EDGE_PAYLOADS = [
        {"name": "Empty JSON Object", "data": b"{}"},
        {"name": "Null Body", "data": b"null"},
        {"name": "Array instead of Object", "data": b"[1, 2, 3]"},
        {"name": "Type Confusion (numeric where string expected)", "data": b'{"id": 99999999999999999999999999999, "name": 12345}'},
        {"name": "Oversized string payload (10KB)", "data": json.dumps({"test": "A" * 10000}).encode("utf-8")},
        {"name": "Malformed JSON syntax", "data": b'{"key": "value",,,}'},
        {"name": "SQL Injection probe payload", "data": b'{"id": "1\' OR \'1\'=\'1", "username": "\' OR 1=1--"}'},
        {"name": "Path Traversal probe payload", "data": b'{"path": "../../../../etc/passwd", "file": "..\\\\..\\\\win.ini"}'},
    ]

    def __init__(self, base_url: str, allow_remote: bool = False, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.allow_remote = allow_remote
        self.timeout = timeout
        self._validate_target()

    def _validate_target(self) -> None:
        parsed = urllib.parse.urlparse(self.base_url)
        hostname = (parsed.hostname or "").lower()

        if not self.allow_remote and hostname not in self.SAFE_HOSTS and not hostname.endswith(".local"):
            raise ValueError(
                f"🛡️ SAFEGUARD ACTIVADO: La URL '{self.base_url}' parece ser un host remoto/producción.\n"
                f"El fuzzer dinámico solo se permite en localhost por defecto para evitar caídas en producción.\n"
                f"Para entornos de staging autorizados, añade explícitamente el flag --allow-remote."
            )

    def test_endpoint(
        self,
        endpoint_path: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        url = f"{self.base_url}/{endpoint_path.lstrip('/')}"
        base_headers = {"Content-Type": "application/json", "User-Agent": "API-Guardian-Fuzzer/1.0"}
        if headers:
            base_headers.update(headers)

        for probe in self.EDGE_PAYLOADS:
            req = urllib.request.Request(
                url=url,
                data=probe["data"] if method.upper() in ("POST", "PUT", "PATCH") else None,
                headers=base_headers,
                method=method.upper(),
            )

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    # Endpoint responded 2xx
                    pass
            except urllib.error.HTTPError as e:
                # 4xx is expected and secure (proper validation)
                if e.code == 500:
                    body_preview = ""
                    try:
                        body_preview = e.read()[:300].decode("utf-8", errors="ignore")
                    except Exception:
                        pass

                    findings.append(
                        Finding(
                            id="API-FUZZ-500",
                            title=f"Excepción no controlada (HTTP 500) ante payload '{probe['name']}'",
                            severity=Severity.HIGH,
                            category="Mala Gestión de Errores / Robustez",
                            location=f"{method.upper()} {endpoint_path}",
                            description=f"Al enviar el payload '{probe['name']}', el servidor colapsó con código HTTP 500 en lugar de retornar una validación 400 o 422.",
                            impact="Agotamiento de recursos, posibles fugas de memoria o vulnerabilidad a caídas por DoS mediante payloads de entrada imprevistos.",
                            remediation="Implementar un esquema de validación estricto (Pydantic, Zod, DTOs con class-validator) y capturar excepciones con error handlers centralizados.",
                            evidence=f"Payload: {probe['data'][:80]!r}\nRespuesta 500: {body_preview}",
                            owasp_api_id="API8:2023",
                            cwe="CWE-754",
                        )
                    )
            except urllib.error.URLError as e:
                # Connection refused or timeout
                findings.append(
                    Finding(
                        id="API-FUZZ-CONN",
                        title=f"Fallo de conexión o timeout durante la prueba de robustez",
                        severity=Severity.MEDIUM,
                        category="Disponibilidad",
                        location=url,
                        description=f"No se pudo completar la conexión con el servidor local: {e.reason}",
                        impact="El servidor local podría estar apagado o bloqueando conexiones.",
                        remediation="Verificar que el servidor local esté activo en el puerto especificado.",
                    )
                )
                break
            except Exception as e:
                pass

        return findings

    def run_suite(self, endpoints: List[Dict[str, str]]) -> AuditReport:
        report = AuditReport(
            target=self.base_url,
            mode="local",
            metadata={"tested_endpoints_count": len(endpoints)},
        )

        for item in endpoints:
            path = item.get("path", "/")
            method = item.get("method", "POST")
            headers = item.get("headers")
            findings = self.test_endpoint(path, method=method, headers=headers)
            for f in findings:
                report.add_finding(f)

        return report
