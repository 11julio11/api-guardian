"""Differential Code Scanner: Analyzes Git diffs and router/controller files for OWASP API vulnerabilities."""

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from api_guardian.core.models import AuditReport, Finding, Severity


class DiffScanner:
    """Scalable scanner targeting only modified code and route handlers in large codebases."""

    ROUTE_EXTENSIONS = {".py", ".ts", ".js", ".java", ".go", ".cs", ".rb", ".php"}

    # Pattern detectors
    PATTERNS = [
        # 1. Hardcoded Secrets
        {
            "id": "API-DIFF-001",
            "title": "Credencial, clave o token hardcodeado en código fuente",
            "severity": Severity.CRITICAL,
            "category": "Gestión de Credenciales",
            "regex": re.compile(
                r"""(?i)(api[_-]?key|jwt[_-]?secret|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{12,}["']"""
            ),
            "description": "Se detectó la asignación directa de una cadena que aparenta ser un token, clave privada o API secret en el código.",
            "impact": "Fuga total de credenciales si el código se almacena en el control de versiones.",
            "remediation": "Mover el secreto a variables de entorno o un gestor de secretos (Vault, AWS Secrets Manager, GCP Secret Manager).",
            "owasp_api_id": "API2:2023",
            "cwe": "CWE-798",
        },
        # 2. Raw SQL / String concatenation in queries
        {
            "id": "API-DIFF-002",
            "title": "Concatenación de variables en consulta de base de datos (Inyección SQL)",
            "severity": Severity.CRITICAL,
            "category": "Inyección",
            "regex": re.compile(
                r"""(?i)(execute|query|raw|select)\s*\(\s*(f["'].*\{|["'].*\s*\+\s*[a-zA-Z0-9_]+)"""
            ),
            "description": "Se detectó la concatenación de variables en una consulta a base de datos en lugar de utilizar sentencias preparadas.",
            "impact": "Un atacante puede alterar la consulta y extraer, modificar o eliminar registros de la base de datos.",
            "remediation": "Utilizar parámetros parametrizados o bindings de ORM (ej. `query('SELECT * WHERE id = $1', [id])`).",
            "owasp_api_id": "API8:2023",
            "cwe": "CWE-89",
        },
        # 3. Mass Assignment: passing raw request body to ORM create/update
        {
            "id": "API-DIFF-003",
            "title": "Asignación masiva (Mass Assignment) de datos sin filtrar hacia el modelo",
            "severity": Severity.HIGH,
            "category": "Asignación Masiva / BOPLA",
            "regex": re.compile(
                r"""(?i)(\.create|\.update|\.save)\s*\(\s*(req\.body|request\.data|request\.json|\*\*request\.POST)"""
            ),
            "description": "El objeto recibido directamente del cliente HTTP se pasa al método de persistencia sin un esquema DTO o lista blanca de atributos.",
            "impact": "Un atacante puede inyectar campos restringidos como `role='admin'`, `is_verified=true` o `balance=999999`.",
            "remediation": "Usar DTOs o mapear explícitamente solo los campos permitidos: `{ name: req.body.name, email: req.body.email }`.",
            "owasp_api_id": "API3:2023",
            "cwe": "CWE-915",
        },
        # 4. Information Disclosure in Catch / Error Handlers
        {
            "id": "API-DIFF-004",
            "title": "Fuga de stack trace o detalle interno en respuesta de error",
            "severity": Severity.MEDIUM,
            "category": "Mala Configuración de Seguridad",
            "regex": re.compile(
                r"""(?i)(res\.status\(500\)|\.send\(|\.json\()\s*\{?.*(err\.stack|e\.stack|err\.message|str\(e\)|printStackTrace)"""
            ),
            "description": "Se está devolviendo el stack trace o mensaje crudo de la excepción en la respuesta HTTP hacia el cliente.",
            "impact": "Revela información sobre dependencias, rutas internas de archivos, versiones y queries fallidas a posibles atacantes.",
            "remediation": "Registrar el error detallado internamente en logs (`logger.error(err)`) y devolver un mensaje genérico al cliente (`{ error: 'Internal Server Error' }`).",
            "owasp_api_id": "API8:2023",
            "cwe": "CWE-209",
        },
        # 5. Direct ID Lookup (Potential BOLA / IDOR)
        {
            "id": "API-DIFF-005",
            "title": "Consulta directa por ID sin validación aparente de pertenencia o tenant (Alerta BOLA/IDOR)",
            "severity": Severity.HIGH,
            "category": "Autorización Rota a Nivel de Objeto (BOLA)",
            "regex": re.compile(
                r"""(?i)(findById|findByPk|get_object_or_404|objects\.get)\s*\(\s*(id|req\.params\.id|params\[:id\])"""
            ),
            "description": "Se detectó la búsqueda directa de un registro utilizando un ID externo sin combinarlo con el ID de usuario o empresa de la sesión actual.",
            "impact": "Si el endpoint no valida la propiedad del recurso, cualquier usuario autenticado puede acceder a datos de terceros cambiando el ID.",
            "remediation": "Comprobar que el objeto pertenezca al usuario autenticado: `WHERE id = :id AND user_id = :current_user_id` o verificar permisos explícitamente.",
            "owasp_api_id": "API1:2023",
            "cwe": "CWE-639",
        },
        # 6. [AGENT-READY] Insecure Tenant ID extraction from client payload
        {
            "id": "API-AGENT-002",
            "title": "Extracción insegura de tenant_id desde el cuerpo de la petición (Riesgo de Agentes)",
            "severity": Severity.HIGH,
            "category": "Aislamiento Multi-Tenant & Agent Safety",
            "regex": re.compile(
                r"""(?i)(req\.body|request\.data|data|body|payload)(\.get\(['"](tenant_id|org_id|account_id)['"]\)|\[['"](tenant_id|org_id|account_id)['"]\]|\.(tenant_id|org_id|account_id))"""
            ),
            "description": "Se detectó la extracción del identificador de tenant/organización directamente desde los datos enviados por el cliente o agente.",
            "impact": "Un agente autónomo (por alucinación o Prompt Injection) o un atacante puede alterar este valor y acceder o mutar datos de otra empresa.",
            "remediation": "Extraer el tenant_id exclusivamente del token JWT / API Key en el middleware de autenticación (ej: `req.user.tenant_id` o `request.state.tenant_id`).",
            "owasp_api_id": "API1:2023",
            "cwe": "CWE-639",
        },
        # 7. [OWASP API7:2023] SSRF in outgoing HTTP requests
        {
            "id": "API-DIFF-006",
            "title": "Petición HTTP saliente utilizando URL no validada del cliente (Riesgo SSRF)",
            "severity": Severity.HIGH,
            "category": "Server-Side Request Forgery (SSRF)",
            "regex": re.compile(
                r"""(?i)(requests\.(get|post|put|delete)|fetch|axios\.(get|post)|http\.(get|request))\s*\(\s*(req\.body|request\.data|req\.query|params|data|body)(\.get\(['"].*?(url|target|webhook|dest|callback).*?['"]\)|\[['"].*?(url|target|webhook|dest|callback).*?['"]\]|\.[a-zA-Z0-9_]*(url|target|webhook|dest|callback))"""
            ),
            "description": "Se detectó la realización de una petición HTTP hacia una dirección controlada por el usuario sin validación de lista blanca o IP interna.",
            "impact": "Un atacante puede forzar al servidor a acceder a servicios locales (127.0.0.1, localhost) o metadatos de proveedores cloud (169.254.169.254).",
            "remediation": "Validar la URL contra una lista blanca estricta de dominios permitidos y resolver la IP para bloquear rangos privados (RFC 1918).",
            "owasp_api_id": "API7:2023",
            "cwe": "CWE-918",
        },
        # 8. [OWASP API8:2023] OS Command Injection / Dynamic Execution
        {
            "id": "API-DIFF-007",
            "title": "Ejecución de comando del sistema con entrada de usuario (Riesgo RCE)",
            "severity": Severity.CRITICAL,
            "category": "Inyección de Comandos / RCE",
            "regex": re.compile(
                r"""(?i)(subprocess\.(Popen|run|call|check_output)\s*\(.*(req\.|request\.|params|data).*shell\s*=\s*True|subprocess\.(Popen|run|call|check_output)\s*\(.*shell\s*=\s*True.*(req\.|request\.|params|data)|(eval|exec|os\.system)\s*\(\s*.*(req\.|request\.|params|data)|child_process\.exec\s*\(.*(req\.|request\.|params|data))"""
            ),
            "description": "Se detectó la ejecución de comandos del shell o evaluación dinámica de código vinculada a datos recibidos de la petición.",
            "impact": "Ejecución Remota de Código (RCE) y compromiso total del servidor anfitrión o contenedor.",
            "remediation": "Evitar invocaciones de shell (`shell=False`) y usar listas de argumentos sin interpolar cadenas de usuario.",
            "owasp_api_id": "API8:2023",
            "cwe": "CWE-78",
        },
        # 9. [OWASP API8:2023] Permissive CORS with credentials in code
        {
            "id": "API-DIFF-008",
            "title": "CORS permisivo con comodín (Access-Control-Allow-Origin: *)",
            "severity": Severity.HIGH,
            "category": "Mala Configuración de CORS",
            "regex": re.compile(
                r"""(?i)(access-control-allow-origin['"]?\s*[:=,]\s*['"]\*['"]|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\])"""
            ),
            "description": "Se detectó la configuración de origen comodín (*) en el código de endpoints o middleware.",
            "impact": "Permite que cualquier sitio web de terceros realice peticiones a la API o lea respuestas sensibles si no se restringe por origen.",
            "remediation": "Especificar orígenes explícitos en lugar de comodines abiertos para APIs corporativas.",
            "owasp_api_id": "API8:2023",
            "cwe": "CWE-942",
        },
    ]

    def __init__(self, repo_path: str = ".", base_ref: Optional[str] = None):
        self.repo_path = Path(repo_path).resolve()
        self.base_ref = base_ref

    def get_diff_lines(self) -> List[Tuple[str, int, str]]:
        """Extracts modified added lines (+) from git diff along with file path and line number."""
        diff_output = ""
        # Try diff against specified base_ref, or common defaults, or staged/unstaged
        candidates = [self.base_ref] if self.base_ref else ["origin/main", "origin/master", "main", "master", "HEAD~1", None]

        for ref in candidates:
            cmd = ["git", "diff"]
            if ref:
                cmd.append(ref)
            try:
                res = subprocess.run(
                    cmd,
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    diff_output = res.stdout
                    break
            except Exception:
                pass

        if not diff_output:
            # Fallback to local unstaged/staged diff
            try:
                res = subprocess.run(
                    ["git", "diff", "HEAD"],
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                diff_output = res.stdout
            except Exception:
                diff_output = ""

        return self._parse_diff(diff_output)

    def _parse_diff(self, diff_text: str) -> List[Tuple[str, int, str]]:
        """Parses git unified diff into a list of (file_path, line_no, added_line_content)."""
        results = []
        current_file = ""
        current_line = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("@@"):
                # Parse chunk header: @@ -10,4 +25,8 @@
                m = re.search(r"\+(\d+)", line)
                if m:
                    current_line = int(m.group(1))
            elif line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                results.append((current_file, current_line, added_content))
                current_line += 1
            elif not line.startswith("-"):
                current_line += 1

        return results

    def scan_diff(self) -> AuditReport:
        report = AuditReport(
            target=str(self.repo_path),
            mode="diff",
            metadata={"base_ref": self.base_ref or "auto-detected"},
        )

        diff_lines = self.get_diff_lines()
        if not diff_lines:
            report.metadata["note"] = "No se detectaron diferencias activas en git diff."
            return report

        for file_path, line_no, content in diff_lines:
            path_obj = Path(file_path)
            if path_obj.suffix.lower() not in self.ROUTE_EXTENSIONS:
                continue

            for rule in self.PATTERNS:
                if rule["regex"].search(content):
                    report.add_finding(
                        Finding(
                            id=rule["id"],
                            title=rule["title"],
                            severity=rule["severity"],
                            category=rule["category"],
                            location=f"{file_path}:{line_no}",
                            description=rule["description"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            evidence=content.strip(),
                            owasp_api_id=rule.get("owasp_api_id"),
                            cwe=rule.get("cwe"),
                        )
                    )

        return report

    def scan_file(self, file_path: str) -> AuditReport:
        """Direct file scan mode (convenient when analyzing a single file without git diff)."""
        target = Path(file_path).resolve()
        report = AuditReport(target=str(target), mode="diff")

        if not target.exists():
            raise FileNotFoundError(f"File not found: {target}")

        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, line in enumerate(lines, start=1):
            for rule in self.PATTERNS:
                if rule["regex"].search(line):
                    report.add_finding(
                        Finding(
                            id=rule["id"],
                            title=rule["title"],
                            severity=rule["severity"],
                            category=rule["category"],
                            location=f"{target.name}:{idx}",
                            description=rule["description"],
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            evidence=line.strip(),
                            owasp_api_id=rule.get("owasp_api_id"),
                            cwe=rule.get("cwe"),
                        )
                    )

        return report
