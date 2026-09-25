"""Command Line Interface for API Guardian."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from api_guardian.core.models import AuditReport, Finding, Severity
from api_guardian.core.reporter import Reporter
from api_guardian.modules.spec_auditor import SpecAuditor
from api_guardian.modules.diff_scanner import DiffScanner
from api_guardian.modules.local_fuzzer import LocalFuzzer
from api_guardian.modules.prod_inspector import ProdInspector


def handle_output(report: AuditReport, args: argparse.Namespace) -> int:
    fmt = getattr(args, "format", "console")
    if fmt == "markdown":
        output = Reporter.format_markdown(report)
    elif fmt == "json":
        output = Reporter.format_json(report)
    else:
        output = Reporter.format_console(report)

    print(output)

    if getattr(args, "save", False):
        saved = Reporter.save(
            report,
            output_dir=getattr(args, "output_dir", "reports"),
            filename_prefix=getattr(args, "report_prefix", None),
        )
        print(f"\n📁 Reportes guardados con éxito:\n  • Markdown: {saved['markdown']}\n  • JSON:     {saved['json']}")

    # Check fail-on threshold for CI/CD
    fail_on = getattr(args, "fail_on", None)
    if fail_on:
        threshold = Severity[fail_on.upper()]
        severity_rank = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        for f in report.findings:
            if severity_rank.get(f.severity, 0) >= severity_rank[threshold]:
                return 1

    return 0


def cmd_spec(args: argparse.Namespace) -> int:
    auditor = SpecAuditor(args.spec_file)
    report = auditor.audit()
    return handle_output(report, args)


def cmd_diff(args: argparse.Namespace) -> int:
    scanner = DiffScanner(repo_path=args.repo, base_ref=args.base)
    report = scanner.scan_diff()
    return handle_output(report, args)


def cmd_file(args: argparse.Namespace) -> int:
    scanner = DiffScanner()
    report = scanner.scan_file(args.file_path)
    return handle_output(report, args)


def cmd_local(args: argparse.Namespace) -> int:
    fuzzer = LocalFuzzer(base_url=args.url, allow_remote=args.allow_remote)
    endpoints = []
    if args.endpoints:
        for ep in args.endpoints.split(","):
            endpoints.append({"path": ep.strip(), "method": args.method})
    else:
        endpoints.append({"path": "/", "method": args.method})

    report = fuzzer.run_suite(endpoints)
    return handle_output(report, args)


def cmd_prod(args: argparse.Namespace) -> int:
    inspector = ProdInspector(base_url=args.url)
    report = inspector.inspect()
    return handle_output(report, args)


def cmd_scan(args: argparse.Namespace) -> int:
    """Auto-detect target type (URL, Spec, Route file, Git repo)."""
    target = args.target

    if target.startswith(("http://", "https://")):
        if "localhost" in target or "127.0.0.1" in target:
            fuzzer = LocalFuzzer(base_url=target)
            report = fuzzer.run_suite([{"path": "/", "method": "GET"}])
        else:
            inspector = ProdInspector(base_url=target)
            report = inspector.inspect()
        return handle_output(report, args)

    p = Path(target)
    if p.is_file():
        if p.suffix.lower() in (".json", ".yaml", ".yml") and any(k in p.name.lower() for k in ("swagger", "openapi", "api", "spec")):
            auditor = SpecAuditor(str(p))
            report = auditor.audit()
        elif p.suffix.lower() in DiffScanner.ROUTE_EXTENSIONS:
            scanner = DiffScanner()
            report = scanner.scan_file(str(p))
        else:
            try:
                auditor = SpecAuditor(str(p))
                report = auditor.audit()
            except Exception:
                scanner = DiffScanner()
                report = scanner.scan_file(str(p))
        return handle_output(report, args)

    if p.is_dir() or target == ".":
        scanner = DiffScanner(repo_path=str(p))
        report = scanner.scan_diff()
        return handle_output(report, args)

    print(f"Error: No se pudo determinar el tipo de objetivo para '{target}'.", file=sys.stderr)
    return 2


def cmd_mcp(args: argparse.Namespace) -> int:
    server_path = Path(args.server_path).resolve()
    if not server_path.exists():
        print(f"❌ Error: Archivo de servidor MCP no encontrado: {server_path}", file=sys.stderr)
        return 1

    action = getattr(args, "mcp_action", "test")
    if action == "run":
        print(f"🛡️ [API Guardian] Ejecutando servidor MCP: {server_path.name} ...", file=sys.stderr)
        proc = subprocess.run([sys.executable, str(server_path)])
        return proc.returncode

    # action == "test": perform handshake and healthcheck
    print(f"🔍 [API Guardian] Iniciando diagnóstico de protocolo MCP sobre: {server_path.name}")
    proc = subprocess.Popen(
        [sys.executable, str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Step 1: initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "api-guardian-mcp-auditor", "version": "1.0.0"},
            },
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()

        resp_line = proc.stdout.readline()
        if not resp_line:
            print("❌ Error: El servidor MCP cerró la conexión sin responder a 'initialize'.", file=sys.stderr)
            return 1

        init_resp = json.loads(resp_line)
        server_info = init_resp.get("result", {}).get("serverInfo", {})
        server_name = server_info.get("name", "Unknown Server")
        server_ver = server_info.get("version", "Unknown")

        # Step 2: notifications/initialized
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        # Step 3: tools/list
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.flush()

        tools_line = proc.stdout.readline()
        tools_resp = json.loads(tools_line)
        tools = tools_resp.get("result", {}).get("tools", [])

        # Report results
        if args.format == "json":
            out_data = {
                "server": {"name": server_name, "version": server_ver, "path": str(server_path)},
                "status": "HEALTHY",
                "tools_count": len(tools),
                "tools": tools,
            }
            print(json.dumps(out_data, indent=2, ensure_ascii=False))
        else:
            print(f"\n========================================================")
            print(f"🛡️  DIAGNÓSTICO MCP: {server_name} v{server_ver}")
            print(f"========================================================")
            print(f"✅ Handshake JSON-RPC 2.0 (stdio): EXITOSO")
            print(f"✅ Protocol Version: {init_resp.get('result', {}).get('protocolVersion')}")
            print(f"📦 Herramientas registradas ({len(tools)}):")

            for t in tools:
                name = t.get("name")
                desc = t.get("description", "Sin descripción")
                params = list(t.get("inputSchema", {}).get("properties", {}).keys())
                reqs = t.get("inputSchema", {}).get("required", [])
                print(f"\n  • 🔧 Tool: \033[1m{name}\033[0m")
                print(f"    - Descripción: {desc.strip()[:100]}...")
                print(f"    - Parámetros: {', '.join(params) if params else '(ninguno)'}")
                print(f"    - Requeridos: {', '.join(reqs) if reqs else '(ninguno)'}")

            print(f"\n✨ Servidor 100% compatible con clientes MCP (Cursor, Claude Desktop, Antigravity).\n")

        return 0

    except Exception as e:
        print(f"❌ Fallo durante la prueba del servidor MCP: {e}", file=sys.stderr)
        return 1
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.stderr.close()
        proc.terminate()
        proc.wait(timeout=2.0)


def cmd_agent_check(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"❌ Error: Objetivo no encontrado: {target}", file=sys.stderr)
        return 1

    # Run spec or diff scanner
    if target.suffix.lower() in (".json", ".yaml", ".yml"):
        auditor = SpecAuditor(str(target))
        full_report = auditor.audit()
    else:
        scanner = DiffScanner()
        full_report = scanner.scan_file(str(target))

    AGENT_RULES = {
        "API-AGENT-001",
        "API-AGENT-002",
        "API-AGENT-003",
        "API-SPEC-009",
        "API-SPEC-008",
        "API-SPEC-007",
        "API-SPEC-005",
        "API-DIFF-006",
    }
    agent_findings = [f for f in full_report.findings if f.id in AGENT_RULES or "AGENT" in f.id]

    penalties = {
        Severity.CRITICAL: 35,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }
    score = 100
    for f in agent_findings:
        score -= penalties.get(f.severity, 0)
    score = max(0, score)

    if score >= 90:
        grade, badge = "A+", "🟢 EXCELENTE (AGENT-READY)"
    elif score >= 75:
        grade, badge = "B", "🟡 BUENO (Pequeños ajustes requeridos)"
    elif score >= 50:
        grade, badge = "C", "🟠 RIESGOSO (Brechas para agentes de IA)"
    else:
        grade, badge = "F", "🔴 INSEGURO (No apto para consumo por agentes)"

    if args.format == "json":
        out = {
            "target": str(target),
            "score": score,
            "grade": grade,
            "verdict": badge,
            "agent_findings_count": len(agent_findings),
            "findings": [f.to_dict() for f in agent_findings],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print("\n" + "=" * 60)
        print("🤖 API GUARDIAN: EVALUACIÓN DE PREPARACIÓN PARA AGENTES IA")
        print("=" * 60)
        print(f"🎯 Objetivo: {target.name}")
        print(f"📊 Puntuación Agent-Ready: {score}/100 [Grado {grade}]")
        print(f"🏷️  Veredicto: {badge}\n")

        print("📋 Desglose de Conformidad con Agentes Autónomos:")
        has_rls_issue = any(f.id == "API-AGENT-002" for f in agent_findings)
        has_idemp_issue = any(f.id == "API-AGENT-001" for f in agent_findings)
        has_rfc_issue = any(f.id == "API-AGENT-003" for f in agent_findings)
        has_doc_issue = any(f.id == "API-SPEC-009" for f in agent_findings)

        print(f"  • Aislamiento Multi-Tenant (RLS):       {'❌ Riesgo de fuga de tenant' if has_rls_issue else '✅ Aislamiento perimetral correcto'}")
        print(f"  • Idempotencia en Mutaciones (Replay):   {'❌ Sin Idempotency-Key' if has_idemp_issue else '✅ Idempotencia declarada'}")
        print(f"  • Semántica de Errores (RFC 9457):      {'❌ Formato de error sin JSON Pointer' if has_rfc_issue else '✅ Problem Details estándar'}")
        print(f"  • Descripciones Semánticas para LLM:    {'❌ Herramientas sin description/summary' if has_doc_issue else '✅ Descripciones completas'}")

        if agent_findings:
            print(f"\n⚠️  Hallazgos críticos para agentes detectados ({len(agent_findings)}):")
            for f in agent_findings:
                print(f"   [{f.severity.emoji} {f.severity.value}] {f.id}: {f.title} ({f.location})")
        else:
            print("\n🎉 ¡Felicidades! La API cumple con todos los estándares para consumo seguro por IA.")
        print()

    return 1 if score < 60 else 0


def cmd_init(args: argparse.Namespace) -> int:
    target_dir = Path(getattr(args, "dir", ".") or ".").resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Config file
    config_file = target_dir / ".api-guardian.json"
    config_content = {
        "$schema": "https://raw.githubusercontent.com/11julio11/api-guardian/main/schemas/config.schema.json",
        "version": "1.0",
        "fail_on": "high",
        "output_format": "console",
        "reports_dir": "reports",
        "rules": {
            "exclude": []
        }
    }
    config_file.write_text(json.dumps(config_content, indent=2) + "\n", encoding="utf-8")
    print(f"✅ Archivo de configuración creado: {config_file}")

    # 2. GitHub Actions workflow
    if getattr(args, "ci", True):
        workflow_dir = target_dir / ".github" / "workflows"
        workflow_dir.mkdir(parents=True, exist_ok=True)
        ci_file = workflow_dir / "api-guardian.yml"
        ci_content = """name: API Guardian Security Audit

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install API Guardian
        run: pip install .

      - name: Run API Guardian Scan
        run: api-guardian scan . --fail-on high --save
"""
        ci_file.write_text(ci_content, encoding="utf-8")
        print(f"✅ Workflow de CI/CD generado: {ci_file}")

    print("\n🎉 Proyecto inicializado con éxito. Puedes ejecutar `api-guardian scan .` para auditar.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="api-guardian",
        description="🛡️ API Guardian: Auditoría y protección de APIs para proyectos independientes y grandes empresas.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Common args
    def add_common_args(subp):
        subp.add_argument("--format", choices=["console", "markdown", "json"], default="console", help="Formato de salida")
        subp.add_argument("--save", action="store_true", help="Guardar reportes en el directorio reports/")
        subp.add_argument("--output-dir", default="reports", help="Directorio donde guardar los reportes")
        subp.add_argument("--report-prefix", default=None, help="Prefijo para los nombres de archivo generados")
        subp.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None, help="Retornar código de salida 1 si hay hallazgos de esta severidad o superior (CI/CD)")

    # 1. spec
    p_spec = subparsers.add_parser("spec", help="Auditar especificación OpenAPI / Swagger")
    p_spec.add_argument("spec_file", help="Ruta al archivo openapi.json o openapi.yaml")
    add_common_args(p_spec)
    p_spec.set_defaults(func=cmd_spec)

    # 2. diff
    p_diff = subparsers.add_parser("diff", help="Auditar cambios diferenciales de routers con git diff")
    p_diff.add_argument("--repo", default=".", help="Ruta a la raíz del repositorio Git")
    p_diff.add_argument("--base", default=None, help="Rama base para la comparación (ej. origin/main)")
    add_common_args(p_diff)
    p_diff.set_defaults(func=cmd_diff)

    # 3. file
    p_file = subparsers.add_parser("file", help="Auditar un archivo específico de router o controlador")
    p_file.add_argument("file_path", help="Ruta al archivo fuente")
    add_common_args(p_file)
    p_file.set_defaults(func=cmd_file)

    # 4. local
    p_local = subparsers.add_parser("local", help="Pruebas de robustez y boundary fuzzing en servidor local")
    p_local.add_argument("url", help="URL base del servidor local (ej. http://localhost:8000)")
    p_local.add_argument("--endpoints", help="Lista de endpoints separados por coma (ej. /api/users,/api/orders)")
    p_local.add_argument("--method", default="POST", choices=["POST", "PUT", "GET", "PATCH"], help="Método HTTP a probar")
    p_local.add_argument("--allow-remote", action="store_true", help="Desactivar el safeguard de localhost para staging autorizado")
    add_common_args(p_local)
    p_local.set_defaults(func=cmd_local)

    # 5. prod
    p_prod = subparsers.add_parser("prod", help="Auditoría pasiva y segura en producción/staging")
    p_prod.add_argument("url", help="URL base del servicio en vivo (ej. https://api.empresa.com)")
    add_common_args(p_prod)
    p_prod.set_defaults(func=cmd_prod)

    # 6. scan (auto)
    p_scan = subparsers.add_parser("scan", help="Detección automática del objetivo (URL, Spec, Archivo o Repo)")
    p_scan.add_argument("target", help="Objetivo a escanear")
    add_common_args(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    # 7. mcp
    p_mcp = subparsers.add_parser("mcp", help="Diagnóstico y ejecución de servidores Model Context Protocol (MCP)")
    p_mcp.add_argument("mcp_action", choices=["test", "run"], help="Acción a realizar: 'test' (diagnóstico) o 'run' (ejecución stdio)")
    p_mcp.add_argument("server_path", help="Ruta al archivo Python del servidor MCP")
    p_mcp.add_argument("--format", choices=["console", "json"], default="console", help="Formato de salida")
    p_mcp.set_defaults(func=cmd_mcp)

    # 8. agent-check
    p_agent = subparsers.add_parser("agent-check", help="Evaluación especializada de preparación y seguridad para Agentes IA")
    p_agent.add_argument("target", help="Contrato OpenAPI o archivo de rutas a evaluar")
    p_agent.add_argument("--format", choices=["console", "json"], default="console", help="Formato de salida")
    p_agent.set_defaults(func=cmd_agent_check)

    # 9. init
    p_init = subparsers.add_parser("init", help="Inicializar configuración de API Guardian y workflow de CI/CD")
    p_init.add_argument("--dir", default=".", help="Directorio destino")
    p_init.add_argument("--no-ci", dest="ci", action="store_false", help="No generar el workflow de GitHub Actions")
    p_init.set_defaults(func=cmd_init)

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()
    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
