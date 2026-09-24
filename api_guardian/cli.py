"""Command Line Interface for API Guardian."""

import argparse
import sys
from pathlib import Path
from api_guardian.core.models import AuditReport, Severity
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
            # Try as spec first, then file
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
