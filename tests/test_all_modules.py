"""Comprehensive unit test suite for API Guardian."""

import json
import unittest
from pathlib import Path
from api_guardian.core.models import AuditReport, Finding, Severity
from api_guardian.core.reporter import Reporter
from api_guardian.modules.spec_auditor import SpecAuditor
from api_guardian.modules.diff_scanner import DiffScanner
from api_guardian.modules.local_fuzzer import LocalFuzzer


class TestApiGuardian(unittest.TestCase):

    def setUp(self):
        self.base_dir = Path(__file__).parent

    def test_spec_auditor(self):
        spec_file = self.base_dir / "sample_openapi.json"
        auditor = SpecAuditor(str(spec_file))
        report = auditor.audit()

        self.assertEqual(report.mode, "spec")
        self.assertGreater(len(report.findings), 0)

        finding_ids = {f.id for f in report.findings}
        # API-SPEC-001 (Insecure HTTP server)
        self.assertIn("API-SPEC-001", finding_ids)
        # API-SPEC-002 (Missing global security)
        self.assertIn("API-SPEC-002", finding_ids)
        # API-SPEC-003 (Unauthenticated POST mutation)
        self.assertIn("API-SPEC-003", finding_ids)
        # API-SPEC-004 (Token in query)
        self.assertIn("API-SPEC-004", finding_ids)
        # API-SPEC-005 (Array collection without pagination)
        self.assertIn("API-SPEC-005", finding_ids)
        # API-SPEC-006 (Role in request body - Mass assignment)
        self.assertIn("API-SPEC-006", finding_ids)
        # API-AGENT-001 (Missing Idempotency-Key in mutating operation)
        self.assertIn("API-AGENT-001", finding_ids)

    def test_diff_scanner_file(self):
        sample_file = self.base_dir / "sample_routes.py"
        scanner = DiffScanner()
        report = scanner.scan_file(str(sample_file))

        self.assertEqual(report.mode, "diff")
        self.assertGreater(len(report.findings), 0)

        finding_ids = {f.id for f in report.findings}
        self.assertIn("API-DIFF-001", finding_ids)  # Hardcoded secret
        self.assertIn("API-DIFF-002", finding_ids)  # Raw SQL
        self.assertIn("API-DIFF-003", finding_ids)  # Mass assignment
        self.assertIn("API-DIFF-004", finding_ids)  # Stack disclosure
        self.assertIn("API-DIFF-005", finding_ids)  # BOLA ID lookup
        self.assertIn("API-AGENT-002", finding_ids) # Insecure tenant_id extraction

    def test_local_fuzzer_safeguard(self):
        # Must refuse public internet domains without --allow-remote
        with self.assertRaises(ValueError):
            LocalFuzzer(base_url="https://production-bank.com", allow_remote=False)

        # Must accept localhost
        fuzzer = LocalFuzzer(base_url="http://localhost:8080", allow_remote=False)
        self.assertEqual(fuzzer.base_url, "http://localhost:8080")

    def test_reporter_formatting(self):
        report = AuditReport(target="test_target", mode="spec")
        report.add_finding(
            Finding(
                id="TEST-001",
                title="Prueba de hallazgo",
                severity=Severity.HIGH,
                category="Autenticación",
                location="POST /test",
                description="Descripción de prueba",
                impact="Impacto de prueba",
                remediation="Solución recomendada",
            )
        )

        console_out = Reporter.format_console(report)
        self.assertIn("API GUARDIAN", console_out)
        self.assertIn("TEST-001", console_out)

        md_out = Reporter.format_markdown(report)
        self.assertIn("# 🛡️ Reporte de Auditoría", md_out)
        self.assertIn("Prueba de hallazgo", md_out)

        json_out = Reporter.format_json(report)
        parsed = json.loads(json_out)
        self.assertEqual(parsed["target"], "test_target")
        self.assertEqual(parsed["summary"]["HIGH"], 1)


if __name__ == "__main__":
    unittest.main()
