"""Report formatters for API Guardian audits (Console, Markdown, JSON)."""

import json
from pathlib import Path
from typing import Optional
from api_guardian.core.models import AuditReport, Severity


class Reporter:
    @staticmethod
    def format_console(report: AuditReport) -> str:
        lines = []
        divider = "=" * 70
        subdivider = "-" * 70

        lines.append(divider)
        lines.append(f"  🛡️  API GUARDIAN - AUDIT REPORT")
        lines.append(divider)
        lines.append(f"🎯 Objetivo : {report.target}")
        lines.append(f"⚙️  Modo     : {report.mode.upper()}")
        lines.append(f"📅 Fecha    : {report.timestamp}")
        lines.append(subdivider)

        counts = report.counts
        summary_str = " | ".join(
            f"{Severity(s).emoji} {s}: {counts[s]}" for s in counts
        )
        lines.append(f"📊 Resumen  : {summary_str}")
        lines.append(divider)

        if not report.findings:
            lines.append("✅ ¡Felicitaciones! No se detectaron vulnerabilidades ni fallos de configuración.")
            lines.append(divider)
            return "\n".join(lines)

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            report.findings, key=lambda f: severity_order.get(f.severity, 99)
        )

        for i, finding in enumerate(sorted_findings, start=1):
            lines.append("")
            lines.append(f"[{i}] {finding.severity.emoji} [{finding.severity.value}] {finding.title}")
            lines.append(f"    ID       : {finding.id} (OWASP: {finding.owasp_api_id or 'N/A'})")
            lines.append(f"    Ubicación: {finding.location}")
            lines.append(f"    Categoría: {finding.category}")
            lines.append(f"    Detalle  : {finding.description}")
            lines.append(f"    Impacto  : {finding.impact}")
            if finding.evidence:
                lines.append(f"    Evidencia: {finding.evidence}")
            lines.append(f"    🛠️ Fix   : {finding.remediation.replace(chr(10), chr(10) + '               ')}")
            lines.append(subdivider)

        return "\n".join(lines)

    @staticmethod
    def format_markdown(report: AuditReport) -> str:
        lines = []
        lines.append(f"# 🛡️ Reporte de Auditoría de API - API Guardian")
        lines.append("")
        lines.append(f"**Objetivo:** `{report.target}`  ")
        lines.append(f"**Modo de Análisis:** `{report.mode.upper()}`  ")
        lines.append(f"**Fecha y Hora:** `{report.timestamp}`  ")
        lines.append("")

        counts = report.counts
        lines.append("## 📊 Resumen Ejecutivo")
        lines.append("")
        lines.append("| Severidad | Hallazgos | Estado |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| 🛑 **Crítica** | `{counts['CRITICAL']}` | {'⚠️ Atención inmediata requerida' if counts['CRITICAL'] > 0 else '✅ Limpio'} |")
        lines.append(f"| 🔴 **Alta** | `{counts['HIGH']}` | {'⚠️ Mitigar antes de producción' if counts['HIGH'] > 0 else '✅ Limpio'} |")
        lines.append(f"| 🟡 **Media** | `{counts['MEDIUM']}` | {'Revisar en sprint' if counts['MEDIUM'] > 0 else '✅ Limpio'} |")
        lines.append(f"| 🔵 **Baja** | `{counts['LOW']}` | Mejora preventiva |")
        lines.append(f"| ℹ️ **Informativa** | `{counts['INFO']}` | Best practices |")
        lines.append("")

        if not report.findings:
            lines.append("> [!TIP]\n> No se encontraron incidencias de seguridad en el alcance analizado.")
            return "\n".join(lines)

        lines.append("## 🔍 Detalle de Hallazgos y Remediaciones")
        lines.append("")

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            report.findings, key=lambda f: severity_order.get(f.severity, 99)
        )

        for finding in sorted_findings:
            alert_type = "CAUTION" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "WARNING" if finding.severity == Severity.MEDIUM else "NOTE"
            lines.append(f"### {finding.severity.emoji} [{finding.severity.value}] {finding.title} (`{finding.id}`)")
            lines.append("")
            lines.append(f"- **Ubicación:** `{finding.location}`")
            lines.append(f"- **Categoría:** {finding.category} ({finding.owasp_api_id or 'General'})")
            if finding.cwe:
                lines.append(f"- **CWE:** {finding.cwe}")
            lines.append("")
            lines.append(f"> [!{alert_type}]\n> **Descripción:** {finding.description}\n>\n> **Impacto:** {finding.impact}")
            lines.append("")

            if finding.evidence:
                lines.append("**Evidencia detectada:**")
                lines.append("```text")
                lines.append(finding.evidence)
                lines.append("```")
                lines.append("")

            lines.append("**🛠️ Remediación recomendada:**")
            lines.append(finding.remediation)
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def format_json(report: AuditReport) -> str:
        data = {
            "target": report.target,
            "mode": report.mode,
            "timestamp": report.timestamp,
            "summary": report.counts,
            "total_findings": report.total,
            "max_severity": report.max_severity.value if report.max_severity else None,
            "metadata": report.metadata,
            "findings": [f.to_dict() for f in report.findings],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    @classmethod
    def save(
        cls,
        report: AuditReport,
        output_dir: str = "reports",
        filename_prefix: Optional[str] = None,
    ) -> dict:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        prefix = filename_prefix or f"audit_{report.mode}"
        clean_prefix = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in prefix)

        md_file = out_path / f"{clean_prefix}.md"
        json_file = out_path / f"{clean_prefix}.json"

        md_file.write_text(cls.format_markdown(report), encoding="utf-8")
        json_file.write_text(cls.format_json(report), encoding="utf-8")

        return {"markdown": str(md_file), "json": str(json_file)}
