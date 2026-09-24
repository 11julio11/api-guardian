# Playbook Empresarial: Integración de API Guardian en CI/CD y Monorrepositorios

Este documento describe la arquitectura de despliegue de **API Guardian** en organizaciones con múltiples equipos, microservicios o grandes monorrepositorios.

---

## 🏗️ Estrategia en Grandes Repositorios (Escalabilidad)

En bases de código con más de 100,000 líneas de código:
1. **No ejecutes análisis de árbol completo en cada commit**: Utiliza el modo `diff`:
   ```bash
   python3 -m api_guardian diff --base origin/main --fail-on high
   ```
2. **Filtrado por tipo de archivo**: El módulo ignora automáticamente archivos de tests unitarios, documentación y configuraciones, auditando únicamente routers, controladores y middlewares (`.ts`, `.py`, `.java`, `.go`, `.cs`).

---

## 🔄 Integración en GitHub Actions (Workflow de Pull Request)

Crea `.github/workflows/api-guardian.yml` en el repositorio:

```yaml
name: API Guardian Security Gate

on:
  pull_request:
    branches: [ main, develop ]
    paths:
      - '**/controllers/**'
      - '**/routes/**'
      - '**/api/**'
      - '**/*openapi*'
      - '**/*swagger*'

jobs:
  api-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout del código
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Necesario para git diff contra la rama base

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Ejecutar Auditoría Diferencial de APIs
        run: |
          python3 -m api_guardian diff --base origin/${{ github.base_ref }} --format markdown --save --fail-on high

      - name: Publicar Resumen de Seguridad en el PR
        if: always()
        run: |
          if [ -f reports/audit_diff.md ]; then
            cat reports/audit_diff.md >> $GITHUB_STEP_SUMMARY
          fi
```

---

## 🪝 Hook de Pre-commit para Desarrolladores

Para evitar que los desarrolladores envíen código con fallos de BOLA o credenciales a la rama remota, se puede configurar un hook local en `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
echo "🛡️ Ejecutando API Guardian pre-commit check..."
python3 -m api_guardian diff --fail-on critical
if [ $? -ne 0 ]; then
  echo "❌ Se detectaron fallos críticos de seguridad en los endpoints modificados."
  echo "Corrige los hallazgos antes de hacer commit."
  exit 1
fi
```
