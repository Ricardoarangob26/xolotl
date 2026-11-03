---
name: appsec-audit
description: Auditoría de seguridad de un aplicativo con el MCP Xolotl (Semgrep, Bandit, CodeQL, OSV-Scanner, Trivy, Gitleaks). Úsala cuando pidan auditar, escanear o revisar la seguridad de un repositorio, buscar vulnerabilidades en el código, dependencias vulnerables o con CVE, secretos o credenciales filtradas, revisar Dockerfiles, Kubernetes o Terraform, o escanear una imagen de contenedor.
---

# Auditoría de seguridad estática

Herramientas del servidor MCP `xolotl` (en Claude Code aparecen como `mcp__xolotl__<nombre>` o `mcp__plugin_xolotl_xolotl__<nombre>`).

## 1. Preparar

1. `xolotl_doctor` — qué escáneres hay. Si falta alguno que la auditoría necesita, ofrécele al usuario `xolotl_install` (descarga binarios oficiales con verificación SHA-256). No instales sin preguntar: son descargas de cientos de MB.
2. Identifica el proyecto: lenguajes, gestor de dependencias (lockfiles), si hay `.git`, Dockerfile, manifiestos K8s o Terraform. Eso decide qué escáneres valen la pena.

## 2. Escanear

| Necesidad | Herramienta | Notas |
|---|---|---|
| Panorama completo del repo | `scan_static` | Semgrep + Bandit (si hay Python) + OSV + Trivy (vuln, secret, misconfig) + Gitleaks. Es el punto de partida. |
| Reglas específicas del stack | `scan_static` con `semgrep_configs` | p. ej. `["p/default","p/owasp-top-ten","p/typescript","p/react","p/nextjs"]`, `["p/python","p/django"]`, `["p/java","p/spring"]`. Reglas propias: ruta a un .yml. |
| Confirmar inyecciones que cruzan archivos | `scan_codeql` | Lento (minutos a una hora). Úsalo en proyectos críticos o cuando Semgrep deja dudas de flujo de datos. TypeScript → `language: "typescript"`. |
| Imagen publicada | `scan_container_image` | Paquetes del SO + secretos dentro de la imagen. |
| Solo infraestructura | `scan_iac` | Dockerfile, compose, K8s, Helm, Terraform, CloudFormation. |

- Gitleaks en modo `auto` revisa **todo el historial de git**: un secreto borrado hace meses sigue siendo un hallazgo real.
- Los resultados de todas las herramientas se deduplican (misma CVE de Trivy y OSV → un hallazgo con ambas herramientas).
- Un escáner en estado `error` o `skipped` es un hueco en la cobertura: dilo en el informe, no lo ocultes.

## 3. Revisar

No entregues la lista cruda: la mayoría del valor está en el triage. Sigue la skill **appsec-triage**:
`findings_query` (min_severity high primero) → `finding_get` para leer el código → `finding_triage` con justificación.

## 4. Entregar

- `report_generate` en `md` para leer, `html` para compartir, `sarif` para subir a GitHub/GitLab code scanning o abrir en VS Code (extensión SARIF Viewer).
- En la respuesta al usuario: cuántos hallazgos reales quedaron por severidad, los 3–5 que hay que atender primero con su arreglo concreto, qué se descartó y por qué, y qué no se pudo cubrir.
- Para corregir, sigue la skill **appsec-fix**.
