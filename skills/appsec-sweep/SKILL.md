---
name: appsec-sweep
description: Orquestar una auditoría de seguridad completa de un sistema o de todo el ecosistema con el MCP Xolotl, y consolidar el resultado en un informe transversal. Úsala cuando pidan "auditar todo", "una auditoría completa", "un barrido de seguridad", "el estado de seguridad de la infraestructura", "un informe ejecutivo del ecosistema", o cuando haya que combinar varias fuentes (código, host, red, BD, AD, Kubernetes, nube) en una sola foto. Decide qué correr y cómo se consolida; usa las skills de cada dominio para el detalle. Nivel de acceso: transversal.
model: haiku
---

<!-- model: asesoría ligera (orquesta skills y tools ya existentes; no razona sobre código). -->

# Barrido de seguridad y consolidación

Xolotl cubre varios dominios con el mismo flujo de solo lectura (Tier 1: corres y traes el
resultado; Tier 2: ejecuta con aprobación). Esta skill los **orquesta** y **consolida** el
resultado. El trabajo pesado lo hacen los motores y las skills de cada dominio.

## 1. Barrido por dominio

Según lo que tengas, corre lo que aplique (cada uno alimenta el mismo inventario):

| Dominio | Tool | Skill | Acceso |
|---|---|---|---|
| Código (SAST/SCA/secretos/IaC) | `scan_static`, `scan_codeql`, `scan_iac` | *appsec-audit* | 📄 código |
| Imagen de contenedor | `scan_container_image` | *appsec-audit* | imagen |
| Red sin credenciales | `scan_network` | *appsec-network* | 🌑 red |
| Servidor Linux | `scan_host` + `scan_lynis` | *appsec-hosts* | 🌓/🌕 |
| Base de datos | `scan_db` (PostgreSQL, MySQL) | *appsec-database* | 🌓 lectura |
| Active Directory | `scan_ad` | *appsec-ad* | 🌓 lectura del dominio |
| Kubernetes | `scan_k8s` | *appsec-k8s* | 🌓 lectura del clúster |
| Nube | `scan_cloud` (Azure/Prowler, OCI/CIS) | *appsec-cloud* | 🌓 identidad RO |
| Aplicación en ejecución | `scan_dast` | *appsec-dast* | alcance autorizado |

`eval_plan` te dice, por activo, qué falta; `inventory view=next` muestra la cobertura.

## 2. Priorizar y clasificar

- Fija la **criticidad de negocio** de los activos con `asset_criticality` y baja los feeds de
  riesgo con `risk_feeds` (EPSS/CISA KEV) para que la prioridad sea real.
- Haz **triage** con memoria (*appsec-triage*): descarta falsos positivos, acepta riesgos con
  justificación. Se recuerda por huella entre corridas.

## 3. Consolidar en un informe del ecosistema

Todo lo escaneado vive en un solo inventario. Para la foto completa:

- **`report_generate scope=inventory`** — informe transversal de **todos** los activos: resumen
  ejecutivo (postura, explotabilidad real, lo más urgente), prioridad por riesgo, **cobertura
  MITRE ATT&CK** por táctica y **brechas de cumplimiento** por marco (OWASP/PCI/NIST/ISO/CIS).
  En `md`, `html`, `sarif` o `json`.
- `inventory view=summary` / `view=assets` para el panorama rápido; `view=next` para lo que falta.

## 4. Traspasar

- `handoff action=export` empaqueta alcance, triage, criticidad, inventario, corridas y el plan de
  compromiso para retomar en otra máquina o sesión.

## El bucle

Escanea → prioriza → documenta → arregla → **`revalidate`** (veredicto de 3 estados) y `runs_diff`
para confirmar que se cerró sin regresión → vuelve a consolidar. La validación ofensiva (Fase 5,
vía roja) es el cierre, solo sobre activos ya endurecidos y bajo el plan de compromiso.

## Qué NO hace

- No inventa cobertura: solo consolida lo que de verdad escaneaste. Un activo sin escanear no está.
- No ejecuta por su cuenta las partes que tocan sistemas vivos: respeta Tier 1/Tier 2 y el alcance.
