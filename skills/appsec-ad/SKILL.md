---
name: appsec-ad
description: Evaluar la postura de seguridad de un dominio de Active Directory con el MCP Xolotl, usando el tool scan_ad y una cuenta de SOLO LECTURA (al estilo PingCastle). Úsala cuando pidan auditar o endurecer Active Directory, revisar la política de contraseñas del dominio, cuentas privilegiadas (Domain/Enterprise Admins), delegación, Kerberoasting/AS-REP, antigüedad de krbtgt, MachineAccountQuota o cuentas inactivas. Sin conexión propia: entrega un script PowerShell de solo lectura para correrlo a mano y parsea la salida. Nivel de acceso: usuario de lectura del dominio.
---

# Postura de Active Directory

`scan_ad` evalúa cómo está **configurado** un dominio (no ataca ni toca nada), al estilo
PingCastle. No se conecta ni instala módulos: entrega un script PowerShell de **solo lectura**
(`Get-AD*`, `Search-ADAccount`) que calcula métricas del dominio; tú lo corres con una cuenta de
lectura y traes la salida, y Xolotl la parsea a hallazgos aplicando umbrales.

## El flujo (Tier 1, tu MobaXterm)

1. `scan_ad` (sin más) devuelve `ad-collect.ps1` y el comando. Requiere el módulo ActiveDirectory
   (RSAT) y una cuenta con lectura del dominio (un usuario normal suele bastar). No cambia nada.
2. En un equipo unido al dominio:
   `powershell -ExecutionPolicy Bypass -File ad-collect.ps1 | Out-File -Encoding utf8 ad-audit.txt`
3. `scan_ad collected_file=<ruta>` lo parsea a hallazgos.

## Qué comprueba

| Área | Hallazgos |
|---|---|
| Política de contraseñas | longitud mínima < 8 (alto) o < 14 (medio) vs NIST/CIS; cifrado reversible (alto); sin bloqueo de cuentas (medio); historial corto y sin complejidad (bajo) |
| Kerberos | krbtgt sin rotar (alto/medio, Golden Ticket); delegación sin restricción (alto); AS-REP roastable (alto); cuentas con SPN / Kerberoastable (medio) |
| Exposición | `ms-DS-MachineAccountQuota > 0` (medio, habilita RBCD) |
| Cuentas privilegiadas | demasiados Domain Admins (medio/bajo); Enterprise Admins > 1 (bajo); privilegiadas sin expiración (bajo) |
| Higiene | cuentas habilitadas e inactivas 90+ días (bajo) |

Los hallazgos Kerberos se mapean a MITRE ATT&CK (T1558: Golden Ticket, Kerberoasting, AS-REP
Roasting), así que alimentan la ingeniería de detección de la vía púrpura.

## Sobre NIST 800-63B

La política se evalúa con criterio moderno: se favorece la **longitud** y el **cribado de
contraseñas filtradas** sobre las reglas de composición y la rotación forzada. La complejidad se
marca como aviso bajo (CIS la pide; NIST permite compensarla con longitud).

## Relación con el resto

- Los hallazgos son de categoría **config**: heredan cumplimiento, riesgo, inventario,
  revalidación e informes, y (Kerberos) el mapeo a ATT&CK.
- Es **postura de solo lectura** (vía azul). La validación ofensiva de AD (Kerberoasting real,
  etc.) es Fase 5 (vía roja), bajo el candado del plan de compromiso.

## Límites

- Mide métricas agregadas del dominio; no enumera cada objeto ni sus ACL una por una (eso es un
  análisis más profundo, previsto más adelante).
- Necesita el módulo ActiveDirectory (RSAT). Sin él, el script no corre; instálalo o usa un DC.
