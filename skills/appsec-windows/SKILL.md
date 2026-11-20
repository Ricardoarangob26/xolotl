---
name: appsec-windows
description: Evaluar el endurecimiento de un servidor Windows con el MCP Xolotl, usando el tool scan_windows y un recolector PowerShell de SOLO LECTURA (local o por WinRM). Úsala cuando pidan auditar o endurecer un servidor Windows, revisar SMBv1, WDigest, UAC, LLMNR, Defender, firewall, RDP/NLA, la cuenta Guest o PowerShell v2, o comparar un Windows con buenas prácticas. Sin conexión propia: entrega el script para correrlo a mano y parsea la salida. Nivel de acceso: administrador local de lectura.
---

# Postura de Windows Server

`scan_windows` revisa la configuración de endurecimiento de un Windows en solo lectura, con un
recolector PowerShell. No se conecta ni cambia nada: entrega el script y parsea su salida a
hallazgos. Se complementa con `scan_ad` (dominio) y `scan_host`/`scan_lynis` (Linux).

## El flujo (Tier 1)

1. `scan_windows` (sin más) devuelve `win-collect.ps1` y los comandos.
2. Córrelo como **administrador local** (para ver toda la configuración):
   - Local: `powershell -ExecutionPolicy Bypass -File win-collect.ps1 | Out-File -Encoding utf8 win-audit.txt`
   - Remoto por **WinRM**: `Invoke-Command -ComputerName <host> -FilePath win-collect.ps1 | Out-File -Encoding utf8 win-audit.txt`
3. `scan_windows collected_file=win-audit.txt` lo parsea.

## Qué comprueba

| Área | Hallazgos |
|---|---|
| Protocolos | SMBv1 habilitado (alto, EternalBlue); firma SMB no obligatoria (medio, SMB relay) |
| Credenciales | WDigest guarda contraseñas en memoria (alto, Mimikatz); cuenta Guest habilitada (alto) |
| Elevación | UAC deshabilitado (alto) |
| Red / nombres | LLMNR activo (medio, envenenamiento/Responder); perfiles de firewall apagados (medio) |
| Acceso remoto | RDP sin NLA (medio) |
| Defensa | protección en tiempo real de Defender desactivada (alto); PowerShell v2 instalado (medio) |
| Cuentas | muchos administradores locales (bajo) |

Varios hallazgos mapean a MITRE ATT&CK: WDigest → T1003 (volcado de credenciales), SMBv1 → T1210
(explotación de servicios remotos), LLMNR → T1557 (adversario en el medio).

## Relación con el resto

- Los hallazgos son de categoría **config**: heredan cumplimiento, riesgo, inventario,
  revalidación, ATT&CK e informes.
- Es **postura de solo lectura** (vía azul). La validación ofensiva en Windows (LLMNR poisoning
  real, extracción de credenciales) es Fase 5 (vía roja), bajo el plan de compromiso.

## Límites

- Cubre los controles de mayor impacto, no el CIS Windows completo. Para un benchmark exhaustivo
  se puede sumar HardeningKitty más adelante (mismo patrón de salida).
- Necesita privilegios de administrador local para leer toda la configuración; sin ellos, algunos
  valores vendrán vacíos y esas comprobaciones pueden faltar.
