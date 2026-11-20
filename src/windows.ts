/*
 * Postura de Windows Server (Fase 2, vía azul). Recolector PowerShell de SOLO LECTURA (local o por
 * WinRM) que consulta la configuración de endurecimiento; tú lo corres y traes la salida, y Xolotl
 * la parsea a hallazgos. No cambia nada. Comprueba lo de mayor impacto (SMBv1, WDigest, UAC,
 * Defender, firewall, RDP/NLA, LLMNR, cuenta Guest, PowerShell v2…), al estilo de un CIS reducido.
 */
import type { RawFinding, Severity } from "./findings.js";

const WIN_COLLECTOR = [
  "$os = Get-CimInstance Win32_OperatingSystem",
  '"===XOLOTL meta==="',
  '"hostname|$env:COMPUTERNAME"',
  '"os|$($os.Caption) $($os.Version)"',
  '"===XOLOTL settings==="',
  "$smb = Get-SmbServerConfiguration",
  '"smb1|$($smb.EnableSMB1Protocol)"',
  '"smb_signing|$($smb.RequireSecuritySignature)"',
  'try { "defender_rtp|$((Get-MpComputerStatus).RealTimeProtectionEnabled)" } catch { "defender_rtp|unknown" }',
  'try { "defender_av|$((Get-MpComputerStatus).AntivirusEnabled)" } catch { "defender_av|unknown" }',
  '"firewall_disabled|$(((Get-NetFirewallProfile) | Where-Object { -not $_.Enabled } | Select-Object -Expand Name) -join \',\')"',
  '"uac|$((Get-ItemProperty \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\' -Name EnableLUA -EA SilentlyContinue).EnableLUA)"',
  '"wdigest|$((Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\' -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential)"',
  '"llmnr|$((Get-ItemProperty \'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\' -Name EnableMulticast -EA SilentlyContinue).EnableMulticast)"',
  '"rdp_denied|$((Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections)"',
  '"rdp_nla|$((Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\' -Name UserAuthentication -EA SilentlyContinue).UserAuthentication)"',
  '"guest_enabled|$((Get-LocalUser -Name Guest -EA SilentlyContinue).Enabled)"',
  '"local_admins|$(((Get-LocalGroupMember Administrators -EA SilentlyContinue)).Count)"',
  '"ps2|$((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -EA SilentlyContinue).State)"',
].join("\r\n");

export function windowsAdvisory(target?: string): string {
  return [
    `## Tier 1 · advisory — postura de Windows Server${target ? ` (${target})` : ""} (solo lectura)`,
    "El script solo consulta configuración (Get-*, registro en lectura): no cambia nada. Requiere",
    "ejecutarse como administrador local para ver toda la configuración.",
    "",
    "En el servidor (local) o desde tu equipo por WinRM:",
    "  - Local:  guarda el script como win-collect.ps1 y corre:",
    "       powershell -ExecutionPolicy Bypass -File win-collect.ps1 | Out-File -Encoding utf8 win-audit.txt",
    "  - Remoto por WinRM:",
    "       Invoke-Command -ComputerName <host> -FilePath win-collect.ps1 | Out-File -Encoding utf8 win-audit.txt",
    "",
    "Script win-collect.ps1:",
    "",
    WIN_COLLECTOR,
    "",
    "Volver: scan_windows con collected_file=<ruta de win-audit.txt>.",
  ].join("\n");
}

function sections(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  let cur = "";
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.match(/^===XOLOTL (\w+)===/);
    if (m) {
      cur = m[1];
      out[cur] = [];
      continue;
    }
    if (cur && raw.trim()) out[cur].push(raw.trim());
  }
  return out;
}

export interface WinParse {
  findings: RawFinding[];
  host: string;
}

export function parseWindowsCollected(text: string, fallbackHost = "servidor-windows"): WinParse {
  if (!/===XOLOTL (meta|settings)===/.test(text))
    throw new Error("La salida no trae las marcas ===XOLOTL …===. Genera el archivo con el script que da scan_windows en modo advisory.");
  const sec = sections(text);
  const meta: Record<string, string> = {};
  for (const l of sec.meta ?? []) {
    const i = l.indexOf("|");
    if (i > 0) meta[l.slice(0, i)] = l.slice(i + 1).trim();
  }
  const s: Record<string, string> = {};
  for (const l of sec.settings ?? []) {
    const i = l.indexOf("|");
    if (i > 0) s[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim();
  }
  const host = meta.hostname || fallbackHost;

  const out: RawFinding[] = [];
  const add = (rule: string, severity: Severity, title: string, description: string, remediation: string, evidence?: string) =>
    out.push({ tool: "win-audit", category: "config", severity, ruleId: rule, title, description, remediation, evidence, location: { target: host } });
  const isTrue = (v?: string) => (v ?? "").toLowerCase() === "true";

  if (isTrue(s.smb1))
    add("XOL-WIN-SMB1", "high", "SMBv1 habilitado", "SMBv1 es obsoleto y vulnerable (EternalBlue/WannaCry). No debería estar activo en ningún servidor moderno.", "Deshabilitar SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false y quitar la característica SMB1.", "EnableSMB1Protocol=True");

  if (s.smb_signing !== undefined && !isTrue(s.smb_signing))
    add("XOL-WIN-SMBSIGN", "medium", "Firma SMB no obligatoria", "Sin firma SMB obligatoria el tráfico es susceptible a retransmisión (SMB relay) y manipulación.", "Exigir la firma: Set-SmbServerConfiguration -RequireSecuritySignature $true (y en GPO).", "RequireSecuritySignature=False");

  if (s.wdigest === "1")
    add("XOL-WIN-WDIGEST", "high", "WDigest guarda credenciales en memoria", "Con UseLogonCredential=1, las contraseñas quedan en claro en la memoria de LSASS y se extraen con Mimikatz.", "Poner UseLogonCredential=0 en HKLM\\...\\WDigest (desactivado por defecto desde Windows 8.1/2012 R2).", "WDigest UseLogonCredential=1");

  if (s.uac === "0")
    add("XOL-WIN-UAC", "high", "UAC deshabilitado", "Con EnableLUA=0 no hay elevación: cualquier proceso corre con privilegios completos sin confirmación.", "Habilitar UAC (EnableLUA=1) y reiniciar.", "EnableLUA=0");

  // LLMNR: EnableMulticast=0 lo desactiva; ausente o 1 → activo (envenenamiento de nombres).
  if (s.llmnr !== "0" && "llmnr" in s)
    add("XOL-WIN-LLMNR", "medium", "LLMNR activo (resolución multicast de nombres)", "LLMNR permite a un atacante de la red responder consultas de nombres y capturar hashes NetNTLM (Responder).", "Deshabilitar LLMNR por GPO: 'Turn off multicast name resolution' (EnableMulticast=0).", `EnableMulticast=${s.llmnr || "(no configurado → activo)"}`);

  if (isTrue(s.defender_rtp) === false && s.defender_rtp === "False")
    add("XOL-WIN-DEFENDER", "high", "Protección en tiempo real de Defender desactivada", "Sin protección en tiempo real no se bloquea malware al ejecutarse.", "Habilitar la protección en tiempo real de Microsoft Defender (o del EDR corporativo si lo reemplaza).", "RealTimeProtectionEnabled=False");

  if (s.firewall_disabled)
    add("XOL-WIN-FIREWALL", "medium", `Perfiles de firewall deshabilitados: ${s.firewall_disabled}`, "Un perfil de firewall apagado deja los servicios del host expuestos en esa red.", "Habilitar los tres perfiles (Domain/Private/Public): Set-NetFirewallProfile -Enabled True.", `perfiles apagados: ${s.firewall_disabled}`);

  // RDP habilitado (fDenyTSConnections=0) sin NLA (UserAuthentication!=1).
  if (s.rdp_denied === "0" && s.rdp_nla !== "1")
    add("XOL-WIN-RDPNLA", "medium", "RDP habilitado sin Autenticación a Nivel de Red (NLA)", "Sin NLA, RDP acepta conexiones antes de autenticar, lo que amplía la superficie y facilita la fuerza bruta.", "Exigir NLA (UserAuthentication=1) y limitar el acceso RDP por firewall a la red de administración.", "RDP-Tcp UserAuthentication!=1");

  if (isTrue(s.guest_enabled))
    add("XOL-WIN-GUEST", "high", "Cuenta Guest habilitada", "La cuenta de invitado permite acceso sin credenciales nominales y rompe la trazabilidad.", "Deshabilitar la cuenta Guest: Disable-LocalUser -Name Guest.", "Guest.Enabled=True");

  const admins = Number(s.local_admins);
  if (!Number.isNaN(admins) && admins > 3)
    add("XOL-WIN-ADMINS", "low", `Muchos administradores locales (${admins})`, "Cuantos más administradores locales, mayor superficie para el movimiento lateral si uno se compromete.", "Revisar el grupo Administradores; usar LAPS para la contraseña del admin local y menor privilegio.", `Administradores locales=${admins}`);

  if ((s.ps2 ?? "").toLowerCase() === "enabled")
    add("XOL-WIN-PS2", "medium", "PowerShell v2 instalado", "PowerShell v2 no tiene registro ni AMSI: se usa para evadir defensas ('downgrade attack').", "Quitar la característica: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2.", "MicrosoftWindowsPowerShellV2=Enabled");

  return { findings: out, host };
}
