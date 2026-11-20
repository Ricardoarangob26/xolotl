/*
 * Postura de Active Directory (Fase 2, vía azul), al estilo PingCastle pero local y de solo
 * lectura. Sin conexión ni módulos propios: entregamos un script PowerShell de SOLO LECTURA que
 * consulta el dominio y emite métricas; tú lo corres con una cuenta de lectura del dominio y traes
 * la salida; Xolotl la parsea a hallazgos aplicando umbrales (política de contraseñas vs NIST/CIS,
 * cuentas privilegiadas, delegación, Kerberoasting/AS-REP, krbtgt, cuentas inactivas…).
 *
 * El script solo lee (Get-AD*, Search-ADAccount): no cambia nada del directorio.
 */
import type { RawFinding, Severity } from "./findings.js";

/** Script PowerShell de solo lectura. Requiere el módulo ActiveDirectory (RSAT) y lectura del dominio. */
const AD_COLLECTOR = [
  "Import-Module ActiveDirectory",
  "$d = Get-ADDomain",
  '"===XOLOTL meta==="',
  '"domain|$($d.DNSRoot)"',
  '"forest_mode|$((Get-ADForest).ForestMode)"',
  "$p = Get-ADDefaultDomainPasswordPolicy",
  '"===XOLOTL policy==="',
  '"MinPasswordLength|$($p.MinPasswordLength)"',
  '"PasswordHistoryCount|$($p.PasswordHistoryCount)"',
  '"MaxPasswordAgeDays|$([int]$p.MaxPasswordAge.TotalDays)"',
  '"LockoutThreshold|$($p.LockoutThreshold)"',
  '"ComplexityEnabled|$($p.ComplexityEnabled)"',
  '"ReversibleEncryptionEnabled|$($p.ReversibleEncryptionEnabled)"',
  '"===XOLOTL metrics==="',
  'function C($x){ ($x | Measure-Object).Count }',
  '"domain_admins|$(C (Get-ADGroupMember \'Domain Admins\' -Recursive))"',
  '"enterprise_admins|$(C (Get-ADGroupMember \'Enterprise Admins\' -Recursive -ErrorAction SilentlyContinue))"',
  '"administrators|$(C (Get-ADGroupMember \'Administrators\' -Recursive -ErrorAction SilentlyContinue))"',
  '"krbtgt_password_age_days|$([int]((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet).TotalDays)"',
  '"unconstrained_delegation|$(C (Get-ADObject -Filter { (userAccountControl -band 524288) -and (objectClass -eq \'user\' -or objectClass -eq \'computer\') } -ErrorAction SilentlyContinue))"',
  '"kerberoastable_users|$(C (Get-ADUser -Filter { ServicePrincipalName -like \'*\' -and Enabled -eq $true }))"',
  '"asrep_roastable|$(C (Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true }))"',
  '"reversible_pwd_accounts|$(C (Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true }))"',
  '"pwd_never_expires_privileged|$(C (Get-ADUser -Filter { PasswordNeverExpires -eq $true -and adminCount -eq 1 -and Enabled -eq $true }))"',
  '"inactive_enabled_accounts|$(C (Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 90.00:00:00 | Where-Object Enabled))"',
  '"machine_account_quota|$((Get-ADObject $d.DistinguishedName -Properties ms-DS-MachineAccountQuota).\'ms-DS-MachineAccountQuota\')"',
].join("\r\n");

export function adAdvisory(target?: string): string {
  return [
    `## Tier 1 · advisory — postura de Active Directory${target ? ` (${target})` : ""} (solo lectura)`,
    "El script solo consulta el dominio (Get-AD*, Search-ADAccount): no cambia nada. Necesita el",
    "módulo ActiveDirectory (RSAT) y una cuenta con lectura del dominio (un usuario normal suele bastar).",
    "",
    "En un equipo unido al dominio (PowerShell):",
    "  1. Guarda este script como ad-collect.ps1:",
    "",
    AD_COLLECTOR,
    "",
    "  2. Ejecútalo y vuelca la salida a un archivo (UTF-8):",
    "       powershell -ExecutionPolicy Bypass -File ad-collect.ps1 | Out-File -Encoding utf8 ad-audit.txt",
    "",
    "  3. Volver: scan_ad con collected_file=<ruta de ad-audit.txt>.",
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

const toMap = (lines: string[] = []): Record<string, string> => {
  const m: Record<string, string> = {};
  for (const l of lines) {
    const i = l.indexOf("|");
    if (i > 0) m[l.slice(0, i)] = l.slice(i + 1).trim();
  }
  return m;
};

export interface AdParse {
  findings: RawFinding[];
  domain: string;
}

export function parseAdCollected(text: string, fallbackDomain = "dominio"): AdParse {
  if (!/===XOLOTL (meta|policy|metrics)===/.test(text))
    throw new Error("La salida no trae las marcas ===XOLOTL …===. Genera el archivo con el script que da scan_ad en modo advisory.");
  const sec = sections(text);
  const meta = toMap(sec.meta);
  const pol = toMap(sec.policy);
  const met = toMap(sec.metrics);
  const domain = meta.domain || fallbackDomain;

  const out: RawFinding[] = [];
  const add = (rule: string, severity: Severity, title: string, description: string, remediation: string, evidence?: string) =>
    out.push({ tool: "ad-audit", category: "config", severity, ruleId: rule, title, description, remediation, evidence, location: { target: domain } });
  const num = (m: Record<string, string>, k: string): number | undefined => (k in m && m[k] !== "" ? Number(m[k]) : undefined);
  const isTrue = (v?: string) => (v ?? "").toLowerCase() === "true";

  // ── Política de contraseñas (NIST 800-63B / CIS) ──
  const minLen = num(pol, "MinPasswordLength");
  if (minLen !== undefined && minLen < 8) add("XOL-AD-PWLEN", "high", `Longitud mínima de contraseña muy baja (${minLen})`, "Por debajo de 8 caracteres las contraseñas se descifran rápido. NIST 800-63B pone el mínimo en 8 y recomienda más longitud antes que complejidad.", "Subir la longitud mínima a 14 (CIS) y cribar contra listas de contraseñas filtradas.", `MinPasswordLength=${minLen}`);
  else if (minLen !== undefined && minLen < 14) add("XOL-AD-PWLEN", "medium", `Longitud mínima de contraseña por debajo de 14 (${minLen})`, "14 es la recomendación de CIS; favorece la longitud sobre las reglas de composición (NIST 800-63B).", "Subir la longitud mínima a 14 y cribar contra contraseñas filtradas.", `MinPasswordLength=${minLen}`);

  if (isTrue(pol.ReversibleEncryptionEnabled)) add("XOL-AD-REVERSIBLE", "high", "Cifrado reversible de contraseñas habilitado en la política", "Con cifrado reversible las contraseñas se pueden recuperar en claro desde la base del dominio: equivale a guardarlas sin cifrar.", "Desactivar el cifrado reversible en la GPO de política de contraseñas y rotar las afectadas.", "ReversibleEncryptionEnabled=True");

  const lockout = num(pol, "LockoutThreshold");
  if (lockout === 0) add("XOL-AD-LOCKOUT", "medium", "Sin bloqueo de cuentas tras intentos fallidos", "Con umbral de bloqueo 0 no hay freno a la fuerza bruta de contraseñas en línea.", "Fijar un umbral de bloqueo (p. ej. 5–10 intentos) con ventana y duración razonables.", "LockoutThreshold=0");

  const hist = num(pol, "PasswordHistoryCount");
  if (hist !== undefined && hist < 24) add("XOL-AD-PWHIST", "low", `Historial de contraseñas corto (${hist})`, "Un historial corto permite reutilizar contraseñas recientes.", "Historial de 24 contraseñas (recomendación CIS).", `PasswordHistoryCount=${hist}`);

  if (!isTrue(pol.ComplexityEnabled) && pol.ComplexityEnabled !== undefined) add("XOL-AD-COMPLEX", "low", "Complejidad de contraseñas desactivada", "Sin complejidad y sin longitud alta ni cribado de contraseñas filtradas, se aceptan contraseñas triviales.", "Habilitar complejidad, o compensarla con longitud alta (15+) y cribado de contraseñas filtradas.", "ComplexityEnabled=False");

  // ── Kerberos / delegación ──
  const krbtgt = num(met, "krbtgt_password_age_days");
  if (krbtgt !== undefined && krbtgt > 365) add("XOL-AD-KRBTGT", "high", `Contraseña de krbtgt sin rotar hace ${krbtgt} días`, "La clave de krbtgt firma todos los tickets Kerberos; si se filtró, permite Golden Tickets persistentes. Más de un año sin rotar es alto riesgo.", "Rotar la contraseña de krbtgt dos veces (con intervalo), siguiendo el procedimiento de Microsoft.", `krbtgt_password_age_days=${krbtgt}`);
  else if (krbtgt !== undefined && krbtgt > 180) add("XOL-AD-KRBTGT", "medium", `Contraseña de krbtgt sin rotar hace ${krbtgt} días`, "Conviene rotar krbtgt periódicamente para limitar la vida de un Golden Ticket.", "Rotar krbtgt dos veces siguiendo el procedimiento de Microsoft (cada 6–12 meses).", `krbtgt_password_age_days=${krbtgt}`);

  const uncon = num(met, "unconstrained_delegation");
  if (uncon && uncon > 0) add("XOL-AD-UNCONSTRAINED", "high", `Cuentas con delegación sin restricción (${uncon})`, "La delegación Kerberos sin restricción deja que un host comprometido suplante a cualquier usuario que se le conecte, incluidos administradores.", "Quitar la delegación sin restricción; usar delegación restringida (constrained) o basada en recursos, y marcar las cuentas sensibles como 'no delegables'.", `unconstrained_delegation=${uncon}`);

  const asrep = num(met, "asrep_roastable");
  if (asrep && asrep > 0) add("XOL-AD-ASREP", "high", `Cuentas sin preautenticación Kerberos (${asrep})`, "Sin preautenticación, cualquiera puede pedir un material cifrado con la contraseña de la cuenta y crackearlo offline (AS-REP Roasting).", "Activar la preautenticación Kerberos en esas cuentas (quitar DONT_REQ_PREAUTH).", `asrep_roastable=${asrep}`);

  const kerb = num(met, "kerberoastable_users");
  if (kerb && kerb > 0) add("XOL-AD-KERBEROAST", "medium", `Cuentas de servicio con SPN (${kerb})`, "Las cuentas de usuario con SPN permiten pedir tickets de servicio y crackear su contraseña offline (Kerberoasting); peligroso si tienen contraseña débil o privilegios.", "Contraseñas largas y aleatorias (25+), o cuentas gestionadas (gMSA); revisar que no tengan privilegios excesivos.", `kerberoastable_users=${kerb}`);

  const maq = num(met, "machine_account_quota");
  if (maq && maq > 0) add("XOL-AD-MAQ", "medium", `MachineAccountQuota permite crear equipos (${maq})`, "Con ms-DS-MachineAccountQuota > 0 cualquier usuario del dominio puede unir máquinas, lo que habilita ataques como RBCD.", "Poner ms-DS-MachineAccountQuota en 0 y delegar la unión de equipos a un grupo concreto.", `machine_account_quota=${maq}`);

  // ── Cuentas privilegiadas / higiene ──
  const da = num(met, "domain_admins");
  if (da !== undefined && da > 10) add("XOL-AD-DA", "medium", `Muchos miembros en Domain Admins (${da})`, "Cada Domain Admin es control total del dominio; cuantos más, mayor superficie y más difícil de proteger.", "Reducir Domain Admins al mínimo; usar cuentas administrativas separadas y niveles (tiering).", `domain_admins=${da}`);
  else if (da !== undefined && da > 5) add("XOL-AD-DA", "low", `Revisar miembros de Domain Admins (${da})`, "Conviene mantener Domain Admins lo más pequeño posible.", "Revisar la pertenencia y quitar cuentas que no la necesiten.", `domain_admins=${da}`);

  const ea = num(met, "enterprise_admins");
  if (ea !== undefined && ea > 1) add("XOL-AD-EA", "low", `Enterprise Admins con más de un miembro (${ea})`, "Enterprise Admins controla todo el bosque; normalmente debería estar casi vacío salvo cambios puntuales.", "Vaciar Enterprise Admins y agregar miembros solo durante operaciones que lo requieran.", `enterprise_admins=${ea}`);

  const pne = num(met, "pwd_never_expires_privileged");
  if (pne && pne > 0) add("XOL-AD-PNE", "low", `Cuentas privilegiadas con contraseña que no expira (${pne})`, "Una contraseña privilegiada que nunca cambia aumenta el impacto si se filtra.", "Revisar estas cuentas; para servicios, migrar a gMSA (rotación automática).", `pwd_never_expires_privileged=${pne}`);

  const inactive = num(met, "inactive_enabled_accounts");
  if (inactive && inactive > 0) add("XOL-AD-INACTIVE", "low", `Cuentas habilitadas e inactivas (${inactive})`, "Cuentas habilitadas sin uso en 90+ días son superficie de ataque olvidada (contraseñas viejas, sin MFA).", "Deshabilitar las cuentas inactivas tras confirmarlo con sus dueños.", `inactive_enabled_accounts=${inactive}`);

  return { findings: out, domain };
}
