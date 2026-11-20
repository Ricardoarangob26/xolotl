/*
 * Mapeo de hallazgos a técnicas de MITRE ATT&CK (Enterprise). Determinista y local: no consulta
 * nada, deduce la técnica de la regla, el CWE o la categoría del hallazgo. Da un lenguaje común
 * para la ingeniería de detección (azul) y para planear la validación (roja/púrpura).
 *
 * No todo hallazgo tiene una técnica clara; cuando no la hay, se devuelve vacío (no se inventa).
 */
import type { Finding } from "./findings.js";

export interface Technique {
  id: string;
  name: string;
  tactic: string;
}

// Catálogo acotado a lo que de verdad producen los escáneres de Xolotl.
const CATALOG: Record<string, { name: string; tactic: string }> = {
  T1190: { name: "Exploit Public-Facing Application", tactic: "Acceso inicial" },
  T1133: { name: "External Remote Services", tactic: "Acceso inicial" },
  T1059: { name: "Command and Scripting Interpreter", tactic: "Ejecución" },
  "T1059.007": { name: "Command and Scripting Interpreter: JavaScript", tactic: "Ejecución" },
  T1203: { name: "Exploitation for Client Execution", tactic: "Ejecución" },
  T1068: { name: "Exploitation for Privilege Escalation", tactic: "Escalada de privilegios" },
  T1548: { name: "Abuse Elevation Control Mechanism", tactic: "Escalada de privilegios" },
  "T1548.001": { name: "Setuid and Setgid", tactic: "Escalada de privilegios" },
  "T1548.003": { name: "Sudo and Sudo Caching", tactic: "Escalada de privilegios" },
  T1611: { name: "Escape to Host", tactic: "Escalada de privilegios" },
  T1078: { name: "Valid Accounts", tactic: "Acceso con credenciales válidas" },
  T1136: { name: "Create Account", tactic: "Persistencia" },
  T1053: { name: "Scheduled Task/Job", tactic: "Persistencia" },
  T1110: { name: "Brute Force", tactic: "Acceso a credenciales" },
  "T1552.001": { name: "Unsecured Credentials: Credentials In Files", tactic: "Acceso a credenciales" },
  T1558: { name: "Steal or Forge Kerberos Tickets", tactic: "Acceso a credenciales" },
  "T1558.001": { name: "Golden Ticket", tactic: "Acceso a credenciales" },
  "T1558.003": { name: "Kerberoasting", tactic: "Acceso a credenciales" },
  "T1558.004": { name: "AS-REP Roasting", tactic: "Acceso a credenciales" },
  T1040: { name: "Network Sniffing", tactic: "Acceso a credenciales" },
  T1557: { name: "Adversary-in-the-Middle", tactic: "Acceso a credenciales" },
  "T1021.004": { name: "Remote Services: SSH", tactic: "Movimiento lateral" },
  T1003: { name: "OS Credential Dumping", tactic: "Acceso a credenciales" },
  T1210: { name: "Exploitation of Remote Services", tactic: "Movimiento lateral" },
  T1046: { name: "Network Service Discovery", tactic: "Descubrimiento" },
  T1083: { name: "File and Directory Discovery", tactic: "Descubrimiento" },
  T1526: { name: "Cloud Service Discovery", tactic: "Descubrimiento" },
  T1005: { name: "Data from Local System", tactic: "Recolección" },
  T1222: { name: "File and Directory Permissions Modification", tactic: "Evasión de defensas" },
  "T1562.001": { name: "Impair Defenses: Disable or Modify Tools", tactic: "Evasión de defensas" },
};

// Orden de presentación por cadena de ataque (acceso → impacto).
const TACTIC_ORDER = [
  "Acceso inicial",
  "Ejecución",
  "Persistencia",
  "Escalada de privilegios",
  "Evasión de defensas",
  "Acceso a credenciales",
  "Acceso con credenciales válidas",
  "Descubrimiento",
  "Movimiento lateral",
  "Recolección",
];
export const tacticRank = (t: string) => {
  const i = TACTIC_ORDER.indexOf(t);
  return i < 0 ? TACTIC_ORDER.length : i;
};

// Reglas propias de host/red (XOL-*): el mapeo más preciso porque sabemos qué comprueba cada una.
function byRuleId(ruleId: string): string[] {
  const r = ruleId.toUpperCase();
  if (r.startsWith("XOL-NET-EXP-")) return ["T1133", "T1046"];
  if (r.startsWith("XOL-TLS-")) return ["T1557", "T1040"];
  if (r === "XOL-AD-KERBEROAST") return ["T1558.003"];
  if (r === "XOL-AD-ASREP") return ["T1558.004"];
  if (r === "XOL-AD-KRBTGT") return ["T1558.001"];
  if (r === "XOL-AD-UNCONSTRAINED" || r === "XOL-AD-MAQ") return ["T1558"];
  if (r === "XOL-AD-REVERSIBLE") return ["T1552.001"];
  if (r === "XOL-WIN-WDIGEST") return ["T1003"];
  if (r === "XOL-WIN-SMB1") return ["T1210"];
  if (r === "XOL-WIN-LLMNR") return ["T1557"];
  const exact: Record<string, string[]> = {
    "XOL-SSH-001": ["T1021.004", "T1110"],
    "XOL-SSH-002": ["T1110", "T1021.004"],
    "XOL-SSH-003": ["T1078"],
    "XOL-SSH-005": ["T1110"],
    "XOL-SSH-006": ["T1557", "T1040"],
    "XOL-ACC-001": ["T1136", "T1078"],
    "XOL-ACC-002": ["T1078"],
    "XOL-ACC-003": ["T1548.003"],
    "XOL-ACC-004": ["T1611"],
    "XOL-PAT-001": ["T1068"],
    "XOL-PAT-002": ["T1068"],
    "XOL-NET-001": ["T1133"],
    "XOL-NET-002": ["T1133", "T1046"],
    "XOL-NET-003": ["T1040"],
    "XOL-MAC-001": ["T1562.001"],
    "XOL-MAC-002": ["T1562.001"],
    "XOL-MAC-003": ["T1562.001"],
    "XOL-FS-001": ["T1222", "T1548"],
    "XOL-FS-002": ["T1053", "T1222"],
    "XOL-FS-003": ["T1548.001"],
    "XOL-FS-004": ["T1068"],
    "XOL-LOG-001": ["T1562.001"],
  };
  return exact[r] ?? [];
}

// CWE → técnica (vale para SAST, DAST e IaC).
function byCwe(cwes: string[]): string[] {
  const nums = new Set(cwes.map((c) => c.replace(/^CWE-/i, "")));
  const out: string[] = [];
  const add = (cwe: string, ...ids: string[]) => {
    if (nums.has(cwe)) out.push(...ids);
  };
  add("89", "T1190"); // SQLi
  add("78", "T1059", "T1190"); // OS command injection
  add("77", "T1059"); // command injection
  add("94", "T1059"); // code injection
  add("95", "T1059"); // eval injection
  add("79", "T1059.007"); // XSS
  add("502", "T1190", "T1203"); // deserialización
  add("918", "T1190"); // SSRF
  add("611", "T1190"); // XXE
  add("22", "T1083", "T1005"); // path traversal
  add("23", "T1083");
  add("98", "T1190"); // RFI/LFI
  add("798", "T1552.001"); // credenciales embebidas
  add("259", "T1552.001");
  add("321", "T1552.001");
  add("327", "T1557", "T1040"); // cripto débil
  add("326", "T1557");
  add("295", "T1557"); // validación de certificado
  add("287", "T1078"); // autenticación incorrecta
  add("306", "T1190"); // falta autenticación en función crítica
  add("862", "T1190"); // falta de autorización
  return out;
}

// Red de seguridad por categoría cuando ni la regla ni el CWE dijeron nada.
function byCategory(f: Finding): string[] {
  switch (f.category) {
    case "secret":
      return ["T1552.001"];
    case "sca":
    case "container":
      return ["T1190"];
    case "host":
      return f.package ? ["T1068"] : [];
    case "dast":
      return ["T1190"];
    case "network":
      return ["T1046"];
    case "iac":
      return ["T1190"];
    default:
      return [];
  }
}

/** Técnicas ATT&CK de un hallazgo, de la más específica a la más general (máx. 3). */
export function attackFor(f: Finding): Technique[] {
  let ids = byRuleId(f.ruleId);
  if (!ids.length) ids = byCwe(f.cwe ?? []);
  if (!ids.length) ids = byCategory(f);
  const seen = new Set<string>();
  const out: Technique[] = [];
  for (const id of ids) {
    const meta = CATALOG[id];
    if (!meta || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name: meta.name, tactic: meta.tactic });
  }
  return out.slice(0, 3);
}
