/*
 * Mapeo de hallazgos a controles de marcos de cumplimiento. Determinista y local: clasifica el
 * hallazgo en un "tema" de control (por regla, CWE o categoría) y cada tema se traduce al control
 * equivalente en varios marcos. Es un mapeo ORIENTATIVO para dirigir la remediación y el informe
 * de brechas; no sustituye una auditoría formal.
 */
import type { Finding } from "./findings.js";

export interface Control {
  framework: string;
  id: string;
  title: string;
}

export const FRAMEWORKS = ["OWASP 2021", "PCI DSS 4.0", "NIST 800-53", "ISO 27001:2022", "CIS v8"] as const;
export const frameworkRank = (fw: string) => {
  const i = (FRAMEWORKS as readonly string[]).indexOf(fw);
  return i < 0 ? FRAMEWORKS.length : i;
};

type ThemeKey = "injection" | "secrets" | "crypto" | "authn" | "privilege" | "vulnmgmt" | "config" | "logging" | "appsec";

// Cada tema → el control equivalente en cada marco (omitido donde no hay uno limpio).
const THEME_CONTROLS: Record<ThemeKey, Control[]> = {
  injection: [
    { framework: "OWASP 2021", id: "A03", title: "Inyección" },
    { framework: "PCI DSS 4.0", id: "6.2.4", title: "Codificación segura frente a inyección" },
    { framework: "NIST 800-53", id: "SI-10", title: "Information Input Validation" },
    { framework: "ISO 27001:2022", id: "A.8.28", title: "Codificación segura" },
    { framework: "CIS v8", id: "16.11", title: "Validación de entrada en el software" },
  ],
  secrets: [
    { framework: "OWASP 2021", id: "A07", title: "Fallos de identificación y autenticación" },
    { framework: "PCI DSS 4.0", id: "8.6.2", title: "Credenciales no embebidas en código/scripts" },
    { framework: "NIST 800-53", id: "IA-5", title: "Authenticator Management" },
    { framework: "ISO 27001:2022", id: "A.5.17", title: "Información de autenticación" },
  ],
  crypto: [
    { framework: "OWASP 2021", id: "A02", title: "Fallos criptográficos" },
    { framework: "PCI DSS 4.0", id: "4.2.1", title: "Criptografía fuerte en el transporte" },
    { framework: "NIST 800-53", id: "SC-13", title: "Cryptographic Protection" },
    { framework: "ISO 27001:2022", id: "A.8.24", title: "Uso de criptografía" },
    { framework: "CIS v8", id: "3.10", title: "Cifrar datos sensibles en tránsito" },
  ],
  authn: [
    { framework: "OWASP 2021", id: "A07", title: "Fallos de identificación y autenticación" },
    { framework: "PCI DSS 4.0", id: "8.3.1", title: "Autenticación fuerte de usuarios" },
    { framework: "NIST 800-53", id: "IA-2", title: "Identification and Authentication" },
    { framework: "ISO 27001:2022", id: "A.8.5", title: "Autenticación segura" },
    { framework: "CIS v8", id: "6.3", title: "Autenticación multifactor" },
  ],
  privilege: [
    { framework: "OWASP 2021", id: "A01", title: "Pérdida de control de acceso" },
    { framework: "PCI DSS 4.0", id: "7.2.1", title: "Acceso por menor privilegio" },
    { framework: "NIST 800-53", id: "AC-6", title: "Least Privilege" },
    { framework: "ISO 27001:2022", id: "A.8.2", title: "Derechos de acceso privilegiado" },
    { framework: "CIS v8", id: "5.4", title: "Restringir privilegios de administrador" },
  ],
  vulnmgmt: [
    { framework: "OWASP 2021", id: "A06", title: "Componentes vulnerables y desactualizados" },
    { framework: "PCI DSS 4.0", id: "6.3.1", title: "Identificar y clasificar vulnerabilidades" },
    { framework: "NIST 800-53", id: "SI-2", title: "Flaw Remediation" },
    { framework: "ISO 27001:2022", id: "A.8.8", title: "Gestión de vulnerabilidades técnicas" },
    { framework: "CIS v8", id: "7.1", title: "Gestión continua de vulnerabilidades" },
  ],
  config: [
    { framework: "OWASP 2021", id: "A05", title: "Configuración de seguridad incorrecta" },
    { framework: "PCI DSS 4.0", id: "2.2.1", title: "Estándares de configuración segura" },
    { framework: "NIST 800-53", id: "CM-6", title: "Configuration Settings" },
    { framework: "ISO 27001:2022", id: "A.8.9", title: "Gestión de la configuración" },
    { framework: "CIS v8", id: "4.1", title: "Proceso de configuración segura" },
  ],
  logging: [
    { framework: "OWASP 2021", id: "A09", title: "Fallos de registro y monitoreo de seguridad" },
    { framework: "PCI DSS 4.0", id: "10.2.1", title: "Registros de auditoría" },
    { framework: "NIST 800-53", id: "AU-2", title: "Event Logging" },
    { framework: "ISO 27001:2022", id: "A.8.15", title: "Registro de eventos" },
    { framework: "CIS v8", id: "8.2", title: "Recolección de registros de auditoría" },
  ],
  appsec: [
    { framework: "OWASP 2021", id: "A04", title: "Diseño inseguro" },
    { framework: "PCI DSS 4.0", id: "6.2.1", title: "Software desarrollado de forma segura" },
    { framework: "NIST 800-53", id: "SA-11", title: "Developer Testing and Evaluation" },
    { framework: "ISO 27001:2022", id: "A.8.25", title: "Ciclo de vida de desarrollo seguro" },
    { framework: "CIS v8", id: "16.1", title: "Proceso de desarrollo seguro" },
  ],
};

function themesOf(f: Finding): ThemeKey[] {
  const cw = new Set((f.cwe ?? []).map((c) => c.replace(/^CWE-/i, "")));
  const r = f.ruleId.toUpperCase();
  const out = new Set<ThemeKey>();
  const anyCwe = (...ids: string[]) => ids.some((c) => cw.has(c));

  if (anyCwe("89", "78", "77", "74", "90", "91", "94", "95", "79", "22", "23", "98", "611", "918", "502", "643")) out.add("injection");
  if (f.category === "secret" || anyCwe("798", "259", "321", "522", "256")) out.add("secrets");
  if (anyCwe("327", "326", "310", "295", "319", "757") || r.startsWith("XOL-TLS-") || r === "XOL-SSH-006" || r === "XOL-NET-003") out.add("crypto");
  if (anyCwe("287", "306", "862", "285", "863", "639", "640", "384") || r.startsWith("XOL-SSH-") || r.startsWith("XOL-ACC-")) out.add("authn");
  if (r === "XOL-ACC-001" || r === "XOL-ACC-003" || r === "XOL-ACC-004" || r === "XOL-FS-003") out.add("privilege");
  if (f.category === "sca" || f.category === "container" || (f.category === "host" && f.package) || r.startsWith("XOL-PAT-")) out.add("vulnmgmt");
  if (f.category === "iac" || r.startsWith("XOL-MAC-") || r.startsWith("XOL-KRN-") || r.startsWith("XOL-NET-") || r.startsWith("XOL-SVC-") || r.startsWith("XOL-FS-")) out.add("config");
  if (r.startsWith("XOL-LOG-")) out.add("logging");

  if (!out.size) {
    if (f.category === "sast" || f.category === "dast") out.add("appsec");
    else if (f.category === "config" || f.category === "network") out.add("config");
  }
  return [...out];
}

/** Controles de cumplimiento de un hallazgo, deduplicados y ordenados por marco. */
export function controlsFor(f: Finding): Control[] {
  const seen = new Set<string>();
  const out: Control[] = [];
  for (const theme of themesOf(f)) {
    for (const c of THEME_CONTROLS[theme]) {
      const key = `${c.framework}|${c.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(c);
    }
  }
  return out.sort((a, b) => frameworkRank(a.framework) - frameworkRank(b.framework) || a.id.localeCompare(b.id, undefined, { numeric: true }));
}
