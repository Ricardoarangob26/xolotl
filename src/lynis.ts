/*
 * Benchmark de endurecimiento con Lynis (Fase 2, vía azul). Lynis audita la configuración de un
 * sistema Unix/Linux contra buenas prácticas (muchas alineadas con CIS/STIG) y publica un índice
 * de endurecimiento. Encaja con el flujo Tier 1/MobaXterm: tú corres `lynis audit system` en el
 * servidor y traes su `lynis-report.dat`; Xolotl lo parsea a hallazgos. En Tier 2 se corre por SSH.
 *
 * Solo lectura: Lynis no cambia nada del sistema. Aquí solo parseamos su informe, texto plano.
 */
import { run, which } from "./exec.js";
import type { RawFinding, Severity } from "./findings.js";

/** Comando remoto: corre lynis (si está) y vuelca el informe a stdout. No cambia nada. */
export const LYNIS_REPORT_PATH = "/tmp/xolotl-lynis.dat";
export const LYNIS_REMOTE_CMD =
  `command -v lynis >/dev/null 2>&1 || { echo "LYNIS_NOT_INSTALLED"; exit 0; }; ` +
  `sudo -n lynis audit system --quiet --no-colors --report-file ${LYNIS_REPORT_PATH} >/dev/null 2>&1; ` +
  `cat ${LYNIS_REPORT_PATH} 2>/dev/null`;

interface Parsed {
  findings: RawFinding[];
  hardeningIndex?: number;
  lynisVersion?: string;
  host: string;
}

/** Desescapa el formato de lynis-report.dat (campos separados por '|'). */
const clean = (s: string | undefined) => (s && s !== "-" ? s.trim() : "");

/**
 * Parsea un lynis-report.dat. Las líneas relevantes:
 *   warning[]=TEST-ID|texto|detalle|solución
 *   suggestion[]=TEST-ID|texto|detalle|solución
 *   hardening_index=NN
 *   lynis_version=X.Y.Z
 */
export function parseLynisReport(text: string, host = "servidor"): Parsed {
  if (!/lynis_version=|hardening_index=|^(warning|suggestion)\[\]=/m.test(text)) {
    throw new Error("El archivo no parece un informe de Lynis (lynis-report.dat). Genera uno con: sudo lynis audit system --report-file <ruta>.");
  }
  const findings: RawFinding[] = [];
  let hardeningIndex: number | undefined;
  let lynisVersion: string | undefined;
  let reportHost = host;

  const emit = (kind: "warning" | "suggestion", rest: string) => {
    const [idRaw, title, details, solution] = rest.split("|");
    const id = clean(idRaw).replace(/:.*$/, "") || "LYNIS";
    const severity: Severity = kind === "warning" ? "medium" : "low";
    findings.push({
      tool: "lynis",
      category: "config",
      severity,
      ruleId: `LYNIS-${id}`,
      title: clean(title) || (kind === "warning" ? `Aviso de Lynis ${id}` : `Sugerencia de Lynis ${id}`),
      description: clean(details) || undefined,
      remediation: clean(solution) || undefined,
      location: { target: reportHost },
    });
  };

  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([a-z_]+)(\[\])?=(.*)$/);
    if (!m) continue;
    const key = m[1];
    const val = m[3];
    if (key === "warning") emit("warning", val);
    else if (key === "suggestion") emit("suggestion", val);
    else if (key === "hardening_index") hardeningIndex = Number(val) || undefined;
    else if (key === "lynis_version") lynisVersion = val.trim();
    else if ((key === "hostname" || key === "os_hostname") && val.trim()) reportHost = val.trim();
  }
  // Reasigna el host real a los hallazgos si el informe lo traía.
  if (reportHost !== host) for (const f of findings) f.location = { target: reportHost };

  if (hardeningIndex !== undefined) {
    const sev: Severity = hardeningIndex < 55 ? "high" : hardeningIndex < 70 ? "medium" : hardeningIndex < 80 ? "low" : "info";
    findings.unshift({
      tool: "lynis",
      category: "config",
      severity: sev,
      ruleId: "LYNIS-HARDENING-INDEX",
      title: `Índice de endurecimiento de Lynis: ${hardeningIndex}/100`,
      description:
        `Lynis${lynisVersion ? ` ${lynisVersion}` : ""} calificó el endurecimiento del sistema en ${hardeningIndex}/100. ` +
        "Es una medida global de la postura; súbela atendiendo los avisos y sugerencias de abajo.",
      remediation: "Prioriza los avisos (warnings) y luego las sugerencias; reejecuta Lynis para ver cómo sube el índice.",
      location: { target: reportHost },
    });
  }
  return { findings, hardeningIndex, lynisVersion, host: reportHost };
}

/** Tier 1 (advisory): instrucciones para correr Lynis a mano y traer el informe. */
export function advisoryLynis(target?: string): string {
  return [
    "## Tier 1 · advisory — benchmark de endurecimiento con Lynis (solo lectura)",
    `Objetivo: ${target ?? "el servidor Linux"}. Lynis no cambia nada del sistema.`,
    "",
    "En el servidor (MobaXterm, consola o bastión):",
    "  1. Instalar Lynis si falta:",
    "       Debian/Ubuntu:  sudo apt-get install -y lynis",
    "       RHEL/Rocky:     sudo dnf install -y lynis   (o desde el repo de CISOfy)",
    "       Sin paquete:    git clone https://github.com/CISOfy/lynis && cd lynis",
    "  2. Auditar y guardar el informe (solo lectura):",
    `       sudo lynis audit system --quiet --no-colors --report-file ${LYNIS_REPORT_PATH}`,
    `  3. Descargar el informe:  ${LYNIS_REPORT_PATH}`,
    "",
    "Volver: scan_lynis con report_file=<ruta del lynis-report.dat>. El ingreso es completo.",
  ].join("\n");
}

/** Tier 2: corre Lynis por SSH (solo con llave/agente) y devuelve el informe. */
export async function runLynisViaSsh(o: { target: string; port?: number; identityFile?: string; timeoutMs: number }): Promise<string> {
  const ssh = which("ssh");
  if (!ssh) throw new Error("No se encontró el cliente ssh en el PATH.");
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*(@[A-Za-z0-9._-]+)?$/.test(o.target)) throw new Error(`Destino SSH no válido: ${o.target}`);
  const args = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    "-o", "StrictHostKeyChecking=accept-new",
    ...(o.port ? ["-p", String(o.port)] : []),
    ...(o.identityFile ? ["-i", o.identityFile] : []),
    "--",
    o.target,
    "sh -s",
  ];
  const r = await run(ssh, args, { input: LYNIS_REMOTE_CMD, timeoutMs: o.timeoutMs, maxStdout: 16 * 1024 * 1024 });
  if (r.timedOut) throw new Error("La ejecución de Lynis por SSH superó el tiempo límite.");
  if (r.stdout.includes("LYNIS_NOT_INSTALLED")) throw new Error("Lynis no está instalado en el objetivo. Instálalo (apt/dnf install lynis) o usa el modo advisory y súbelo a mano.");
  if (!/hardening_index=|lynis_version=/.test(r.stdout)) throw new Error(`No se obtuvo el informe de Lynis por SSH (código ${r.code}). Revisa sudo/instalación, o usa advisory + report_file.`);
  return r.stdout;
}
