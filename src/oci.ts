/*
 * Postura de Oracle Cloud (OCI) (Fase 2, vía azul). Prowler no cubre OCI, así que usamos el script
 * oficial CIS de Oracle (cis_reports.py del oci-cis-landingzone-quickstart), que evalúa la tenancy
 * contra el CIS OCI Benchmark con una identidad de SOLO LECTURA y escribe un CSV resumen. Fiel a
 * "depende de ti": tú lo corres y traes el CSV; Xolotl lo parsea a hallazgos. El script solo lee.
 */
import type { RawFinding, Severity } from "./findings.js";

export function ociAdvisory(target?: string): string {
  return [
    `## Tier 1 · advisory — postura de Oracle Cloud (OCI) con el script CIS oficial (solo lectura)${target ? ` · ${target}` : ""}`,
    "Oracle no está cubierto por Prowler; se usa el script oficial cis_reports.py (CIS OCI Benchmark).",
    "Solo lee: con un usuario de solo lectura (grupo 'Auditors' y la política",
    "'Allow group Auditors to read all-resources in tenancy') no cambia nada.",
    "",
    "1. Ten el OCI CLI configurado con ese usuario de solo lectura (~/.oci/config).",
    "2. Descarga y ejecuta el script:",
    "     git clone https://github.com/oracle-quickstart/oci-cis-landingzone-quickstart",
    "     cd oci-cis-landingzone-quickstart/scripts/cis-reports",
    "     python3 cis_reports.py --report-directory ./oci-cis-out",
    "   (añade --region o --all-resources según tu entorno; usa la auth de tu ~/.oci/config.)",
    "",
    "3. Trae el CSV resumen que lista cada recomendación con su cumplimiento:",
    "     ./oci-cis-out/<fecha>/cis_summary_report.csv",
    "",
    "Volver: scan_cloud con provider=oci y collected_file=<ruta del cis_summary_report.csv>.",
  ].join("\n");
}

/** CSV mínimo con comillas: separa por comas respetando campos entre comillas dobles. */
function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

const findCol = (headers: string[], ...needles: string[]) =>
  headers.findIndex((h) => needles.some((n) => h.toLowerCase().includes(n)));

const isCompliant = (v: string) => /^(yes|true|compliant|pass|ok)\b/i.test(v.trim());

export interface OciParse {
  findings: RawFinding[];
  tenancy: string;
  total: number;
  nonCompliant: number;
}

export function parseOciCis(csv: string, tenancy = "tenancy"): OciParse {
  const lines = csv.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) throw new Error("El CSV está vacío o no tiene filas. Usa el cis_summary_report.csv que genera cis_reports.py.");
  const headers = parseCsvLine(lines[0]);
  const cRec = findCol(headers, "recommendation", "number", "cis", "#");
  const cTitle = findCol(headers, "title", "name", "description");
  const cComp = findCol(headers, "compliant", "status", "result");
  const cLevel = findCol(headers, "level");
  const cFind = findCol(headers, "finding", "total", "count");
  if (cComp < 0 || cTitle < 0)
    throw new Error("El CSV no parece el resumen CIS (faltan columnas de título y cumplimiento). Usa cis_summary_report.csv, no los CSV por recurso.");

  const findings: RawFinding[] = [];
  let total = 0;
  let nonCompliant = 0;
  for (const line of lines.slice(1)) {
    const cols = parseCsvLine(line);
    if (cols.length <= cComp) continue;
    const comp = cols[cComp] ?? "";
    if (comp === "") continue;
    total++;
    if (isCompliant(comp)) continue;
    nonCompliant++;

    const rec = cRec >= 0 ? cols[cRec] : "";
    const level = cLevel >= 0 ? cols[cLevel] : "";
    const findingsCount = cFind >= 0 ? cols[cFind] : "";
    const severity: Severity = /2/.test(level) ? "low" : "medium"; // CIS Level 2 → bajo; Level 1 (o sin nivel) → medio
    findings.push({
      tool: "oci-cis",
      category: "config",
      severity,
      ruleId: `CIS-OCI-${rec || findings.length + 1}`,
      title: `${rec ? `${rec} ` : ""}${cols[cTitle] || "recomendación CIS OCI"}`.trim(),
      description: `CIS OCI Benchmark${level ? ` · Nivel ${level}` : ""} · no conforme${findingsCount && findingsCount !== "0" ? ` · ${findingsCount} hallazgo(s)` : ""}.`,
      remediation: "Revisa la recomendación en el CIS OCI Benchmark y corrígela en la consola o por Terraform (el landing zone de Oracle trae la configuración conforme).",
      location: { target: tenancy },
    });
  }
  if (!total) throw new Error("No se encontraron filas con estado de cumplimiento. ¿Es el cis_summary_report.csv?");
  return { findings, tenancy, total, nonCompliant };
}
