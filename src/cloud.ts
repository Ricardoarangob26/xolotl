/*
 * Postura de nube (Fase 2, vía azul) con Prowler. Sin conexión ni credenciales propias: fiel a
 * "depende de ti". En modo advisory entregamos cómo correr Prowler contra Azure con una identidad
 * de SOLO LECTURA (roles Reader + Security Reader) y salida JSON (OCSF); tú lo corres y traes el
 * archivo; Xolotl lo parsea a hallazgos. Prowler ya asigna severidad por check: la respetamos.
 *
 * Primer proveedor: Azure. El parser de OCSF es común, así que AWS/GCP entran con el mismo armazón.
 */
import { normSeverity, type RawFinding, type Severity } from "./findings.js";

export type CloudProvider = "azure";

export function cloudAdvisory(provider: CloudProvider, target?: string): string {
  return [
    `## Tier 1 · advisory — postura de Azure con Prowler (solo lectura)${target ? ` · ${target}` : ""}`,
    "Prowler evalúa la suscripción contra CIS y otros marcos. Solo lee: con una identidad de solo",
    "lectura (roles «Reader» + «Security Reader» sobre la suscripción) no cambia nada.",
    "",
    "1. Instala Prowler y autentícate en Azure:",
    "     pipx install prowler            # o: pip install prowler",
    "     az login                        # o una identidad de servicio con los roles de lectura",
    "",
    "2. Ejecuta Prowler sobre tu suscripción con salida JSON (OCSF):",
    "     prowler azure --az-cli-auth --output-formats json-ocsf --output-directory ./prowler-out",
    "   (añade --subscription-ids <id> para acotar; para una identidad de servicio usa --sp-env-auth",
    "    con AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID.)",
    "",
    "3. Trae el archivo JSON: ./prowler-out/*.ocsf.json",
    "",
    "Volver: scan_cloud con provider=azure y collected_file=<ruta del .ocsf.json>.",
  ].join("\n");
}

// ───────────────────────────── Parseo OCSF de Prowler ─────────────────────────────

interface Ocsf {
  status_code?: string;
  Status?: string;
  severity?: string;
  Severity?: string;
  status_detail?: string;
  StatusExtended?: string;
  metadata?: { event_code?: string };
  unmapped?: { check_id?: string };
  CheckID?: string;
  finding_info?: { title?: string };
  CheckTitle?: string;
  remediation?: { desc?: string };
  Remediation?: { Recommendation?: { Text?: string } };
  resources?: Array<{ name?: string; uid?: string; region?: string; group?: { name?: string } }>;
  ResourceId?: string;
  Region?: string;
  ServiceName?: string;
  cloud?: { provider?: string; region?: string; account?: { name?: string; uid?: string } };
}

const pick = (...xs: Array<string | undefined>) => xs.find((x) => x != null && x !== "");

interface Agg {
  severity: Severity;
  title: string;
  remediation?: string;
  service?: string;
  resources: Set<string>;
  manual: boolean;
}

export interface CloudParse {
  findings: RawFinding[];
  totals: { fail: number; manual: number; pass: number };
  account: string;
}

export function parseProwler(provider: CloudProvider, text: string, account = "suscripción"): CloudParse {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("El archivo no es un JSON válido de Prowler. Genéralo con --output-formats json-ocsf.");
  }
  const items: Ocsf[] = Array.isArray(data) ? (data as Ocsf[]) : ((data as { findings?: Ocsf[] }).findings ?? []);
  if (!items.length) throw new Error("No se encontraron hallazgos en el JSON. ¿Es la salida OCSF de Prowler (prowler azure --output-formats json-ocsf)?");

  const totals = { fail: 0, manual: 0, pass: 0 };
  const byCheck = new Map<string, Agg>();
  let accountName = account;

  for (const it of items) {
    const status = String(pick(it.status_code, it.Status) ?? "").toUpperCase();
    if (status === "PASS") {
      totals.pass++;
      continue;
    }
    const manual = status === "MANUAL";
    if (manual) totals.manual++;
    else if (status === "FAIL") totals.fail++;
    else continue;

    const checkId = pick(it.metadata?.event_code, it.unmapped?.check_id, it.CheckID) ?? "prowler";
    const sevRaw = String(pick(it.severity, it.Severity) ?? "medium").toLowerCase();
    const severity: Severity = manual ? "info" : /^inform/.test(sevRaw) ? "info" : normSeverity(sevRaw);
    const title = pick(it.finding_info?.title, it.CheckTitle, checkId) ?? checkId;
    const remediation = pick(it.remediation?.desc, it.Remediation?.Recommendation?.Text);
    const res = it.resources?.[0];
    const resource = pick(res?.name, res?.uid, it.ResourceId);
    const region = pick(res?.region, it.cloud?.region, it.Region);
    const service = pick(res?.group?.name, it.ServiceName);
    if (!accountName || accountName === account) accountName = pick(it.cloud?.account?.name, it.cloud?.account?.uid) ?? account;

    const key = `${checkId}|${manual}`;
    const agg = byCheck.get(key) ?? { severity, title, remediation, service, resources: new Set<string>(), manual };
    if (resource) agg.resources.add(`${resource}${region ? ` (${region})` : ""}`);
    byCheck.set(key, agg);
  }

  const findings: RawFinding[] = [];
  for (const [key, a] of byCheck) {
    const checkId = key.split("|")[0];
    const res = [...a.resources];
    findings.push({
      tool: "prowler",
      category: "config",
      severity: a.severity,
      ruleId: `PROWLER-${checkId}`,
      title: a.title,
      description: `Prowler (Azure)${a.service ? ` · ${a.service}` : ""}${a.manual ? " · requiere revisión manual" : ""}${res.length ? ` · ${res.length} recurso(s) afectado(s)` : ""}.`,
      remediation: a.remediation,
      evidence: res.length ? res.slice(0, 20).join("\n") + (res.length > 20 ? `\n… (+${res.length - 20})` : "") : undefined,
      location: { target: accountName },
    });
  }
  return { findings, totals, account: accountName };
}
