/*
 * Plan de compromiso (reglas de enfrentamiento). Materializa el "candado de la vía roja":
 * registra quién autoriza, con qué referencia, hasta cuándo, sobre qué alcance, en qué ventanas
 * y bajo qué reglas se puede validar ofensivamente la infraestructura PROPIA. No ejecuta nada:
 * es el documento de gobernanza que cualquier capacidad roja debe respetar antes de actuar.
 *
 * El alcance concreto vive en `dast_scope` (scope.json); aquí se guarda el marco: autorización,
 * vigencia, ventanas, exclusiones y el contacto de parada. Viaja en el `handoff`.
 */
import fs from "node:fs";
import { ENGAGEMENT_FILE, ensureDirs } from "./config.js";

export const ENGAGEMENT_VERSION = "1";

export interface Engagement {
  version: string;
  name: string;
  org: string; // organización propia a la que pertenecen los activos
  authorized_by: string;
  authorization_ref: string; // ticket, contrato, acta
  authorized_from?: string; // ISO date (YYYY-MM-DD)
  authorized_until?: string; // ISO date (YYYY-MM-DD)
  windows: string[]; // ventanas permitidas, texto libre
  exclusions: string[]; // explícitamente fuera de alcance
  rules: string[]; // reglas de enfrentamiento adicionales a las del candado
  emergency_contact: string; // a quién avisar / orden de parada
  default_tier: "advisory" | "execute";
  created_at: string;
  updated_at: string;
}

/** El candado: reglas duras de la vía roja, siempre presentes, no editables. */
export const HARD_RULES: string[] = [
  "Solo activos propios dentro del alcance registrado en dast_scope; el objetivo se valida contra el alcance antes de cada acción.",
  "Tier 1 (advisory) por defecto: el servidor entrega el comando y tú lo corres. Tier 2 (ejecución) pide aprobación por comando y registra quién aprobó.",
  "Nada destructivo; nada en producción fuera de la ventana acordada.",
  "Credenciales y artefactos de prueba sintéticos, nunca datos reales de clientes.",
  "Nada contra terceros. Fuera incluso de la vía roja: phishing e ingeniería social, C2 real, exfiltración de datos reales, persistencia duradera y anonimato del operador.",
];

export function loadEngagement(): Engagement | null {
  try {
    const e = JSON.parse(fs.readFileSync(ENGAGEMENT_FILE, "utf8")) as Engagement;
    return e && e.version ? e : null;
  } catch {
    return null;
  }
}

function save(e: Engagement) {
  ensureDirs();
  fs.writeFileSync(ENGAGEMENT_FILE, JSON.stringify(e, null, 2));
}

export function clearEngagement(): boolean {
  try {
    fs.unlinkSync(ENGAGEMENT_FILE);
    return true;
  } catch {
    return false;
  }
}

export interface EngagementPatch {
  name?: string;
  org?: string;
  authorized_by?: string;
  authorization_ref?: string;
  authorized_from?: string;
  authorized_until?: string;
  windows?: string[];
  exclusions?: string[];
  rules?: string[];
  emergency_contact?: string;
  default_tier?: "advisory" | "execute";
}

const isDate = (s?: string) => !s || /^\d{4}-\d{2}-\d{2}$/.test(s);

/** Crea o actualiza el plan (merge de los campos dados). Valida fechas y vigencia. */
export function setEngagement(patch: EngagementPatch): Engagement {
  const prev = loadEngagement();
  const now = new Date().toISOString();
  for (const [k, v] of [
    ["authorized_from", patch.authorized_from],
    ["authorized_until", patch.authorized_until],
  ] as const) {
    if (!isDate(v)) throw new Error(`${k} debe tener formato YYYY-MM-DD.`);
  }
  if (!prev && !patch.name?.trim()) throw new Error("El primer registro del plan necesita al menos 'name' (nombre del compromiso).");
  const merged: Engagement = {
    version: ENGAGEMENT_VERSION,
    name: patch.name?.trim() ?? prev?.name ?? "",
    org: patch.org?.trim() ?? prev?.org ?? "",
    authorized_by: patch.authorized_by?.trim() ?? prev?.authorized_by ?? "",
    authorization_ref: patch.authorization_ref?.trim() ?? prev?.authorization_ref ?? "",
    authorized_from: patch.authorized_from ?? prev?.authorized_from,
    authorized_until: patch.authorized_until ?? prev?.authorized_until,
    windows: patch.windows ?? prev?.windows ?? [],
    exclusions: patch.exclusions ?? prev?.exclusions ?? [],
    rules: patch.rules ?? prev?.rules ?? [],
    emergency_contact: patch.emergency_contact?.trim() ?? prev?.emergency_contact ?? "",
    default_tier: patch.default_tier ?? prev?.default_tier ?? "advisory",
    created_at: prev?.created_at ?? now,
    updated_at: now,
  };
  if (merged.authorized_from && merged.authorized_until && merged.authorized_from > merged.authorized_until) {
    throw new Error("authorized_from no puede ser posterior a authorized_until.");
  }
  save(merged);
  return merged;
}

export interface EngagementStatus {
  present: boolean;
  authorized: boolean; // hay plan, con autorización y dentro de vigencia
  reasons: string[]; // por qué no está autorizado (o avisos)
  engagement: Engagement | null;
}

/**
 * Evalúa si el marco permite actuar hoy: plan presente, con autorización y referencia, y dentro
 * de la vigencia. Es la base que consultará cualquier capacidad de la vía roja (no la ventana
 * horaria fina, que es texto para que la juzgue la persona).
 */
export function engagementStatus(today = new Date()): EngagementStatus {
  const e = loadEngagement();
  if (!e) return { present: false, authorized: false, reasons: ["No hay plan de compromiso. Regístralo con engagement action=set antes de cualquier prueba de la vía roja."], engagement: null };
  const reasons: string[] = [];
  if (!e.authorized_by) reasons.push("Falta quién autoriza (authorized_by).");
  if (!e.authorization_ref) reasons.push("Falta la referencia de autorización (ticket/contrato/acta).");
  const day = today.toISOString().slice(0, 10);
  if (e.authorized_from && day < e.authorized_from) reasons.push(`La autorización empieza el ${e.authorized_from} (hoy ${day}).`);
  if (e.authorized_until && day > e.authorized_until) reasons.push(`La autorización venció el ${e.authorized_until} (hoy ${day}).`);
  if (!e.authorized_until) reasons.push("Aviso: sin fecha de fin (authorized_until); conviene acotar la vigencia.");
  const blocking = reasons.filter((r) => !r.startsWith("Aviso:"));
  return { present: true, authorized: blocking.length === 0, reasons, engagement: e };
}

/** Importa el plan de un traspaso: reemplaza si llega uno, conserva el actual si no. */
export function importEngagement(e: Engagement | null | undefined): boolean {
  if (!e || !e.version) return false;
  save({ ...e, version: ENGAGEMENT_VERSION, updated_at: new Date().toISOString() });
  return true;
}

/** Documento de reglas de enfrentamiento en Markdown (plantilla exportable, firmable). */
export function engagementMarkdown(e: Engagement, scope: string[]): string {
  const st = engagementStatus();
  const estado = !st.present ? "sin plan" : st.authorized ? "autorización vigente" : "autorización NO vigente";
  const line = (label: string, v?: string) => `- **${label}:** ${v && v.trim() ? v : "_(pendiente)_"}`;
  const out: string[] = [];
  out.push(`# Reglas de enfrentamiento — ${e.name || "(sin nombre)"}`, "");
  out.push(`> Estado: **${estado}**. Documento de gobernanza de la vía roja de Xolotl. No autoriza por sí solo: refleja la autorización registrada.`, "");
  out.push("## Autorización", "");
  out.push(line("Organización (activos propios)", e.org));
  out.push(line("Autoriza", e.authorized_by));
  out.push(line("Referencia de autorización", e.authorization_ref));
  out.push(line("Vigencia", `${e.authorized_from ?? "(inicio sin fijar)"} → ${e.authorized_until ?? "(fin sin fijar)"}`));
  out.push(line("Contacto / orden de parada", e.emergency_contact));
  out.push(line("Tier por defecto", e.default_tier === "advisory" ? "Tier 1 (advisory)" : "Tier 2 (ejecución)"));
  out.push("", "## Alcance autorizado", "");
  if (scope.length) for (const s of scope) out.push(`- ${s}`);
  else out.push("_Sin objetivos en dast_scope. Regístralos con dast_scope action=add._");
  if (e.exclusions.length) {
    out.push("", "### Exclusiones (explícitamente fuera de alcance)", "");
    for (const x of e.exclusions) out.push(`- ${x}`);
  }
  out.push("", "## Ventanas permitidas", "");
  if (e.windows.length) for (const w of e.windows) out.push(`- ${w}`);
  else out.push("_Sin ventanas definidas; acuerda y registra las ventanas antes de ejecutar (Tier 2)._");
  out.push("", "## Reglas de enfrentamiento", "");
  out.push("Reglas duras (candado de la vía roja, no negociables):", "");
  for (const r of HARD_RULES) out.push(`- ${r}`);
  if (e.rules.length) {
    out.push("", "Reglas adicionales de este compromiso:", "");
    for (const r of e.rules) out.push(`- ${r}`);
  }
  out.push("", "---", `_Generado por Xolotl el ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC. Creado ${e.created_at.slice(0, 10)}, actualizado ${e.updated_at.slice(0, 10)}._`);
  return out.join("\n");
}
