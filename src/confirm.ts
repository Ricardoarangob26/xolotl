/*
 * Motor de confirmación (revalidación no destructiva). Idea tomada del diseño de escáneres
 * serios y adaptada a un enfoque DEFENSIVO: "el LLM propone, el gate determinista dispone".
 *
 * Un confirmador vuelve a comprobar UN hallazgo concreto de forma local, determinista y SIN
 * tocar ningún sistema (no envía exploits, no se conecta a objetivos, no modifica nada): solo
 * relee archivos locales ya escaneados. Devuelve uno de tres veredictos, nunca una adivinanza:
 *
 *   - confirmed    : la condición del hallazgo SIGUE presente (con evidencia).
 *   - not_present  : ya NO está (probablemente corregida; conviene reescanear para cerrarla).
 *   - inconclusive : no se pudo comprobar aquí (requiere reescaneo del activo, acceso o red).
 *
 * Regla de oro: si un confirmador no pudo ejecutarse, el veredicto es inconclusive, JAMÁS
 * not_present. "No pude comprobarlo" no es lo mismo que "ya no existe".
 */
import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./findings.js";

export type Verdict = "confirmed" | "not_present" | "inconclusive";

export interface Confirmation {
  verdict: Verdict;
  method: string; // la acción exacta que se ejecutó (determinista, no destructiva)
  note: string; // explicación legible
  evidence?: string; // cita mínima; nunca el valor de un secreto
}

const inconclusive = (method: string, note: string): Confirmation => ({ verdict: "inconclusive", method, note });

/** Normaliza para comparar fragmentos de código sin ruido de espacios. */
const norm = (s: string) => s.replace(/\s+/g, " ").trim();

function resolveFile(root: string, file: string): string {
  return path.isAbsolute(file) ? file : path.join(root, file);
}

function readFileSafe(abs: string): string | null {
  try {
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > 5 * 1024 * 1024) return null;
    return fs.readFileSync(abs, "utf8");
  } catch {
    return null;
  }
}

const pkgNameVariants = (name: string): string[] => {
  const low = name.toLowerCase();
  return [...new Set([name, low, low.replace(/[-_.]+/g, "-"), low.replace(/[-_.]+/g, "_")])];
};

/** SCA / dependencias: ¿el manifiesto sigue fijando la versión vulnerable? */
function confirmSca(f: Finding, root: string): Confirmation {
  const file = f.location?.file;
  const pkg = f.package;
  if (!file || !pkg?.name || !pkg.version) return inconclusive("—", "El hallazgo no apunta a un manifiesto con paquete y versión; revalida con scan_static sobre el proyecto.");
  const abs = resolveFile(root, file);
  const text = readFileSafe(abs);
  if (text == null) return inconclusive(`leer ${file}`, "No pude leer el manifiesto (¿se movió o es otra máquina?). Revalida reescaneando el proyecto.");

  const names = pkgNameVariants(pkg.name);
  const lines = text.split(/\r?\n/);
  const ver = pkg.version;
  const hasVer = (l: string) => l.includes(ver);
  const hasName = (l: string) => names.some((n) => l.toLowerCase().includes(n.toLowerCase()));

  const pinned = lines.find((l) => hasName(l) && hasVer(l));
  if (pinned) {
    return {
      verdict: "confirmed",
      method: `buscar ${pkg.name}==${ver} en ${file}`,
      note: `El manifiesto sigue fijando ${pkg.name} ${ver}${pkg.fixedVersion ? `, por debajo de la corrección ${pkg.fixedVersion}` : ""}. Actualiza la dependencia y reescanea.`,
      evidence: norm(pinned).slice(0, 160),
    };
  }
  if (lines.some(hasName)) {
    return {
      verdict: "not_present",
      method: `buscar ${pkg.name}==${ver} en ${file}`,
      note: `${pkg.name} sigue en ${file} pero ya no con la versión ${ver}. Reescanea para confirmar que la nueva versión no tiene otras CVE.`,
    };
  }
  return { verdict: "not_present", method: `buscar ${pkg.name} en ${file}`, note: `${pkg.name} ya no aparece en ${file}. Reescanea para cerrar el hallazgo.` };
}

/** Archivos anclados (SAST, secreto, IaC): ¿el patrón señalado sigue en el archivo? */
function confirmFileAnchored(f: Finding, root: string): Confirmation {
  const file = f.location?.file;
  if (!file) return inconclusive("—", "El hallazgo no apunta a un archivo local; revalida reescaneando.");
  const abs = resolveFile(root, file);
  const text = readFileSafe(abs);
  if (text == null) return inconclusive(`leer ${file}`, "No pude leer el archivo (¿se movió, se borró o es otra máquina?). No asumo que esté corregido.");

  const lines = text.split(/\r?\n/);
  const line = f.location?.startLine;
  const isSecret = f.category === "secret";
  const method = `releer ${file}${line ? `:${line}` : ""}`;

  // Con fragmento de código: comprobar que el patrón exacto sigue presente (en su línea o movido).
  const snippet = f.snippet ? norm(f.snippet) : "";
  if (snippet) {
    const atLine = line && lines[line - 1] ? norm(lines[line - 1]) : "";
    const stillAtLine = atLine && (atLine.includes(snippet) || snippet.includes(atLine));
    const stillInFile = norm(text).includes(snippet);
    if (stillAtLine || stillInFile) {
      return {
        verdict: "confirmed",
        method,
        note: stillAtLine
          ? `El código señalado no cambió en ${file}${line ? `:${line}` : ""}.`
          : `El código señalado sigue en ${file} aunque cambió de línea. ${isSecret ? "El secreto sigue expuesto: revócalo y rótalo." : "Reescanea para confirmar que la regla lo sigue marcando."}`,
        evidence: isSecret ? "coincidencia de secreto presente (valor omitido)" : snippet.slice(0, 160),
      };
    }
    return {
      verdict: "not_present",
      method,
      note: `El código señalado ya no está en ${file}. Probablemente corregido; reescanea con la herramienta original para cerrarlo${isSecret ? ". Aun así, rota el secreto: estuvo expuesto en el historial" : ""}.`,
    };
  }

  // Secreto sin fragmento: solo sé que había algo en esa línea. Si la línea sigue con contenido, no concluyo.
  if (isSecret && line) {
    if (!lines[line - 1]?.trim()) return { verdict: "not_present", method, note: `La línea ${line} de ${file} está vacía o desapareció. Rota el secreto igualmente: estuvo expuesto.` };
    return inconclusive(method, `No tengo el patrón exacto del secreto para compararlo sin exponerlo. Revisa ${file}:${line} a mano o reescanea con gitleaks.`);
  }
  return inconclusive(method, "No tengo un patrón para comparar; reescanea con la herramienta original.");
}

/** Categorías que requieren tocar el objetivo: no se revalidan localmente. */
function confirmLive(f: Finding): Confirmation {
  const how: Record<string, string> = {
    network: "scan_network sobre el host (respeta el alcance y el Tier)",
    config: "scan_host con el recolector o por SSH",
    host: "scan_host con el recolector o por SSH",
    dast: "scan_dast contra el objetivo autorizado en dast_scope",
    container: "scan_container_image sobre la imagen",
  };
  const tool = how[f.category] ?? "el escaneo correspondiente";
  return inconclusive(
    "ninguna (revalidación local no aplica)",
    `Revalidar un hallazgo de ${f.category} exige volver a probar el activo, que no es una comprobación local. Repite ${tool} y compara con runs_diff. No lo doy por corregido sin esa prueba.`,
  );
}

/**
 * Revalida un hallazgo. `root` es la raíz del proyecto escaneado (para resolver rutas relativas):
 * el objetivo de la corrida para análisis de código.
 */
export function confirmFinding(f: Finding, root: string): Confirmation {
  switch (f.category) {
    case "sca":
      return confirmSca(f, root);
    case "sast":
    case "iac":
    case "secret":
      return confirmFileAnchored(f, root);
    default:
      return confirmLive(f);
  }
}

export const VERDICT_ES: Record<Verdict, string> = {
  confirmed: "CONFIRMADO",
  not_present: "RESUELTO",
  inconclusive: "NO CONCLUYENTE",
};
