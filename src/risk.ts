/*
 * Puntuación de riesgo (Fase 1.5). Toma la severidad del escáner y, cuando el hallazgo
 * tiene una CVE, la cruza con dos feeds públicos cacheados en local:
 *   - EPSS (FIRST): probabilidad estimada de explotación en 30 días.
 *   - CISA KEV: catálogo de vulnerabilidades con explotación activa confirmada.
 *
 * Fiel al principio de Xolotl: los feeds son OPCIONALES. Sin ellos la prioridad se calcula
 * solo con la severidad; la descarga (`risk_feeds`) nunca es obligatoria y todo corre offline.
 * Los datos viven en ~/.xolotl/feeds y no salen de la máquina.
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { HOME, ensureDirs } from "./config.js";
import type { Finding, RiskScore, Severity } from "./findings.js";

export const FEEDS_DIR = path.join(HOME, "feeds");
const KEV_FILE = path.join(FEEDS_DIR, "kev.json");
const EPSS_FILE = path.join(FEEDS_DIR, "epss.csv");

// Feeds oficiales. Solo se descargan si el usuario corre `risk_feeds` con refresh=true.
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz";

/** Severidad → base 0..10 (misma escala que usa el informe SARIF). */
const SEV_BASE: Record<Severity, number> = { critical: 9.5, high: 8, medium: 5.5, low: 3, info: 0.5 };

// Caché por proceso: los feeds son grandes y no cambian durante una corrida.
let _kev: Set<string> | null | undefined;
let _epss: Map<string, number> | null | undefined;

/** CVE explotadas (CISA KEV), o null si el feed no está descargado o está vacío. */
export function loadKev(): Set<string> | null {
  if (_kev !== undefined) return _kev;
  try {
    const raw = JSON.parse(fs.readFileSync(KEV_FILE, "utf8")) as { vulnerabilities?: Array<{ cveID?: string }> };
    const set = new Set<string>();
    for (const v of raw.vulnerabilities ?? []) if (v.cveID) set.add(String(v.cveID).toUpperCase());
    _kev = set.size ? set : null;
  } catch {
    _kev = null;
  }
  return _kev;
}

/** CVE → probabilidad EPSS (0..1), o null si el feed no está descargado. */
export function loadEpss(): Map<string, number> | null {
  if (_epss !== undefined) return _epss;
  try {
    const map = new Map<string, number>();
    // CSV grande (~300k filas): cabeceras con '#', luego "cve,epss,percentile".
    for (const line of fs.readFileSync(EPSS_FILE, "utf8").split(/\r?\n/)) {
      if (!line || line[0] === "#") continue;
      const [rawCve, rawEpss] = line.split(",");
      const cve = rawCve?.toUpperCase();
      if (!cve?.startsWith("CVE-")) continue; // salta la fila de cabecera "cve,epss,percentile"
      const epss = Number(rawEpss);
      if (!Number.isNaN(epss)) map.set(cve, epss);
    }
    _epss = map.size ? map : null;
  } catch {
    _epss = null;
  }
  return _epss;
}

function scoreOne(f: Finding, kev: Set<string> | null, epss: Map<string, number> | null): RiskScore {
  const cves = (f.cve ?? []).map((c) => c.toUpperCase());
  const base = SEV_BASE[f.severity];
  const factors: string[] = [`Severidad ${f.severity}`];

  let isKev = false;
  let epssVal: number | undefined;
  for (const c of cves) {
    if (kev?.has(c)) isKev = true;
    const e = epss?.get(c);
    if (e !== undefined) epssVal = Math.max(epssVal ?? 0, e);
  }

  // Factor de explotabilidad: KEV manda; si no, EPSS; si no hay dato, neutro-bajo.
  let exploit: number;
  if (isKev) {
    exploit = 1.0;
    factors.push("En CISA KEV: explotación activa confirmada");
  } else if (epssVal !== undefined) {
    exploit = 0.5 + 0.5 * epssVal;
    factors.push(`EPSS ${(epssVal * 100).toFixed(1)}% de probabilidad de explotación a 30 días`);
  } else {
    exploit = 0.6;
    if (cves.length) factors.push("Sin dato EPSS/KEV para su CVE");
    else if (kev || epss) factors.push("Sin CVE: prioridad por severidad");
  }

  let score = Math.round(base * exploit * 10);
  if (isKev) score = Math.max(score, 90); // explotación activa: nunca por debajo de 90
  score = Math.min(100, Math.max(0, score));

  return { score, severity: f.severity, epss: epssVal, kev: isKev || undefined, factors };
}

/** Puebla `f.risk` en cada hallazgo. Idempotente; seguro sin feeds. */
export function enrichRisk(findings: Finding[]): void {
  const kev = loadKev();
  const epss = loadEpss();
  for (const f of findings) f.risk = scoreOne(f, kev, epss);
}

export interface FeedStatus {
  kev: boolean;
  epss: boolean;
  kevCount: number;
  epssCount: number;
  kevAt?: string;
  epssAt?: string;
}

const fileDate = (p: string): string | undefined => {
  try {
    return fs.statSync(p).mtime.toISOString().slice(0, 10);
  } catch {
    return undefined;
  }
};

export function feedStatus(): FeedStatus {
  const kev = loadKev();
  const epss = loadEpss();
  return {
    kev: !!kev,
    epss: !!epss,
    kevCount: kev?.size ?? 0,
    epssCount: epss?.size ?? 0,
    kevAt: fileDate(KEV_FILE),
    epssAt: fileDate(EPSS_FILE),
  };
}

/** Descarga/actualiza los feeds. Requiere red; devuelve una línea por feed. */
export async function refreshFeeds(which: "all" | "kev" | "epss" = "all"): Promise<string[]> {
  ensureDirs();
  fs.mkdirSync(FEEDS_DIR, { recursive: true });
  const out: string[] = [];

  if (which === "all" || which === "kev") {
    try {
      const res = await fetch(KEV_URL, { headers: { "User-Agent": "xolotl" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      fs.writeFileSync(KEV_FILE, Buffer.from(await res.arrayBuffer()));
      _kev = undefined;
      out.push(`✓ KEV actualizado: ${loadKev()?.size ?? 0} CVE con explotación activa`);
    } catch (e) {
      out.push(`✗ KEV: ${(e as Error).message}`);
    }
  }

  if (which === "all" || which === "epss") {
    try {
      const res = await fetch(EPSS_URL, { headers: { "User-Agent": "xolotl" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const csv = zlib.gunzipSync(Buffer.from(await res.arrayBuffer()));
      fs.writeFileSync(EPSS_FILE, csv);
      _epss = undefined;
      out.push(`✓ EPSS actualizado: ${loadEpss()?.size ?? 0} CVE con probabilidad`);
    } catch (e) {
      out.push(`✗ EPSS: ${(e as Error).message}`);
    }
  }

  return out;
}
