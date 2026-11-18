/*
 * Traspaso de compromiso (Fase 1.5). Empaqueta el estado local de Xolotl en un solo archivo
 * JSON para retomar el trabajo en otra sesión o máquina: alcance autorizado, decisiones de
 * triage, criticidad de activos, el inventario acumulado y (opcional) los artefactos de cada
 * corrida. No incluye los feeds (son grandes y se vuelven a bajar con risk_feeds), solo su estado.
 *
 * Es un archivo local que escribe o lee el usuario; nunca sale de la máquina por su cuenta.
 * Contiene datos sensibles (fragmentos de código, secretos redactados, nombres de host), así que
 * se guarda donde el usuario indique y se trata como confidencial.
 */
import fs from "node:fs";
import path from "node:path";
import { RUNS_DIR, ensureDirs } from "./config.js";
import { importScope, loadScope, ScopeEntry } from "./scope.js";
import { AssetDb, importAssets, loadAssets } from "./assets.js";
import { exportTriage, importTriage } from "./store.js";
import { exportInventory, importInventory, InventoryExport } from "./inventory.js";
import { feedStatus, FeedStatus } from "./risk.js";
import type { Finding } from "./findings.js";

export const HANDOFF_VERSION = "1";

interface RunArtifact {
  id: string;
  meta: unknown;
  findings: Finding[];
}

export interface Handoff {
  xolotl_handoff: string;
  exported_at: string;
  scope: ScopeEntry[];
  triage: Record<string, { status: string; note?: string; at: string; title?: string }>;
  assets: AssetDb;
  feeds: FeedStatus;
  inventory: InventoryExport;
  runs: RunArtifact[];
}

function readAllRuns(): RunArtifact[] {
  let dirs: string[] = [];
  try {
    dirs = fs.readdirSync(RUNS_DIR);
  } catch {
    return [];
  }
  const out: RunArtifact[] = [];
  for (const id of dirs) {
    const metaPath = path.join(RUNS_DIR, id, "meta.json");
    const findingsPath = path.join(RUNS_DIR, id, "findings.json");
    if (!fs.existsSync(metaPath) || !fs.existsSync(findingsPath)) continue;
    try {
      out.push({
        id,
        meta: JSON.parse(fs.readFileSync(metaPath, "utf8")),
        findings: JSON.parse(fs.readFileSync(findingsPath, "utf8")) as Finding[],
      });
    } catch {
      /* corrida ilegible: se omite */
    }
  }
  return out;
}

export function buildHandoff(includeRuns: boolean): Handoff {
  return {
    xolotl_handoff: HANDOFF_VERSION,
    exported_at: new Date().toISOString(),
    scope: loadScope(),
    triage: exportTriage(),
    assets: loadAssets(),
    feeds: feedStatus(),
    inventory: exportInventory(),
    runs: includeRuns ? readAllRuns() : [],
  };
}

export interface ExportStats {
  file: string;
  bytes: number;
  scope: number;
  triage: number;
  assets: number;
  findings: number;
  runs: number;
}

export function writeHandoff(file: string, includeRuns: boolean): ExportStats {
  ensureDirs();
  const h = buildHandoff(includeRuns);
  const json = JSON.stringify(h, null, 2);
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, json);
  return {
    file: path.resolve(file),
    bytes: Buffer.byteLength(json),
    scope: h.scope.length,
    triage: Object.keys(h.triage).length,
    assets: Object.keys(h.assets).length,
    findings: h.inventory.findings.length,
    runs: h.runs.length,
  };
}

export interface ImportStats {
  scope: number;
  triage: number;
  assets: number;
  inventory: { runs: number; findings: number; links: number };
  runsWritten: number;
  runsSkipped: number;
  exportedAt: string;
}

/** Restaura un traspaso. merge por defecto; replace vacía alcance/triage/criticidad antes. */
export function readHandoff(file: string, opts: { replace?: boolean; includeRuns?: boolean } = {}): ImportStats {
  const raw = fs.readFileSync(file, "utf8");
  let h: Handoff;
  try {
    h = JSON.parse(raw) as Handoff;
  } catch {
    throw new Error("El archivo no es un JSON válido.");
  }
  if (!h || h.xolotl_handoff == null) throw new Error("No parece un traspaso de Xolotl (falta xolotl_handoff).");
  if (String(h.xolotl_handoff) !== HANDOFF_VERSION) throw new Error(`Versión de traspaso ${h.xolotl_handoff} no soportada (esperada ${HANDOFF_VERSION}).`);

  const replace = !!opts.replace;
  const scope = importScope(h.scope ?? [], replace);
  const triage = importTriage(h.triage ?? {}, replace);
  const assets = importAssets(h.assets ?? {}, replace);
  const inventory = importInventory(h.inventory ?? { runs: [], findings: [], links: [] });

  let runsWritten = 0;
  let runsSkipped = 0;
  if (opts.includeRuns !== false) {
    ensureDirs();
    for (const r of h.runs ?? []) {
      const dir = path.join(RUNS_DIR, path.basename(r.id));
      if (fs.existsSync(path.join(dir, "meta.json")) && !replace) {
        runsSkipped++;
        continue;
      }
      try {
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, "meta.json"), JSON.stringify(r.meta, null, 2));
        fs.writeFileSync(path.join(dir, "findings.json"), JSON.stringify(r.findings, null, 2));
        runsWritten++;
      } catch {
        /* no se pudo escribir una corrida: se omite sin abortar el resto */
      }
    }
  }

  return { scope, triage, assets, inventory, runsWritten, runsSkipped, exportedAt: h.exported_at };
}
