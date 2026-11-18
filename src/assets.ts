/*
 * Criticidad de negocio por activo (Fase 1.5). La fija el usuario: no todos los sistemas
 * valen lo mismo. Un servidor de producción con datos de clientes pesa más que un entorno de
 * pruebas desechable, así que la misma vulnerabilidad debe priorizarse distinto según dónde esté.
 *
 * Es un mapa pequeño activo → nivel en ~/.xolotl/assets.json, al estilo de scope.json y triage.json.
 * Lo leen el motor de riesgo (risk.ts) y el inventario (inventory.ts); no sale de la máquina.
 */
import fs from "node:fs";
import { ASSETS_FILE, ensureDirs } from "./config.js";

export const CRITICALITY = ["critica", "alta", "normal", "baja"] as const;
export type Criticality = (typeof CRITICALITY)[number];

/** Multiplicador sobre la prioridad de riesgo (0..100, se recorta después). */
const MULT: Record<Criticality, number> = { critica: 1.15, alta: 1.07, normal: 1.0, baja: 0.85 };
export const criticalityMult = (c: Criticality): number => MULT[c];

export interface AssetEntry {
  criticality: Criticality;
  note?: string;
  at: string;
}

export type AssetDb = Record<string, AssetEntry>;

const normKey = (a: string) => a.trim().toLowerCase();

export function loadAssets(): AssetDb {
  try {
    return JSON.parse(fs.readFileSync(ASSETS_FILE, "utf8")) as AssetDb;
  } catch {
    return {};
  }
}

function saveAssets(db: AssetDb): void {
  ensureDirs();
  fs.writeFileSync(ASSETS_FILE, JSON.stringify(db, null, 2));
}

export function setCriticality(asset: string, level: Criticality, note?: string): AssetEntry {
  const db = loadAssets();
  const entry: AssetEntry = { criticality: level, note: note?.trim() || undefined, at: new Date().toISOString() };
  db[normKey(asset)] = entry;
  saveAssets(db);
  return entry;
}

export function clearCriticality(asset: string): boolean {
  const db = loadAssets();
  if (!db[normKey(asset)]) return false;
  delete db[normKey(asset)];
  saveAssets(db);
  return true;
}

/** Importa criticidades de un traspaso: merge por activo, o reemplazo total. */
export function importAssets(incoming: AssetDb, replace: boolean): number {
  const db = replace ? {} : loadAssets();
  for (const [k, v] of Object.entries(incoming ?? {})) {
    if (v?.criticality) db[normKey(k)] = { criticality: v.criticality, note: v.note, at: v.at ?? new Date().toISOString() };
  }
  saveAssets(db);
  return Object.keys(db).length;
}

/** Criticidad de un activo: coincidencia exacta y, si falla, quitando el prefijo "usuario@". */
export function criticalityOf(asset: string, db: AssetDb = loadAssets()): AssetEntry | undefined {
  const k = normKey(asset);
  if (db[k]) return db[k];
  const at = k.indexOf("@");
  if (at >= 0 && db[k.slice(at + 1)]) return db[k.slice(at + 1)];
  return undefined;
}
