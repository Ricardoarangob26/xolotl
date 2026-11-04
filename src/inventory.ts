/*
 * Inventario persistente y local. Cada corrida alimenta una base que crece: qué activos
 * se han visto, qué hallazgos aparecen y desaparecen, con qué herramienta y desde cuándo.
 * Es la memoria larga de Xolotl, aparte del triage.
 *
 * Motor: SQLite nativo del runtime (node:sqlite, Node 22.5+) si está; si no, un JSON local.
 * En ambos casos el archivo vive en ~/.xolotl y no sale de la máquina.
 */
import fs from "node:fs";
import { DB_FILE, INVENTORY_FILE, ensureDirs } from "./config.js";
import type { Finding } from "./findings.js";
import type { RunMeta } from "./store.js";

export interface FindingRow {
  fingerprint: string;
  asset: string;
  category: string;
  severity: string;
  rule_id: string;
  title: string;
  pkg_name: string | null;
  pkg_version: string | null;
  fixed_version: string | null;
  cve: string | null;
  tool_used: string;
  status: string;
  first_seen: string;
  last_seen: string;
  first_run: string;
  last_run: string;
  runs: number;
}

export interface RunRow {
  id: string;
  kind: string;
  target: string;
  started_at: string;
  finished_at: string;
  total: number;
}

interface Link {
  run_id: string;
  fingerprint: string;
  severity: string;
  status: string;
}

interface Backend {
  engine: "sqlite" | "json";
  upsertFinding(row: FindingRow): void;
  insertRun(row: RunRow): void;
  linkRunFinding(l: Link): void;
  allFindings(): FindingRow[];
  allRuns(): RunRow[];
  linksForFinding(fp: string): Link[];
  begin(): void;
  commit(): void;
}

// ───────────────────────────── SQLite ─────────────────────────────
function sqliteBackend(): Backend | null {
  const sqlite = (process as unknown as { getBuiltinModule?: (id: string) => unknown }).getBuiltinModule?.("node:sqlite") as
    | { DatabaseSync: new (p: string) => SqliteDb }
    | undefined;
  if (!sqlite?.DatabaseSync) return null;
  try {
    ensureDirs();
    const db = new sqlite.DatabaseSync(DB_FILE);
    db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY, kind TEXT, target TEXT,
        started_at TEXT, finished_at TEXT, total INTEGER
      );
      CREATE TABLE IF NOT EXISTS findings (
        fingerprint TEXT PRIMARY KEY, asset TEXT, category TEXT, severity TEXT,
        rule_id TEXT, title TEXT, pkg_name TEXT, pkg_version TEXT, fixed_version TEXT,
        cve TEXT, tool_used TEXT, status TEXT,
        first_seen TEXT, last_seen TEXT, first_run TEXT, last_run TEXT, runs INTEGER
      );
      CREATE TABLE IF NOT EXISTS run_findings (
        run_id TEXT, fingerprint TEXT, severity TEXT, status TEXT,
        PRIMARY KEY (run_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_find_asset ON findings(asset);
      CREATE INDEX IF NOT EXISTS idx_find_cat ON findings(category);
      CREATE INDEX IF NOT EXISTS idx_find_status ON findings(status);
    `);
    const cols =
      "fingerprint,asset,category,severity,rule_id,title,pkg_name,pkg_version,fixed_version,cve,tool_used,status,first_seen,last_seen,first_run,last_run,runs";
    const up = db.prepare(
      `INSERT INTO findings (${cols}) VALUES (${cols.split(",").map(() => "?").join(",")})
       ON CONFLICT(fingerprint) DO UPDATE SET
         asset=excluded.asset, category=excluded.category, severity=excluded.severity,
         rule_id=excluded.rule_id, title=excluded.title, pkg_name=excluded.pkg_name,
         pkg_version=excluded.pkg_version, fixed_version=excluded.fixed_version, cve=excluded.cve,
         tool_used=excluded.tool_used, status=excluded.status,
         last_seen=excluded.last_seen, last_run=excluded.last_run, runs=excluded.runs`,
    );
    const insRun = db.prepare("INSERT OR REPLACE INTO runs (id,kind,target,started_at,finished_at,total) VALUES (?,?,?,?,?,?)");
    const insLink = db.prepare("INSERT OR REPLACE INTO run_findings (run_id,fingerprint,severity,status) VALUES (?,?,?,?)");
    const r2f = (r: FindingRow) =>
      [r.fingerprint, r.asset, r.category, r.severity, r.rule_id, r.title, r.pkg_name, r.pkg_version, r.fixed_version, r.cve, r.tool_used, r.status, r.first_seen, r.last_seen, r.first_run, r.last_run, r.runs] as const;
    return {
      engine: "sqlite",
      upsertFinding: (r) => up.run(...r2f(r)),
      insertRun: (r) => insRun.run(r.id, r.kind, r.target, r.started_at, r.finished_at, r.total),
      linkRunFinding: (l) => insLink.run(l.run_id, l.fingerprint, l.severity, l.status),
      allFindings: () => db.prepare("SELECT * FROM findings").all() as FindingRow[],
      allRuns: () => db.prepare("SELECT * FROM runs ORDER BY started_at").all() as RunRow[],
      linksForFinding: (fp) => db.prepare("SELECT * FROM run_findings WHERE fingerprint=?").all(fp) as Link[],
      begin: () => db.exec("BEGIN"),
      commit: () => db.exec("COMMIT"),
    };
  } catch {
    return null;
  }
}

interface SqliteDb {
  exec(sql: string): void;
  prepare(sql: string): { run: (...a: unknown[]) => unknown; all: (...a: unknown[]) => unknown[] };
}

// ───────────────────────────── JSON (respaldo) ─────────────────────────────
function jsonBackend(): Backend {
  interface Data {
    runs: RunRow[];
    findings: Record<string, FindingRow>;
    links: Link[];
  }
  let data: Data = { runs: [], findings: {}, links: [] };
  try {
    data = { runs: [], findings: {}, links: [], ...JSON.parse(fs.readFileSync(INVENTORY_FILE, "utf8")) };
  } catch {
    /* primer uso */
  }
  const save = () => {
    ensureDirs();
    fs.writeFileSync(INVENTORY_FILE, JSON.stringify(data, null, 2));
  };
  let dirty = false;
  return {
    engine: "json",
    upsertFinding: (r) => {
      data.findings[r.fingerprint] = r;
      dirty = true;
    },
    insertRun: (r) => {
      data.runs = data.runs.filter((x) => x.id !== r.id).concat(r);
      dirty = true;
    },
    linkRunFinding: (l) => {
      data.links = data.links.filter((x) => !(x.run_id === l.run_id && x.fingerprint === l.fingerprint)).concat(l);
      dirty = true;
    },
    allFindings: () => Object.values(data.findings),
    allRuns: () => data.runs.slice().sort((a, b) => a.started_at.localeCompare(b.started_at)),
    linksForFinding: (fp) => data.links.filter((l) => l.fingerprint === fp),
    begin: () => {},
    commit: () => {
      if (dirty) save();
      dirty = false;
    },
  };
}

let _backend: Backend | null = null;
function backend(): Backend {
  if (!_backend) _backend = sqliteBackend() ?? jsonBackend();
  return _backend;
}

export const inventoryEngine = () => backend().engine;

// ───────────────────────────── Activo al que pertenece un hallazgo ─────────────────────────────
function assetOf(f: Finding, meta: RunMeta): string {
  const l = f.location ?? {};
  if (l.target) return l.target;
  if (l.url) {
    try {
      return new URL(l.url).host;
    } catch {
      return l.url;
    }
  }
  return meta.target;
}

/** Vuelca una corrida terminada al inventario: altas, re-vistas y enlaces corrida↔hallazgo. */
export function recordRun(meta: RunMeta, findings: Finding[]): void {
  const b = backend();
  const when = meta.finishedAt ?? new Date().toISOString();
  const existing = new Map(b.allFindings().map((r) => [r.fingerprint, r]));
  b.begin();
  try {
    b.insertRun({
      id: meta.id,
      kind: meta.kind,
      target: meta.target,
      started_at: meta.startedAt,
      finished_at: when,
      total: findings.length,
    });
    for (const f of findings) {
      const status = f.triage?.status ?? "open";
      const prev = existing.get(f.fingerprint);
      const tools = new Set([...(prev?.tool_used?.split(",").filter(Boolean) ?? []), ...f.tools]);
      b.upsertFinding({
        fingerprint: f.fingerprint,
        asset: assetOf(f, meta),
        category: f.category,
        severity: f.severity,
        rule_id: f.ruleId,
        title: f.title,
        pkg_name: f.package?.name ?? null,
        pkg_version: f.package?.version ?? null,
        fixed_version: f.package?.fixedVersion ?? null,
        cve: (f.cve ?? []).join(",") || null,
        tool_used: [...tools].join(","),
        status,
        first_seen: prev?.first_seen ?? when,
        last_seen: when,
        first_run: prev?.first_run ?? meta.id,
        last_run: meta.id,
        runs: (prev?.runs ?? 0) + 1,
      });
      b.linkRunFinding({ run_id: meta.id, fingerprint: f.fingerprint, severity: f.severity, status });
    }
    b.commit();
  } catch (e) {
    b.commit();
    throw e;
  }
}

// ───────────────────────────── Consultas ─────────────────────────────
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SUPPRESSED = new Set(["false_positive", "accepted_risk", "fixed"]);

export interface FindingFilter {
  severity?: string;
  category?: string;
  asset?: string;
  status?: string;
  seen?: "all" | "latest" | "new" | "gone";
  includeSuppressed?: boolean;
  limit?: number;
}

function latestRunId(b: Backend): string | undefined {
  return b.allRuns().slice(-1)[0]?.id;
}

export function queryFindings(opt: FindingFilter = {}): FindingRow[] {
  const b = backend();
  const latest = latestRunId(b);
  let rows = b.allFindings();
  if (opt.severity) rows = rows.filter((r) => r.severity === opt.severity);
  if (opt.category) rows = rows.filter((r) => r.category === opt.category);
  if (opt.status) rows = rows.filter((r) => r.status === opt.status);
  if (opt.asset) rows = rows.filter((r) => r.asset.includes(opt.asset!));
  if (!opt.includeSuppressed) rows = rows.filter((r) => !SUPPRESSED.has(r.status));
  if (opt.seen === "latest") rows = rows.filter((r) => r.last_run === latest);
  if (opt.seen === "new") rows = rows.filter((r) => r.first_run === latest);
  if (opt.seen === "gone") rows = rows.filter((r) => r.last_run !== latest);
  rows.sort((a, b2) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b2.severity) || b2.last_seen.localeCompare(a.last_seen));
  return opt.limit ? rows.slice(0, opt.limit) : rows;
}

export interface AssetRow {
  asset: string;
  categories: string[];
  total: number;
  bySeverity: Record<string, number>;
  firstSeen: string;
  lastSeen: string;
}

export function listAssets(): AssetRow[] {
  const map = new Map<string, AssetRow>();
  for (const r of queryFindings({ includeSuppressed: false })) {
    let a = map.get(r.asset);
    if (!a) {
      a = { asset: r.asset, categories: [], total: 0, bySeverity: {}, firstSeen: r.first_seen, lastSeen: r.last_seen };
      map.set(r.asset, a);
    }
    a.total++;
    a.bySeverity[r.severity] = (a.bySeverity[r.severity] ?? 0) + 1;
    if (!a.categories.includes(r.category)) a.categories.push(r.category);
    if (r.first_seen < a.firstSeen) a.firstSeen = r.first_seen;
    if (r.last_seen > a.lastSeen) a.lastSeen = r.last_seen;
  }
  return [...map.values()].sort((a, b) => b.total - a.total);
}

export function findingHistory(fingerprint: string): { finding?: FindingRow; timeline: Array<Link & { kind: string; at: string }> } {
  const b = backend();
  const finding = b.allFindings().find((r) => r.fingerprint === fingerprint);
  const runs = new Map(b.allRuns().map((r) => [r.id, r]));
  const timeline = b
    .linksForFinding(fingerprint)
    .map((l) => ({ ...l, kind: runs.get(l.run_id)?.kind ?? "?", at: runs.get(l.run_id)?.finished_at ?? "" }))
    .sort((a, b2) => a.at.localeCompare(b2.at));
  return { finding, timeline };
}

export interface InventorySummary {
  engine: "sqlite" | "json";
  runs: number;
  assets: number;
  findingsActive: number;
  findingsTotal: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  lastRun?: { id: string; kind: string; target: string; at: string };
}

export function inventorySummary(): InventorySummary {
  const b = backend();
  const all = b.allFindings();
  const active = all.filter((r) => !SUPPRESSED.has(r.status));
  const bySeverity: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const r of active) {
    bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
    byCategory[r.category] = (byCategory[r.category] ?? 0) + 1;
  }
  const last = b.allRuns().slice(-1)[0];
  return {
    engine: b.engine,
    runs: b.allRuns().length,
    assets: new Set(active.map((r) => r.asset)).size,
    findingsActive: active.length,
    findingsTotal: all.length,
    bySeverity,
    byCategory,
    lastRun: last ? { id: last.id, kind: last.kind, target: last.target, at: last.finished_at } : undefined,
  };
}
