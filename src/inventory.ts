/*
 * Inventario persistente y local. Cada corrida alimenta una base que crece: qué activos
 * se han visto, qué hallazgos aparecen y desaparecen, con qué herramienta y desde cuándo.
 * Es la memoria larga de Xolotl, aparte del triage.
 *
 * Motor: SQLite nativo del runtime (node:sqlite, Node 22.5+) si está; si no, un JSON local.
 * En ambos casos el archivo vive en ~/.xolotl y no sale de la máquina.
 */
import fs from "node:fs";
import path from "node:path";
import { DB_FILE, INVENTORY_FILE, RUNS_DIR, ensureDirs } from "./config.js";
import type { Finding } from "./findings.js";
import type { RunMeta } from "./store.js";
import { criticalityOf, loadAssets } from "./assets.js";

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

export interface Link {
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
  allLinks(): Link[];
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
      allLinks: () => db.prepare("SELECT * FROM run_findings").all() as Link[],
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
    allLinks: () => data.links.slice(),
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

// ───────────────────────────── Traspaso (export/import) ─────────────────────────────
export interface InventoryExport {
  runs: RunRow[];
  findings: FindingRow[];
  links: Link[];
}

export function exportInventory(): InventoryExport {
  const b = backend();
  return { runs: b.allRuns(), findings: b.allFindings(), links: b.allLinks() };
}

/** Vuelca un inventario de otro Xolotl: upsert por huella/corrida (merge). */
export function importInventory(data: InventoryExport): { runs: number; findings: number; links: number } {
  const b = backend();
  b.begin();
  try {
    for (const r of data.runs ?? []) b.insertRun(r);
    for (const f of data.findings ?? []) b.upsertFinding(f);
    for (const l of data.links ?? []) b.linkRunFinding(l);
    b.commit();
  } catch (e) {
    b.commit();
    throw e;
  }
  return { runs: data.runs?.length ?? 0, findings: data.findings?.length ?? 0, links: data.links?.length ?? 0 };
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
  criticality?: string;
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
  const assetsDb = loadAssets();
  for (const a of map.values()) a.criticality = criticalityOf(a.asset, assetsDb)?.criticality;
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

// ───────────────────────────── Siguiente paso sugerido por activo ─────────────────────────────
//
// Mira qué tipos de prueba ya corrieron sobre cada activo y propone los que faltan, según el
// tipo de activo y las señales del propio inventario (puertos abiertos, lenguaje, etc). No lanza
// nada: solo dice qué conviene correr después. Es el mapa de "qué tanto le puedo evaluar a esto".

export type AssetKind = "host" | "web" | "code" | "image" | "unknown";
export type TestLevel = "code" | "app" | "machine";

export interface NextStep {
  tool: string;
  level: TestLevel;
  reason: string;
  needs?: string;
}

export interface CoverageCol {
  label: string;
  done: boolean;
}

export interface AssetPlan {
  asset: string;
  kind: AssetKind;
  criticality?: string;
  applied: string[];
  ports: number[];
  columns: CoverageCol[];
  done: number;
  total: number;
  steps: NextStep[];
}

const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 3000, 5000, 9000, 9443]);

/** host:puerto → host · url → host · ruta → ella misma (no parte rutas de Windows «C:\\…»). */
function baseHost(asset: string): string {
  const m = /^([^/\\\s]+):(\d{1,5})$/.exec(asset);
  return m ? m[1] : asset;
}

/** Activos que tocó una corrida que no dejó hallazgos (host limpio, repo limpio): se usan de respaldo. */
function normTargets(kind: string, target: string): string[] {
  if (kind === "host") return [target.split(" (")[0].trim()];
  if (kind === "network" || kind === "dast")
    return target
      .split(/\s+/)
      .filter(Boolean)
      .map((t) => {
        try {
          return new URL(t).host;
        } catch {
          return baseHost(t);
        }
      });
  return [target.trim()];
}

/** Puertos abiertos por host, leídos del hallazgo inventario de red (XOL-NET-INVENTORY) de cada corrida. */
function openPortsByHost(): Map<string, Set<number>> {
  const res = new Map<string, Set<number>>();
  let dirs: string[] = [];
  try {
    dirs = fs.readdirSync(RUNS_DIR);
  } catch {
    return res;
  }
  for (const id of dirs) {
    const metaPath = path.join(RUNS_DIR, id, "meta.json");
    const findPath = path.join(RUNS_DIR, id, "findings.json");
    let kind = "";
    try {
      kind = (JSON.parse(fs.readFileSync(metaPath, "utf8")) as { kind?: string }).kind ?? "";
    } catch {
      continue;
    }
    if (kind !== "network") continue;
    let arr: Array<{ ruleId?: string; location?: { target?: string }; evidence?: string; description?: string }>;
    try {
      arr = JSON.parse(fs.readFileSync(findPath, "utf8"));
    } catch {
      continue;
    }
    for (const f of arr) {
      if (f?.ruleId !== "XOL-NET-INVENTORY") continue;
      const host = f.location?.target;
      if (!host) continue;
      const set = res.get(host) ?? new Set<number>();
      for (const m of String(f.evidence ?? f.description ?? "").matchAll(/(?:^|\n)\s*(\d{1,5})\//g)) set.add(Number(m[1]));
      res.set(host, set);
    }
  }
  return res;
}

const CRIT_RANK: Record<string, number> = { critica: 0, alta: 1, normal: 2, baja: 3 };

function classify(applied: Set<string>, asset: string, hasPorts: boolean): AssetKind {
  if (applied.has("image")) return "image";
  if (asset.startsWith("http://") || asset.startsWith("https://") || applied.has("dast")) return "web";
  if (applied.has("static") || applied.has("codeql") || applied.has("iac")) return "code";
  if (applied.has("network") || applied.has("host") || hasPorts) return "host";
  if (/[\\/]/.test(asset)) return "code";
  return "unknown";
}

/** Propuesta de siguiente paso por activo: qué pruebas faltan según su tipo y sus señales. */
export function suggestNextSteps(): AssetPlan[] {
  const b = backend();
  const findings = b.allFindings();
  const runs = b.allRuns();
  const links = b.allLinks();

  const fpAsset = new Map(findings.map((f) => [f.fingerprint, baseHost(f.asset)]));
  const runKind = new Map(runs.map((r) => [r.id, r.kind]));
  const linkCount = new Map<string, number>();
  const applied = new Map<string, Set<string>>();
  const ports = new Map<string, Set<number>>();
  const addK = (k: string, v?: string) => {
    if (!v) return;
    (applied.get(k) ?? applied.set(k, new Set()).get(k)!).add(v);
  };
  const addP = (k: string, v: number) => (ports.get(k) ?? ports.set(k, new Set()).get(k)!).add(v);

  for (const l of links) {
    linkCount.set(l.run_id, (linkCount.get(l.run_id) ?? 0) + 1);
    addK(fpAsset.get(l.fingerprint) ?? "", runKind.get(l.run_id));
  }
  // Puerto embebido en el activo (host:puerto) de los hallazgos de red por puerto.
  for (const f of findings) {
    const m = /^([^/\\\s]+):(\d{1,5})$/.exec(f.asset);
    if (m) addP(m[1], Number(m[2]));
  }
  // Puertos completos desde los artefactos de red (incluye puertos abiertos "limpios").
  for (const [host, set] of openPortsByHost()) for (const p of set) addP(host, p);
  // Respaldo: corridas sin hallazgos (sistema limpio) igual cuentan como "evaluado".
  for (const r of runs) {
    if (linkCount.get(r.id)) continue;
    for (const t of normTargets(r.kind, r.target)) addK(baseHost(t), r.kind);
  }

  const assetsDb = loadAssets();
  const keys = new Set<string>([...applied.keys(), ...ports.keys()].filter((k) => k && k !== "servidor"));
  const plans: AssetPlan[] = [];

  for (const asset of keys) {
    const ap = applied.get(asset) ?? new Set<string>();
    const ps = [...(ports.get(asset) ?? new Set<number>())].sort((a, b2) => a - b2);
    const webPorts = ps.filter((p) => WEB_PORTS.has(p));
    const kind = classify(ap, asset, ps.length > 0);
    const columns: CoverageCol[] = [];
    const steps: NextStep[] = [];

    if (kind === "host" || kind === "web") {
      const hasNet = ap.has("network");
      const hasHost = ap.has("host");
      const hasDast = ap.has("dast");
      columns.push({ label: "red", done: hasNet });
      if (kind === "host") columns.push({ label: "config", done: hasHost });
      if (webPorts.length || kind === "web") columns.push({ label: "DAST", done: hasDast });

      if (!hasNet) steps.push({ tool: "scan_network", level: "machine", reason: "sin mapa de puertos y servicios expuestos" });
      if (kind === "host" && !hasHost)
        steps.push({ tool: "scan_host", level: "machine", reason: "sin revisión de configuración (SSH, sudo, kernel, SUID, parches)", needs: "SSH con llave (host en dast_scope) o salida de host_collector" });
      if ((webPorts.length || kind === "web") && !hasDast)
        steps.push({
          tool: "scan_dast",
          level: "app",
          reason: webPorts.length ? `puerto web ${webPorts.join(", ")} abierto y sin DAST` : "servicio web sin DAST",
          needs: "registra el alcance con dast_scope action=add",
        });
    } else if (kind === "code") {
      const hasStatic = ap.has("static");
      const hasCodeql = ap.has("codeql");
      const hasIac = ap.has("iac");
      columns.push({ label: "SAST+SCA", done: hasStatic }, { label: "CodeQL", done: hasCodeql }, { label: "IaC", done: hasIac });
      if (!hasStatic) steps.push({ tool: "scan_static", level: "code", reason: "sin SAST, SCA ni revisión de secretos" });
      if (hasStatic && !hasCodeql) steps.push({ tool: "scan_codeql", level: "code", reason: "SAST hecho; falta el análisis profundo por consultas (lenguajes compilados)" });
      if (!hasIac) steps.push({ tool: "scan_iac", level: "code", reason: "falta revisar IaC, Dockerfile y manifiestos si los hay" });
    } else if (kind === "image") {
      columns.push({ label: "imagen", done: ap.has("image") });
    } else {
      columns.push({ label: "evaluado", done: ap.size > 0 });
    }

    const total = columns.length;
    const done = columns.filter((c) => c.done).length;
    plans.push({
      asset,
      kind,
      criticality: criticalityOf(asset, assetsDb)?.criticality,
      applied: [...ap].sort(),
      ports: ps,
      columns,
      done,
      total,
      steps,
    });
  }

  plans.sort((a, b2) => {
    if (!!a.steps.length !== !!b2.steps.length) return a.steps.length ? -1 : 1;
    const ca = CRIT_RANK[a.criticality ?? "normal"] ?? 2;
    const cb = CRIT_RANK[b2.criticality ?? "normal"] ?? 2;
    return ca - cb || b2.steps.length - a.steps.length || a.asset.localeCompare(b2.asset);
  });
  return plans;
}

// ───────────────────────────── Plan de evaluación por activo (orquestación) ─────────────────────────────
//
// Toma los huecos de suggestNextSteps() y los ordena en un plan ejecutable por fases:
// superficie (sin credenciales) → código → configuración interna → aplicación. Cada paso lleva
// su nivel, su Tier por defecto y el acceso que necesita. No ejecuta nada: es el guion a seguir.

export type AccessToken = "red" | "codigo" | "imagen" | "ssh" | "alcance";

interface ToolMeta {
  phase: number;
  phaseName: string;
  tier: string;
  access: string;
  token: AccessToken;
}

const TOOL_META: Record<string, ToolMeta> = {
  scan_network: { phase: 1, phaseName: "Superficie expuesta (sin credenciales)", tier: "Tier 1 (advisory) o Tier 2 (conecta)", access: "red, ninguna credencial", token: "red" },
  scan_static: { phase: 2, phaseName: "Código fuente", tier: "local", access: "código fuente", token: "codigo" },
  scan_codeql: { phase: 2, phaseName: "Código fuente", tier: "local", access: "código fuente (lenguaje compilable)", token: "codigo" },
  scan_iac: { phase: 2, phaseName: "Código fuente", tier: "local", access: "código fuente (IaC/manifiestos)", token: "codigo" },
  scan_container_image: { phase: 2, phaseName: "Artefactos", tier: "local", access: "la imagen o acceso al registro", token: "imagen" },
  scan_host: { phase: 3, phaseName: "Configuración interna del host", tier: "Tier 1 (entrega el recolector) o Tier 2 (SSH)", access: "SSH con llave (host en dast_scope) o salida de host_collector", token: "ssh" },
  scan_dast: { phase: 4, phaseName: "Aplicación en ejecución (autorizado)", tier: "Tier 1 (advisory) o Tier 2 (ejecuta)", access: "alcance autorizado en dast_scope", token: "alcance" },
};

export interface PlanStep {
  order: number;
  phase: number;
  phaseName: string;
  asset: string;
  kind: AssetKind;
  criticality?: string;
  tool: string;
  level: TestLevel;
  tier: string;
  access: string;
  token: AccessToken | "";
  reason: string;
}

export interface EvalPlan {
  steps: PlanStep[];
  upToDate: Array<{ asset: string; kind: AssetKind }>;
}

export function buildEvalPlan(assetFilter?: string): EvalPlan {
  const filter = assetFilter?.trim().toLowerCase();
  const steps: PlanStep[] = [];
  const upToDate: EvalPlan["upToDate"] = [];
  for (const p of suggestNextSteps()) {
    if (filter && !p.asset.toLowerCase().includes(filter)) continue;
    if (!p.steps.length) {
      upToDate.push({ asset: p.asset, kind: p.kind });
      continue;
    }
    for (const s of p.steps) {
      const meta = TOOL_META[s.tool];
      steps.push({
        order: 0,
        phase: meta?.phase ?? 5,
        phaseName: meta?.phaseName ?? "Otros",
        asset: p.asset,
        kind: p.kind,
        criticality: p.criticality,
        tool: s.tool,
        level: s.level,
        tier: meta?.tier ?? "—",
        access: s.needs ?? meta?.access ?? "—",
        token: meta?.token ?? "",
        reason: s.reason,
      });
    }
  }
  steps.sort(
    (a, b) =>
      a.phase - b.phase ||
      (CRIT_RANK[a.criticality ?? "normal"] ?? 2) - (CRIT_RANK[b.criticality ?? "normal"] ?? 2) ||
      a.asset.localeCompare(b.asset) ||
      a.tool.localeCompare(b.tool),
  );
  steps.forEach((s, i) => (s.order = i + 1));
  return { steps, upToDate };
}
