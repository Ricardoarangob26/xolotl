import fs from "node:fs";
import path from "node:path";
import { ensureDirs, RUNS_DIR, TRIAGE_FILE } from "./config.js";
import { CATEGORIES, Finding, SEVERITIES, TriageStatus } from "./findings.js";

export interface ToolRun {
  tool: string;
  status: "ok" | "skipped" | "error";
  version?: string | null;
  message?: string;
  durationMs?: number;
  count?: number;
}

export interface Summary {
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  suppressed: number;
}

export interface RunMeta {
  id: string;
  kind: string;
  target: string;
  startedAt: string;
  finishedAt?: string;
  tools: ToolRun[];
  summary?: Summary;
  options?: Record<string, unknown>;
}

const slug = (s: string) =>
  s
    .replace(/^[a-z]+:\/\//i, "")
    .replace(/[^a-z0-9]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(-40)
    .toLowerCase() || "objetivo";

export function newRun(kind: string, target: string, options?: Record<string, unknown>): { meta: RunMeta; dir: string } {
  ensureDirs();
  const now = new Date();
  const stamp = now.toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  const id = `${stamp}-${kind}-${slug(target)}`;
  const dir = path.join(RUNS_DIR, id);
  fs.mkdirSync(dir, { recursive: true });
  return { meta: { id, kind, target, startedAt: now.toISOString(), tools: [], options }, dir };
}

export const runDir = (id: string) => path.join(RUNS_DIR, id);

const SUPPRESSED: TriageStatus[] = ["false_positive", "accepted_risk", "fixed"];
export const isSuppressed = (f: Finding) => !!f.triage && SUPPRESSED.includes(f.triage.status);

export function summarize(findings: Finding[]): Summary {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byCategory = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  let suppressed = 0;
  for (const f of findings) {
    if (isSuppressed(f)) {
      suppressed++;
      continue;
    }
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }
  return { total: findings.length - suppressed, bySeverity, byCategory, suppressed };
}

export function saveRun(meta: RunMeta, findings: Finding[]): void {
  const dir = runDir(meta.id);
  applyTriage(meta, findings);
  meta.finishedAt = new Date().toISOString();
  meta.summary = summarize(findings);
  fs.writeFileSync(path.join(dir, "findings.json"), JSON.stringify(findings, null, 2));
  fs.writeFileSync(path.join(dir, "meta.json"), JSON.stringify(meta, null, 2));
}

export function listRuns(limit = 20): RunMeta[] {
  ensureDirs();
  return fs
    .readdirSync(RUNS_DIR)
    .filter((d) => fs.existsSync(path.join(RUNS_DIR, d, "meta.json")))
    .sort()
    .reverse()
    .slice(0, limit)
    .map((d) => JSON.parse(fs.readFileSync(path.join(RUNS_DIR, d, "meta.json"), "utf8")) as RunMeta);
}

export function loadRun(id?: string): { meta: RunMeta; findings: Finding[] } {
  const runId = id && id !== "latest" ? id : listRuns(1)[0]?.id;
  if (!runId) throw new Error("No hay corridas todavía. Lanza primero un escaneo (scan_static, scan_dast…).");
  const dir = runDir(path.basename(runId));
  if (!fs.existsSync(path.join(dir, "meta.json"))) throw new Error(`No existe la corrida ${runId}. Usa runs_list.`);
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "meta.json"), "utf8")) as RunMeta;
  const findings = JSON.parse(fs.readFileSync(path.join(dir, "findings.json"), "utf8")) as Finding[];
  applyTriage(meta, findings);
  meta.summary = summarize(findings);
  return { meta, findings };
}

// ───────────── Triage persistente por huella (sobrevive entre corridas) ─────────────
interface TriageEntry {
  status: TriageStatus;
  note?: string;
  at: string;
  title: string;
}

function loadTriage(): Record<string, TriageEntry> {
  try {
    return JSON.parse(fs.readFileSync(TRIAGE_FILE, "utf8"));
  } catch {
    return {};
  }
}

function applyTriage(meta: RunMeta, findings: Finding[]) {
  const db = loadTriage();
  for (const f of findings) {
    const t = db[f.fingerprint];
    if (!t) {
      delete f.triage;
      continue;
    }
    // Marcado como corregido antes de esta corrida pero sigue apareciendo: regresión.
    if (t.status === "fixed" && meta.startedAt > t.at) {
      f.triage = { status: "open", note: `Se marcó corregido el ${t.at.slice(0, 10)} pero reaparece. ${t.note ?? ""}`.trim(), at: t.at };
    } else {
      f.triage = { status: t.status, note: t.note, at: t.at };
    }
  }
}

export function setTriage(findings: Finding[], status: TriageStatus, note?: string): void {
  ensureDirs();
  const db = loadTriage();
  const at = new Date().toISOString();
  for (const f of findings) {
    if (status === "open") delete db[f.fingerprint];
    else db[f.fingerprint] = { status, note, at, title: f.title };
  }
  fs.writeFileSync(TRIAGE_FILE, JSON.stringify(db, null, 2));
}
