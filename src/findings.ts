import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = ["sast", "sca", "secret", "iac", "container", "dast"] as const;
export type Category = (typeof CATEGORIES)[number];

export const TRIAGE_STATUSES = ["open", "confirmed", "false_positive", "accepted_risk", "fixed"] as const;
export type TriageStatus = (typeof TRIAGE_STATUSES)[number];

export interface Location {
  file?: string;
  startLine?: number;
  endLine?: number;
  url?: string;
  target?: string;
  commit?: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  tools: string[];
  category: Category;
  severity: Severity;
  ruleId: string;
  title: string;
  description?: string;
  location?: Location;
  cwe?: string[];
  cve?: string[];
  ids?: string[];
  package?: { name: string; version?: string; ecosystem?: string; fixedVersion?: string };
  references?: string[];
  confidence?: string;
  snippet?: string;
  evidence?: string;
  remediation?: string;
  triage?: { status: TriageStatus; note?: string; at: string };
}

export type RawFinding = Omit<Finding, "id" | "fingerprint" | "tools" | "triage"> & { tool: string };

export const sevRank = (s: Severity) => SEVERITIES.indexOf(s);

export function normSeverity(v: unknown): Severity {
  const s = String(v ?? "").trim().toLowerCase();
  if (s === "critical" || s === "crit") return "critical";
  if (s === "high" || s === "error") return "high";
  if (s === "medium" || s === "moderate" || s === "warning" || s === "med") return "medium";
  if (s === "low" || s === "note") return "low";
  return "info";
}

export function sevFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

const asArray = (v: unknown): unknown[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

export function cweList(v: unknown): string[] {
  const out = new Set<string>();
  for (const item of asArray(v)) {
    const m = String(item).match(/CWE-?0*(\d+)/i);
    if (m) out.add(`CWE-${m[1]}`);
  }
  return [...out];
}

export function strList(v: unknown): string[] {
  return [...new Set(asArray(v).map(String).filter(Boolean))];
}

export function relPath(root: string | null, file: string | undefined): string | undefined {
  if (!file) return undefined;
  let f = file.replace(/^file:\/\//, "");
  if (root && path.isAbsolute(f)) {
    const rel = path.relative(root, f);
    if (!rel.startsWith("..")) f = rel;
  }
  return f.split(path.sep).join("/").replace(/^\.\//, "");
}

export function readLines(root: string, file: string, start: number, end: number): string | undefined {
  try {
    const abs = path.isAbsolute(file) ? file : path.join(root, file);
    const st = fs.statSync(abs);
    if (st.size > 5 * 1024 * 1024) return undefined;
    const lines = fs.readFileSync(abs, "utf8").split(/\r?\n/);
    const s = Math.max(1, start);
    const e = Math.min(lines.length, Math.max(s, end));
    return lines
      .slice(s - 1, e)
      .map((l) => (l.length > 300 ? l.slice(0, 300) + "…" : l))
      .join("\n");
  } catch {
    return undefined;
  }
}

const hash = (parts: unknown[]) =>
  crypto.createHash("sha256").update(parts.map((p) => String(p ?? "")).join("|")).digest("hex").slice(0, 16);

/** "PyYAML" == "pyyaml", "foo_bar" == "foo-bar", "5.3.0" == "5.3": cada herramienta escribe distinto. */
const pkgKey = (p: { name: string; version?: string }) =>
  `${p.name.toLowerCase().replace(/[-_.]+/g, "-")}@${(p.version ?? "").replace(/^v/, "").replace(/(\.0)+$/, "")}`;

function primaryVulnId(f: Finding): string {
  const cves = (f.cve ?? []).slice().sort();
  if (cves.length) return cves[0];
  const ids = (f.ids ?? [f.ruleId]).slice().sort();
  return ids[0];
}

function fingerprintOf(f: Finding): string {
  const loc = f.location ?? {};
  switch (f.category) {
    case "sca":
    case "container":
      return hash([f.category, loc.target ?? "", f.package ? pkgKey(f.package) : "", primaryVulnId(f)]);
    case "secret":
      return hash([f.category, loc.file, loc.startLine, loc.commit ?? ""]);
    case "dast":
      return hash([f.category, f.ruleId, loc.url ?? loc.target]);
    default: {
      const code = f.snippet?.replace(/\s+/g, " ").trim();
      return hash([f.category, f.ruleId, loc.file, code || loc.startLine]);
    }
  }
}

function mergeInto(a: Finding, b: Finding) {
  a.tools = [...new Set([...a.tools, ...b.tools])];
  if (sevRank(b.severity) < sevRank(a.severity)) a.severity = b.severity;
  a.ids = [...new Set([...(a.ids ?? []), ...(b.ids ?? [])])];
  a.cve = [...new Set([...(a.cve ?? []), ...(b.cve ?? [])])];
  a.cwe = [...new Set([...(a.cwe ?? []), ...(b.cwe ?? [])])];
  a.references = [...new Set([...(a.references ?? []), ...(b.references ?? [])])];
  if (a.package && b.package && !a.package.fixedVersion) a.package.fixedVersion = b.package.fixedVersion;
  if (!a.description && b.description) a.description = b.description;
}

/**
 * Une hallazgos del mismo problema reportado por varias herramientas
 * (p. ej. Trivy y OSV con la misma CVE, o Gitleaks y Trivy con el mismo secreto).
 */
function dedupe(list: Finding[]): Finding[] {
  const out: Finding[] = [];
  const byPkg = new Map<string, Finding[]>();
  const bySecret = new Map<string, Finding>();
  const byFp = new Map<string, Finding>();

  for (const f of list) {
    if ((f.category === "sca" || f.category === "container") && f.package) {
      const key = `${f.category}|${f.location?.target ?? ""}|${pkgKey(f.package)}`;
      const bucket = byPkg.get(key) ?? [];
      const ids = new Set([...(f.ids ?? []), ...(f.cve ?? [])]);
      const twin = bucket.find((g) => [...(g.ids ?? []), ...(g.cve ?? [])].some((id) => ids.has(id)));
      if (twin) {
        mergeInto(twin, f);
        continue;
      }
      bucket.push(f);
      byPkg.set(key, bucket);
    } else if (f.category === "secret") {
      const key = `${f.location?.file}|${f.location?.startLine}|${f.location?.commit ?? ""}`;
      const twin = bySecret.get(key);
      if (twin) {
        mergeInto(twin, f);
        continue;
      }
      bySecret.set(key, f);
    }
    out.push(f);
  }

  const final: Finding[] = [];
  for (const f of out) {
    f.fingerprint = fingerprintOf(f);
    const twin = byFp.get(f.fingerprint);
    if (twin) {
      mergeInto(twin, f);
      continue;
    }
    byFp.set(f.fingerprint, f);
    final.push(f);
  }
  return final;
}

/** Normaliza, agrega fragmento de código, deduplica, ordena por severidad y numera F-001… */
export function finalize(raw: RawFinding[], root: string | null): Finding[] {
  const list: Finding[] = raw.map(({ tool, ...rest }) => {
    const f: Finding = { ...rest, id: "", fingerprint: "", tools: [tool] };
    const loc = f.location;
    if (root && loc?.file && loc.startLine && !f.snippet && f.category !== "secret") {
      f.snippet = readLines(root, loc.file, loc.startLine, Math.min(loc.endLine ?? loc.startLine, loc.startLine + 4));
    }
    return f;
  });

  const merged = dedupe(list);
  merged.sort(
    (a, b) =>
      sevRank(a.severity) - sevRank(b.severity) ||
      CATEGORIES.indexOf(a.category) - CATEGORIES.indexOf(b.category) ||
      (a.location?.file ?? "").localeCompare(b.location?.file ?? "") ||
      (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0),
  );
  const width = Math.max(3, String(merged.length).length);
  merged.forEach((f, i) => (f.id = `F-${String(i + 1).padStart(width, "0")}`));
  return merged;
}

export function where(f: Finding): string {
  const l = f.location ?? {};
  if (l.url) return l.url;
  const file = l.file ? `${l.file}${l.startLine ? `:${l.startLine}` : ""}` : l.target ?? "";
  return l.commit ? `${file} @${l.commit.slice(0, 8)}` : file;
}

export function oneLine(f: Finding): string {
  const pkg = f.package ? ` ${f.package.name}@${f.package.version ?? "?"}${f.package.fixedVersion ? ` (fix: ${f.package.fixedVersion})` : ""}` : "";
  const status = f.triage && f.triage.status !== "open" ? ` {${f.triage.status}}` : "";
  const title = f.title.length > 110 ? f.title.slice(0, 110) + "…" : f.title;
  return `${f.id} [${f.severity}] ${f.category}${pkg} — ${title} · ${where(f)} [${f.tools.join(", ")}]${status}`;
}
