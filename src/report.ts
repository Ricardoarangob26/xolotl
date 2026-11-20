import { CATEGORIES, Finding, SEVERITIES, sevRank, where } from "./findings.js";
import { isSuppressed, RunMeta } from "./store.js";
import { attackFor, tacticRank, Technique } from "./attack.js";
import { controlsFor, frameworkRank, Control } from "./compliance.js";

/** ¿La prioridad aporta algo más allá de la severidad? (feeds o criticidad del activo) */
const riskEnriched = (f: Finding): boolean => !!f.risk && (f.risk.kev || f.risk.epss !== undefined || !!f.risk.assetCriticality);

/** Hallazgos activos ordenados por prioridad de riesgo (desc), solo los enriquecidos. */
function topByRisk(findings: Finding[], n = 10): Finding[] {
  return findings
    .filter((f) => !isSuppressed(f) && riskEnriched(f))
    .sort((a, b) => (b.risk!.score - a.risk!.score) || a.id.localeCompare(b.id))
    .slice(0, n);
}

const riskCell = (f: Finding): string => {
  const r = f.risk;
  if (!r) return "—";
  const tags = [r.kev ? "KEV" : "", r.epss !== undefined ? `EPSS ${(r.epss * 100).toFixed(0)}%` : "", r.assetCriticality ? `activo ${r.assetCriticality}` : ""].filter(Boolean).join(", ");
  return `${r.score}${tags ? ` (${tags})` : ""}`;
};

const SEV_ES: Record<string, string> = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", info: "Informativa" };
const CAT_ES: Record<string, string> = {
  sast: "Código (SAST)",
  sca: "Dependencias (SCA)",
  secret: "Secretos",
  iac: "Infraestructura como código",
  container: "Contenedores",
  host: "Paquetes del servidor",
  config: "Endurecimiento del servidor",
  network: "Red y servicios expuestos",
  dast: "Pruebas dinámicas (DAST)",
};
const STATUS_ES: Record<string, string> = {
  open: "abierto",
  confirmed: "confirmado",
  false_positive: "falso positivo",
  accepted_risk: "riesgo aceptado",
  fixed: "corregido",
};

const fence = (s: string) => "```\n" + s.replace(/```/g, "ˋˋˋ") + "\n```";
const trunc = (s: string | undefined, n: number) => (!s ? "" : s.length > n ? s.slice(0, n) + "…" : s);

// ───────────────────────────── Resumen ejecutivo (capa de negocio) ─────────────────────────────

export interface PriorRun {
  meta: RunMeta;
  findings: Finding[];
}

interface Trend {
  prevId: string;
  resolved: number;
  added: number;
  kept: number;
}

export interface ExecSummary {
  total: number;
  crit: number;
  high: number;
  openCritHigh: number;
  kev: number;
  highEpss: number;
  bizCritical: number;
  assets: number;
  remediation: { fixed: number; accepted: number; fp: number };
  trend: Trend | null;
  top: Finding[];
}

const EPSS_HIGH = 0.1; // 10%: umbral habitual para "alta probabilidad de explotación".

function assetKey(f: Finding, meta: RunMeta): string {
  const l = f.location ?? {};
  if (l.target) return l.target;
  if (l.url) {
    try {
      return new URL(l.url).host;
    } catch {
      return l.url;
    }
  }
  return l.file ?? meta.target;
}

/** Lo más urgente: por prioridad de riesgo si hay feeds/criticidad; si no, por severidad y CVSS. */
function topUrgent(active: Finding[], n = 3): Finding[] {
  const enriched = topByRisk(active, n);
  if (enriched.length) return enriched;
  return active
    .slice()
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0) || a.id.localeCompare(b.id))
    .slice(0, n);
}

/** Etiqueta de urgencia de un hallazgo: riesgo priorizado, o CVSS, o severidad. */
function urgencyLabel(f: Finding): string {
  if (riskEnriched(f)) return `riesgo ${f.risk!.score}/100`;
  if (f.cvss) return `CVSS ${f.cvss.score}`;
  return SEV_ES[f.severity];
}

function computeTrend(active: Finding[], prev?: PriorRun): Trend | null {
  if (!prev) return null;
  const prevActive = prev.findings.filter((f) => !isSuppressed(f));
  const curFp = new Set(active.map((f) => f.fingerprint));
  const prevFp = new Set(prevActive.map((f) => f.fingerprint));
  return {
    prevId: prev.meta.id,
    added: active.filter((f) => !prevFp.has(f.fingerprint)).length,
    resolved: prevActive.filter((f) => !curFp.has(f.fingerprint)).length,
    kept: active.filter((f) => prevFp.has(f.fingerprint)).length,
  };
}

export function buildExecSummary(meta: RunMeta, findings: Finding[], prev?: PriorRun): ExecSummary {
  const active = findings.filter((f) => !isSuppressed(f));
  const suppressed = findings.filter(isSuppressed);
  const crit = active.filter((f) => f.severity === "critical").length;
  const high = active.filter((f) => f.severity === "high").length;
  const remediation = { fixed: 0, accepted: 0, fp: 0 };
  for (const f of suppressed) {
    if (f.triage!.status === "fixed") remediation.fixed++;
    else if (f.triage!.status === "accepted_risk") remediation.accepted++;
    else if (f.triage!.status === "false_positive") remediation.fp++;
  }
  return {
    total: active.length,
    crit,
    high,
    openCritHigh: crit + high,
    kev: active.filter((f) => f.risk?.kev).length,
    highEpss: active.filter((f) => (f.risk?.epss ?? 0) >= EPSS_HIGH).length,
    bizCritical: active.filter((f) => f.risk?.assetCriticality === "critica" || f.risk?.assetCriticality === "alta").length,
    assets: new Set(active.map((f) => assetKey(f, meta))).size,
    remediation,
    trend: computeTrend(active, prev),
    top: topUrgent(active, 3),
  };
}

function trendPhrase(t: Trend): string {
  const dir = t.added > t.resolved ? "empeoró" : t.resolved > t.added ? "mejoró" : "se mantuvo";
  return `Frente a la corrida anterior (\`${t.prevId}\`) la postura **${dir}**: ${t.resolved} resuelto(s), ${t.added} nuevo(s), ${t.kept} persisten.`;
}

function execLines(e: ExecSummary): string[] {
  const out: string[] = ["## Resumen ejecutivo", ""];
  if (e.total === 0) {
    out.push("No hay hallazgos activos en esta corrida.");
    if (e.trend) out.push("", trendPhrase(e.trend));
    if (e.remediation.fixed || e.remediation.accepted) out.push("", `Remediación: ${e.remediation.fixed} corregido(s), ${e.remediation.accepted} con riesgo aceptado.`);
    out.push("");
    return out;
  }
  const foco = e.openCritHigh ? `${e.openCritHigh} requiere(n) atención prioritaria (${e.crit} crítico(s), ${e.high} alto(s))` : "ninguno es crítico ni alto";
  out.push(`Se evaluaron **${e.assets}** activo(s) y hay **${e.total}** hallazgo(s) activo(s); ${foco}.`);
  const expl: string[] = [];
  if (e.kev) expl.push(`**${e.kev}** en explotación activa (CISA KEV)`);
  if (e.highEpss) expl.push(`**${e.highEpss}** con alta probabilidad de explotación (EPSS ≥ 10%)`);
  if (expl.length) out.push("", `Explotabilidad real: ${expl.join(" y ")} — son los que conviene remediar primero.`);
  if (e.bizCritical) out.push("", `**${e.bizCritical}** afecta(n) a activos de criticidad de negocio alta o crítica.`);
  if (e.trend) out.push("", trendPhrase(e.trend));
  const rem = e.remediation;
  if (rem.fixed || rem.accepted || rem.fp) out.push("", `Avance de remediación: ${rem.fixed} corregido(s), ${rem.accepted} con riesgo aceptado, ${rem.fp} descartado(s) como falso positivo.`);
  if (e.top.length) {
    out.push("", "**Lo más urgente:**");
    for (const f of e.top) out.push(`- ${f.id} · ${urgencyLabel(f)} · ${trunc(f.title, 90)}`);
  }
  out.push("");
  return out;
}

function details(f: Finding): string[] {
  const rows: string[] = [];
  rows.push(`- **Categoría:** ${CAT_ES[f.category]} · **Herramienta:** ${f.tools.join(", ")} · **Regla:** \`${f.ruleId}\``);
  rows.push(`- **Ubicación:** \`${where(f)}\``);
  if (f.package) rows.push(`- **Paquete:** ${f.package.name}@${f.package.version ?? "?"}${f.package.fixedVersion ? ` → actualizar a ${f.package.fixedVersion}` : " (sin versión corregida publicada)"}`);
  const ids = [...(f.cve ?? []), ...(f.cwe ?? [])];
  if (ids.length) rows.push(`- **Referencias:** ${ids.join(", ")}`);
  if (f.cvss) rows.push(`- **CVSS:** ${f.cvss.score}${f.cvss.version ? ` (v${f.cvss.version})` : ""}${f.cvss.source ? ` · ${f.cvss.source}` : ""}${f.cvss.vector ? ` · \`${f.cvss.vector}\`` : ""}`);
  if (riskEnriched(f)) rows.push(`- **Prioridad de riesgo:** ${f.risk!.score}/100 — ${f.risk!.factors.join("; ")}`);
  const tech = attackFor(f);
  if (tech.length) rows.push(`- **MITRE ATT&CK:** ${tech.map((t) => `${t.id} ${t.name} (${t.tactic})`).join("; ")}`);
  const ctrls = controlsFor(f);
  if (ctrls.length) rows.push(`- **Cumplimiento:** ${ctrls.map((c) => `${c.id} (${c.framework})`).join("; ")}`);
  if (f.triage) rows.push(`- **Estado:** ${STATUS_ES[f.triage.status]}${f.triage.note ? ` — ${f.triage.note}` : ""}`);
  return rows;
}

// ───────────────────────────── Cobertura MITRE ATT&CK ─────────────────────────────

interface TacticGroup {
  tactic: string;
  techniques: Array<{ tech: Technique; ids: string[] }>;
}

function attackCoverage(active: Finding[]): TacticGroup[] {
  const byTech = new Map<string, { tech: Technique; ids: string[] }>();
  for (const f of active) {
    for (const t of attackFor(f)) {
      const e = byTech.get(t.id) ?? { tech: t, ids: [] };
      if (!e.ids.includes(f.id)) e.ids.push(f.id);
      byTech.set(t.id, e);
    }
  }
  const byTactic = new Map<string, TacticGroup>();
  for (const e of byTech.values()) {
    const g = byTactic.get(e.tech.tactic) ?? { tactic: e.tech.tactic, techniques: [] };
    g.techniques.push(e);
    byTactic.set(e.tech.tactic, g);
  }
  const groups = [...byTactic.values()].sort((a, b) => tacticRank(a.tactic) - tacticRank(b.tactic));
  for (const g of groups) g.techniques.sort((a, b) => a.tech.id.localeCompare(b.tech.id));
  return groups;
}

// ───────────────────────────── Brechas de cumplimiento ─────────────────────────────

interface FwGroup {
  framework: string;
  controls: Array<{ control: Control; ids: string[] }>;
}

function complianceCoverage(active: Finding[]): FwGroup[] {
  const byCtrl = new Map<string, { control: Control; ids: string[] }>();
  for (const f of active) {
    for (const c of controlsFor(f)) {
      const key = `${c.framework}|${c.id}`;
      const e = byCtrl.get(key) ?? { control: c, ids: [] };
      if (!e.ids.includes(f.id)) e.ids.push(f.id);
      byCtrl.set(key, e);
    }
  }
  const byFw = new Map<string, FwGroup>();
  for (const e of byCtrl.values()) {
    const g = byFw.get(e.control.framework) ?? { framework: e.control.framework, controls: [] };
    g.controls.push(e);
    byFw.set(e.control.framework, g);
  }
  const groups = [...byFw.values()].sort((a, b) => frameworkRank(a.framework) - frameworkRank(b.framework));
  for (const g of groups) g.controls.sort((a, b) => a.control.id.localeCompare(b.control.id, undefined, { numeric: true }));
  return groups;
}

function complianceLinesMd(active: Finding[]): string[] {
  const groups = complianceCoverage(active);
  if (!groups.length) return [];
  const out = ["## Brechas de cumplimiento", "", "Controles con hallazgos abiertos, por marco. Mapeo orientativo para dirigir la remediación; no sustituye una auditoría formal.", ""];
  for (const g of groups) {
    out.push(`**${g.framework}**`);
    for (const c of g.controls) out.push(`- \`${c.control.id}\` ${c.control.title} — ${c.ids.length} hallazgo(s): ${c.ids.slice(0, 12).join(", ")}${c.ids.length > 12 ? "…" : ""}`);
    out.push("");
  }
  return out;
}

function complianceHtml(active: Finding[]): string {
  const groups = complianceCoverage(active);
  if (!groups.length) return "";
  const rows = groups
    .map((g) => {
      const ctrls = g.controls
        .map((c) => `<li><code>${esc(c.control.id)}</code> ${esc(c.control.title)} — <b>${c.ids.length}</b> (${c.ids.slice(0, 12).map((i) => `<code>${i}</code>`).join(" ")}${c.ids.length > 12 ? "…" : ""})</li>`)
        .join("");
      return `<tr><td><b>${esc(g.framework)}</b></td><td><ul class="att">${ctrls}</ul></td></tr>`;
    })
    .join("");
  return `<h2>Brechas de cumplimiento</h2><p class="meta">Controles con hallazgos abiertos, por marco. Mapeo orientativo; no sustituye una auditoría formal.</p><table><tr><th>Marco</th><th>Controles</th></tr>${rows}</table>`;
}

function attackLinesMd(active: Finding[]): string[] {
  const groups = attackCoverage(active);
  if (!groups.length) return [];
  const out = ["## Cobertura MITRE ATT&CK", "", "Técnicas que habilitan los hallazgos activos, por táctica. Útil para priorizar detección y planear la validación.", ""];
  for (const g of groups) {
    out.push(`**${g.tactic}**`);
    for (const t of g.techniques) out.push(`- \`${t.tech.id}\` ${t.tech.name} — ${t.ids.join(", ")}`);
    out.push("");
  }
  return out;
}

function attackHtml(active: Finding[]): string {
  const groups = attackCoverage(active);
  if (!groups.length) return "";
  const rows = groups
    .map((g) => {
      const techs = g.techniques
        .map((t) => `<li><code>${t.tech.id}</code> ${esc(t.tech.name)} — ${t.ids.map((i) => `<code>${i}</code>`).join(" ")}</li>`)
        .join("");
      return `<tr><td><b>${esc(g.tactic)}</b></td><td><ul class="att">${techs}</ul></td></tr>`;
    })
    .join("");
  return `<h2>Cobertura MITRE ATT&CK</h2><p class="meta">Técnicas que habilitan los hallazgos activos, por táctica.</p><table><tr><th>Táctica</th><th>Técnicas</th></tr>${rows}</table>`;
}

export function toMarkdown(meta: RunMeta, findings: Finding[], includeSuppressed: boolean, prev?: PriorRun): string {
  const s = meta.summary!;
  const active = findings.filter((f) => !isSuppressed(f));
  const suppressed = findings.filter(isSuppressed);
  const out: string[] = [];
  out.push(`# Informe de seguridad — ${meta.target}`, "");
  out.push(`Corrida \`${meta.id}\` · ${meta.kind} · ${meta.startedAt.replace("T", " ").slice(0, 16)} UTC`, "");
  out.push(...execLines(buildExecSummary(meta, findings, prev)));
  out.push("## Resumen técnico", "");
  out.push("| Severidad | Hallazgos |", "|---|---:|");
  for (const sev of SEVERITIES) out.push(`| ${SEV_ES[sev]} | ${s.bySeverity[sev]} |`);
  out.push(`| **Total activos** | **${s.total}** |`, "");
  if (s.suppressed) out.push(`Además, ${s.suppressed} hallazgo(s) quedaron descartados en el triage (falso positivo, riesgo aceptado o corregido).`, "");
  out.push("| Categoría | Hallazgos |", "|---|---:|");
  for (const c of CATEGORIES) if (s.byCategory[c]) out.push(`| ${CAT_ES[c]} | ${s.byCategory[c]} |`);
  out.push("", "### Herramientas", "", "| Herramienta | Versión | Estado | Hallazgos | Nota |", "|---|---|---|---:|---|");
  for (const t of meta.tools) out.push(`| ${t.tool} | ${t.version ?? "—"} | ${t.status} | ${t.count ?? 0} | ${trunc(t.message, 120).replace(/\|/g, "/").replace(/\n/g, " ")} |`);
  out.push("");

  const priority = topByRisk(active);
  if (priority.length) {
    out.push("## Prioridad por riesgo", "", "Orden por explotabilidad real (EPSS/CISA KEV), no solo por severidad.", "", "| # | Riesgo | Severidad | Hallazgo | Dónde |", "|---|---|---|---|---|");
    for (const f of priority) out.push(`| ${f.id} | ${riskCell(f)} | ${SEV_ES[f.severity]} | ${trunc(f.title, 70).replace(/\|/g, "/")} | \`${where(f)}\` |`);
    out.push("");
  }

  out.push(...attackLinesMd(active));
  out.push(...complianceLinesMd(active));

  for (const sev of SEVERITIES) {
    const group = active.filter((f) => f.severity === sev);
    if (!group.length) continue;
    out.push(`## ${SEV_ES[sev]} (${group.length})`, "");
    for (const f of group) {
      out.push(`### ${f.id} · ${f.title}`, "", ...details(f), "");
      if (f.description) out.push(trunc(f.description, 800), "");
      if (f.snippet) out.push(fence(f.snippet), "");
      if (f.evidence) out.push(fence(trunc(f.evidence, 1200)), "");
      if (f.remediation) out.push(`**Remediación:** ${trunc(f.remediation, 600)}`, "");
    }
  }

  if (includeSuppressed && suppressed.length) {
    out.push("## Descartados en el triage", "", "| ID | Severidad | Hallazgo | Estado | Nota |", "|---|---|---|---|---|");
    for (const f of suppressed) out.push(`| ${f.id} | ${SEV_ES[f.severity]} | ${trunc(f.title, 80).replace(/\|/g, "/")} | ${STATUS_ES[f.triage!.status]} | ${trunc(f.triage!.note, 120).replace(/\|/g, "/")} |`);
    out.push("");
  }
  return out.join("\n");
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function execHtml(e: ExecSummary): string {
  const lines = execLines(e)
    .slice(2) // quita "## Resumen ejecutivo" y la línea en blanco
    .filter((l) => l !== "" && l !== "## Resumen ejecutivo")
    .map((l) => {
      const html = esc(l.replace(/^- /, "")).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`(.+?)`/g, "<code>$1</code>");
      return l.startsWith("- ") ? `<li>${html}</li>` : l.startsWith("**Lo más urgente:**") ? `<p><b>Lo más urgente:</b></p><ul>` : `<p>${html}</p>`;
    });
  // cierra la lista de "lo más urgente" si quedó abierta
  const body = lines.join("\n") + (lines.some((l) => l.includes("<ul>")) ? "</ul>" : "");
  const kpis = [
    { n: e.total, l: "Hallazgos activos" },
    { n: e.openCritHigh, l: "Crít./altos" },
    { n: e.kev, l: "En KEV" },
    { n: e.highEpss, l: "EPSS ≥ 10%" },
  ];
  const strip = kpis.map((k) => `<div class="kpi"><b>${k.n}</b><span>${k.l}</span></div>`).join("");
  return `<section class="exec"><h2>Resumen ejecutivo</h2><div class="kpis">${strip}</div>${body}</section>`;
}

export function toHtml(meta: RunMeta, findings: Finding[], includeSuppressed: boolean, prev?: PriorRun): string {
  const s = meta.summary!;
  const active = findings.filter((f) => !isSuppressed(f));
  const cards = active
    .map((f) => {
      const rows = details(f).map((r) => `<li>${esc(r.replace(/^- /, "")).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`(.+?)`/g, "<code>$1</code>")}</li>`);
      return `<details class="f ${f.severity}"><summary><span class="sev">${SEV_ES[f.severity]}</span><span class="id">${f.id}</span>${esc(f.title)}</summary>
<ul>${rows.join("")}</ul>
${f.description ? `<p>${esc(trunc(f.description, 1200))}</p>` : ""}
${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ""}
${f.evidence ? `<pre>${esc(trunc(f.evidence, 1500))}</pre>` : ""}
${f.remediation ? `<p><b>Remediación:</b> ${esc(trunc(f.remediation, 800))}</p>` : ""}</details>`;
    })
    .join("\n");
  const suppressedRows = includeSuppressed
    ? findings
        .filter(isSuppressed)
        .map((f) => `<tr><td>${f.id}</td><td>${SEV_ES[f.severity]}</td><td>${esc(f.title)}</td><td>${STATUS_ES[f.triage!.status]}</td><td>${esc(f.triage!.note ?? "")}</td></tr>`)
        .join("")
    : "";
  const tiles = SEVERITIES.map((sev) => `<div class="tile ${sev}"><b>${s.bySeverity[sev]}</b><span>${SEV_ES[sev]}</span></div>`).join("");
  const tools = meta.tools
    .map((t) => `<tr><td>${t.tool}</td><td>${t.version ?? "—"}</td><td>${t.status}</td><td>${t.count ?? 0}</td><td>${esc(trunc(t.message, 160))}</td></tr>`)
    .join("");
  const priority = topByRisk(active);
  const priorityRows = priority
    .map((f) => `<tr><td><code>${f.id}</code></td><td><b>${esc(riskCell(f))}</b></td><td>${SEV_ES[f.severity]}</td><td>${esc(trunc(f.title, 90))}</td><td><code>${esc(where(f))}</code></td></tr>`)
    .join("");

  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de seguridad</title><style>
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e3e2dd;--critical:#9b1c1c;--high:#c2410c;--medium:#a16207;--low:#2563eb;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#a3a29c;--card:#1f1f1d;--line:#33322f;--critical:#f87171;--high:#fb923c;--medium:#facc15;--low:#60a5fa;--info:#9ca3af}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}main{max-width:980px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.meta{color:var(--mut);font-size:13px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px;padding:10px 12px}.tile b{display:block;font-size:24px}.tile span{color:var(--mut);font-size:12px}
.critical{--c:var(--critical)}.high{--c:var(--high)}.medium{--c:var(--medium)}.low{--c:var(--low)}.info{--c:var(--info)}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0 20px;display:block;overflow-x:auto}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px;margin:8px 0;padding:8px 12px}.f summary{cursor:pointer;font-weight:600}
.sev{color:var(--c);font-size:12px;text-transform:uppercase;margin-right:8px}.id{color:var(--mut);font-family:ui-monospace,monospace;font-size:12px;margin-right:8px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}code{font-size:12px;word-break:break-all}ul{padding-left:18px}
.exec{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--low);border-radius:8px;padding:4px 16px 12px;margin:20px 0}.exec h2{margin:12px 0 4px}.exec p{margin:8px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin:12px 0}.kpi{text-align:center;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px}.kpi b{display:block;font-size:22px}.kpi span{color:var(--mut);font-size:11px}
ul.att{margin:0;padding-left:16px}ul.att li{margin:2px 0}
</style></head><body><main>
<h1>Informe de seguridad — ${esc(meta.target)}</h1><div class="meta">Corrida ${esc(meta.id)} · ${esc(meta.kind)} · ${meta.startedAt.replace("T", " ").slice(0, 16)} UTC · ${s.total} hallazgos activos${s.suppressed ? `, ${s.suppressed} descartados` : ""}</div>
${execHtml(buildExecSummary(meta, findings, prev))}
<div class="tiles">${tiles}</div>
<h2>Herramientas</h2><table><tr><th>Herramienta</th><th>Versión</th><th>Estado</th><th>Hallazgos</th><th>Nota</th></tr>${tools}</table>
${priorityRows ? `<h2>Prioridad por riesgo</h2><p class="meta">Orden por explotabilidad real (EPSS/CISA KEV), no solo por severidad.</p><table><tr><th>#</th><th>Riesgo</th><th>Severidad</th><th>Hallazgo</th><th>Dónde</th></tr>${priorityRows}</table>` : ""}
${attackHtml(active)}
${complianceHtml(active)}
<h2>Hallazgos</h2>${cards || "<p>Sin hallazgos activos.</p>"}
${suppressedRows ? `<h2>Descartados en el triage</h2><table><tr><th>ID</th><th>Severidad</th><th>Hallazgo</th><th>Estado</th><th>Nota</th></tr>${suppressedRows}</table>` : ""}
</main></body></html>`;
}

const SARIF_LEVEL: Record<string, string> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SARIF_SCORE: Record<string, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" };

/** SARIF 2.1.0 unificado: se puede subir a GitHub/GitLab code scanning o abrir en VS Code. */
export function toSarif(meta: RunMeta, findings: Finding[]): object {
  const active = findings.filter((f) => !isSuppressed(f));
  const rules = new Map<string, object>();
  for (const f of active) {
    if (rules.has(f.ruleId)) continue;
    rules.set(f.ruleId, {
      id: f.ruleId,
      shortDescription: { text: trunc(f.title, 200) },
      helpUri: f.references?.[0],
      properties: {
        "security-severity": f.cvss ? String(f.cvss.score) : SARIF_SCORE[f.severity],
        tags: [
          "security",
          f.category,
          ...(f.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`),
          ...attackFor(f).map((t) => `external/attack/${t.id}`),
          ...controlsFor(f).filter((c) => c.framework === "OWASP 2021").map((c) => `external/owasp/${c.id.toLowerCase()}`),
        ],
      },
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "xolotl", informationUri: "https://github.com/Ricardoarangob26/xolotl", rules: [...rules.values()] } },
        automationDetails: { id: meta.id },
        results: active.map((f) => ({
          ruleId: f.ruleId,
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.title}${f.package?.fixedVersion ? ` (actualizar a ${f.package.fixedVersion})` : ""}` },
          partialFingerprints: { appsecFingerprint: f.fingerprint },
          properties: { tools: f.tools, category: f.category, severity: f.severity, cve: f.cve, findingId: f.id },
          locations: f.location?.file
            ? [{ physicalLocation: { artifactLocation: { uri: f.location.file }, region: f.location.startLine ? { startLine: f.location.startLine, endLine: f.location.endLine ?? f.location.startLine } : undefined } }]
            : f.location?.url
              ? [{ logicalLocations: [{ fullyQualifiedName: f.location.url }] }]
              : [],
        })),
      },
    ],
  };
}
