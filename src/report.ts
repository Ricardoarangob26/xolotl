import { CATEGORIES, Finding, SEVERITIES, where } from "./findings.js";
import { isSuppressed, RunMeta } from "./store.js";

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

function details(f: Finding): string[] {
  const rows: string[] = [];
  rows.push(`- **Categoría:** ${CAT_ES[f.category]} · **Herramienta:** ${f.tools.join(", ")} · **Regla:** \`${f.ruleId}\``);
  rows.push(`- **Ubicación:** \`${where(f)}\``);
  if (f.package) rows.push(`- **Paquete:** ${f.package.name}@${f.package.version ?? "?"}${f.package.fixedVersion ? ` → actualizar a ${f.package.fixedVersion}` : " (sin versión corregida publicada)"}`);
  const ids = [...(f.cve ?? []), ...(f.cwe ?? [])];
  if (ids.length) rows.push(`- **Referencias:** ${ids.join(", ")}`);
  if (f.triage) rows.push(`- **Estado:** ${STATUS_ES[f.triage.status]}${f.triage.note ? ` — ${f.triage.note}` : ""}`);
  return rows;
}

export function toMarkdown(meta: RunMeta, findings: Finding[], includeSuppressed: boolean): string {
  const s = meta.summary!;
  const active = findings.filter((f) => !isSuppressed(f));
  const suppressed = findings.filter(isSuppressed);
  const out: string[] = [];
  out.push(`# Informe de seguridad — ${meta.target}`, "");
  out.push(`Corrida \`${meta.id}\` · ${meta.kind} · ${meta.startedAt.replace("T", " ").slice(0, 16)} UTC`, "");
  out.push("## Resumen", "");
  out.push("| Severidad | Hallazgos |", "|---|---:|");
  for (const sev of SEVERITIES) out.push(`| ${SEV_ES[sev]} | ${s.bySeverity[sev]} |`);
  out.push(`| **Total activos** | **${s.total}** |`, "");
  if (s.suppressed) out.push(`Además, ${s.suppressed} hallazgo(s) quedaron descartados en el triage (falso positivo, riesgo aceptado o corregido).`, "");
  out.push("| Categoría | Hallazgos |", "|---|---:|");
  for (const c of CATEGORIES) if (s.byCategory[c]) out.push(`| ${CAT_ES[c]} | ${s.byCategory[c]} |`);
  out.push("", "### Herramientas", "", "| Herramienta | Versión | Estado | Hallazgos | Nota |", "|---|---|---|---:|---|");
  for (const t of meta.tools) out.push(`| ${t.tool} | ${t.version ?? "—"} | ${t.status} | ${t.count ?? 0} | ${trunc(t.message, 120).replace(/\|/g, "/").replace(/\n/g, " ")} |`);
  out.push("");

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

export function toHtml(meta: RunMeta, findings: Finding[], includeSuppressed: boolean): string {
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
</style></head><body><main>
<h1>Informe de seguridad — ${esc(meta.target)}</h1><div class="meta">Corrida ${esc(meta.id)} · ${esc(meta.kind)} · ${meta.startedAt.replace("T", " ").slice(0, 16)} UTC · ${s.total} hallazgos activos${s.suppressed ? `, ${s.suppressed} descartados` : ""}</div>
<div class="tiles">${tiles}</div>
<h2>Herramientas</h2><table><tr><th>Herramienta</th><th>Versión</th><th>Estado</th><th>Hallazgos</th><th>Nota</th></tr>${tools}</table>
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
      properties: { "security-severity": SARIF_SCORE[f.severity], tags: ["security", f.category, ...(f.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`)] },
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
