import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolveTool, SPECS, TOOL_IDS, ToolId, toolVersion } from "./binaries.js";
import { DEFAULT_EXCLUDES, ensureDirs, HOME, minutes, SCOPE_FILE } from "./config.js";
import { CATEGORIES, finalize, Finding, oneLine, readLines, RawFinding, SEVERITIES, sevRank, TRIAGE_STATUSES } from "./findings.js";
import { installTool } from "./installer.js";
import { toHtml, toMarkdown, toSarif } from "./report.js";
import {
  limited,
  Outcome,
  ScanCtx,
  scanBandit,
  scanCodeql,
  scanGitleaks,
  scanNuclei,
  scanOsv,
  scanSemgrep,
  scanTrivyFs,
  scanTrivyImage,
} from "./scanners.js";
import { addScope, builtinScope, loadScope, matchScope, removeScope } from "./scope.js";
import { isSuppressed, listRuns, loadRun, newRun, RunMeta, runDir, saveRun, setTriage } from "./store.js";

const server = new McpServer(
  { name: "xolotl", version: "0.1.0" },
  {
    instructions:
      "Herramienta unificada de pruebas de seguridad de aplicaciones. Flujo: xolotl_doctor → scan_static (código, " +
      "dependencias, secretos, IaC) y/o scan_dast (solo objetivos autorizados en dast_scope) → findings_query/finding_get " +
      "para revisar → finding_triage para marcar falsos positivos → report_generate. Cada escaneo crea una corrida; " +
      "runs_diff compara dos corridas para verificar correcciones. Nunca lances DAST contra un objetivo sin autorización explícita del usuario.",
  },
);

const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const fail = (t: string) => ({ content: [{ type: "text" as const, text: t }], isError: true });

type Extra = { _meta?: { progressToken?: string | number }; sendNotification: (n: any) => Promise<void> };

/** Notificaciones de progreso: mantienen viva la llamada en escaneos largos y le dicen al cliente qué está pasando. */
function progress(extra: Extra, done: number, total: number, message: string) {
  const token = extra._meta?.progressToken;
  if (token === undefined) return;
  extra.sendNotification({ method: "notifications/progress", params: { progressToken: token, progress: done, total, message } }).catch(() => {});
}

function resolveDir(p: string): string {
  const abs = path.resolve(p);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new Error(`No existe la carpeta ${abs}`);
  return abs;
}

function summaryText(meta: RunMeta, findings: Finding[], top = 15): string {
  const s = meta.summary!;
  const lines = [`Corrida: ${meta.id}  (${meta.kind} · ${meta.target})`, "Herramientas:"];
  for (const t of meta.tools) {
    const dur = t.durationMs ? ` · ${Math.round(t.durationMs / 1000)}s` : "";
    const count = t.status === "ok" ? ` · ${t.count} hallazgos` : "";
    lines.push(`  - ${t.tool}${t.version ? ` ${t.version}` : ""}: ${t.status}${count}${dur}${t.message ? ` — ${t.message}` : ""}`);
  }
  lines.push(
    `Resumen: ${SEVERITIES.map((sev) => `${s.bySeverity[sev]} ${sev}`).join(" · ")} — ${s.total} activos` +
      (s.suppressed ? `, ${s.suppressed} descartados por triage previo` : ""),
  );
  const active = findings.filter((f) => !isSuppressed(f));
  if (active.length) {
    lines.push(`Principales (${Math.min(top, active.length)} de ${active.length}):`);
    for (const f of active.slice(0, top)) lines.push(`  ${oneLine(f)}`);
  }
  lines.push("Siguiente: findings_query para filtrar, finding_get para ver el detalle con código, report_generate para el informe.");
  return lines.join("\n");
}

async function finishRun(meta: RunMeta, outcomes: Outcome[], root: string | null): Promise<string> {
  meta.tools.push(...outcomes.map((o) => o.run));
  const raw: RawFinding[] = outcomes.flatMap((o) => o.findings);
  const findings = finalize(raw, root);
  saveRun(meta, findings);
  return summaryText(meta, findings);
}

// ═════════════ Diagnóstico e instalación ═════════════

server.registerTool(
  "xolotl_doctor",
  {
    title: "Diagnóstico de escáneres",
    description: "Revisa qué escáneres están disponibles (Semgrep, Bandit, CodeQL, OSV-Scanner, Trivy, Gitleaks, Nuclei), su versión y de dónde se ejecutan.",
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => {
    ensureDirs();
    const rows = await Promise.all(
      TOOL_IDS.map(async (id) => {
        const t = resolveTool(id);
        if (!t) return `✗ ${id.padEnd(12)} no disponible — ${SPECS[id].purpose}. Instalar: xolotl_install ["${id}"]`;
        const v = await toolVersion(t);
        return `✓ ${id.padEnd(12)} ${v ?? "versión ?"} (${t.source}: ${t.source === "uvx" ? "uvx " + t.prefix.join(" ") : t.cmd}) — ${SPECS[id].purpose}`;
      }),
    );
    return text([`Carpeta de trabajo: ${HOME}`, ...rows, `Alcance DAST: ${SCOPE_FILE} (${loadScope().length} objetivos autorizados + localhost)`].join("\n"));
  },
);

server.registerTool(
  "xolotl_install",
  {
    title: "Instalar escáneres",
    description:
      "Descarga e instala escáneres en la carpeta de xolotl. Binarios Go (trivy, gitleaks, osv-scanner, nuclei, codeql) desde la última versión oficial en GitHub, verificando SHA-256 cuando el proyecto lo publica; semgrep y bandit con `uv tool install`. CodeQL pesa ~500 MB.",
    inputSchema: { tools: z.array(z.enum(TOOL_IDS)).min(1).describe("Escáneres a instalar o actualizar") },
    annotations: { openWorldHint: true },
  },
  async ({ tools }, extra) => {
    const out: string[] = [];
    let i = 0;
    for (const id of tools) {
      progress(extra as Extra, i++, tools.length, `instalando ${id}`);
      const r = await installTool(id as ToolId);
      out.push(`${r.ok ? "✓" : "✗"} ${r.message}`);
    }
    return text(out.join("\n"));
  },
);

// ═════════════ Escaneos ═════════════

const STATIC_TOOLS = ["semgrep", "bandit", "osv-scanner", "trivy", "gitleaks"] as const;

server.registerTool(
  "scan_static",
  {
    title: "Escaneo estático completo",
    description:
      "Analiza una carpeta de código sin ejecutarla: SAST (Semgrep; Bandit si hay Python), SCA (OSV-Scanner + Trivy), secretos (Gitleaks, con historial git si existe, + Trivy) e IaC/Dockerfiles (Trivy misconfig). Une y deduplica los resultados en una corrida.",
    inputSchema: {
      path: z.string().describe("Carpeta raíz del proyecto (ruta absoluta)"),
      tools: z.array(z.enum(STATIC_TOOLS)).optional().describe("Subconjunto de escáneres; por defecto todos los disponibles"),
      semgrep_configs: z
        .array(z.string())
        .optional()
        .describe("Reglas de Semgrep: rulesets del registro (p/default, p/owasp-top-ten, p/typescript, p/python, p/secrets…) o rutas a reglas propias. Por defecto p/default + p/owasp-top-ten"),
      trivy_scanners: z.array(z.enum(["vuln", "secret", "misconfig", "license"])).optional().describe("Por defecto vuln, secret, misconfig"),
      secrets_mode: z.enum(["auto", "git", "dir"]).optional().describe("auto: historial git si hay .git; dir: solo archivos actuales"),
      exclude: z.array(z.string()).optional().describe("Carpetas extra a excluir (se suman a node_modules, dist, .next, vendor, venv…)"),
      timeout_minutes: z.number().min(1).max(240).optional().describe("Tiempo máximo por escáner (por defecto 30)"),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args, extra) => {
    let root: string;
    try {
      root = resolveDir(args.path);
    } catch (e) {
      return fail((e as Error).message);
    }
    const wanted = new Set(args.tools ?? STATIC_TOOLS);
    const configs = args.semgrep_configs?.length ? args.semgrep_configs : ["p/default", "p/owasp-top-ten"];
    const trivyScanners = args.trivy_scanners?.length ? args.trivy_scanners : ["vuln", "secret", "misconfig"];
    const { meta, dir } = newRun("static", root, { tools: [...wanted], configs, trivyScanners });
    const ctx: ScanCtx = {
      root,
      dir,
      excludes: [...new Set([...DEFAULT_EXCLUDES, ...(args.exclude ?? [])])],
      timeoutMs: minutes(args.timeout_minutes ?? 30),
    };

    const tasks: { name: string; fn: () => Promise<Outcome> }[] = [];
    if (wanted.has("semgrep")) tasks.push({ name: "semgrep", fn: () => scanSemgrep(ctx, configs) });
    if (wanted.has("bandit")) tasks.push({ name: "bandit", fn: () => scanBandit(ctx) });
    if (wanted.has("osv-scanner")) tasks.push({ name: "osv-scanner", fn: () => scanOsv(ctx) });
    if (wanted.has("trivy")) tasks.push({ name: "trivy", fn: () => scanTrivyFs(ctx, trivyScanners) });
    if (wanted.has("gitleaks")) tasks.push({ name: "gitleaks", fn: () => scanGitleaks(ctx, args.secrets_mode ?? "auto") });

    let done = 0;
    progress(extra as Extra, 0, tasks.length, `escaneando ${root}`);
    const outcomes = await limited(
      tasks.map((t) => async () => {
        const o = await t.fn();
        progress(extra as Extra, ++done, tasks.length, `${t.name}: ${o.run.status}`);
        return o;
      }),
      3,
    );
    return text(await finishRun(meta, outcomes, root));
  },
);

server.registerTool(
  "scan_codeql",
  {
    title: "Análisis profundo con CodeQL",
    description:
      "SAST semántico con flujo de datos (detecta inyecciones que cruzan funciones y archivos). Crea la base de datos CodeQL y corre la suite security-extended. Más lento que Semgrep: úsalo en proyectos clave o para confirmar hallazgos.",
    inputSchema: {
      path: z.string().describe("Carpeta raíz del código"),
      language: z
        .enum(["javascript", "typescript", "python", "java", "csharp", "go", "ruby", "cpp", "swift", "rust", "actions"])
        .describe("Lenguaje principal (typescript se analiza como javascript)"),
      build_mode: z.enum(["none", "autobuild", "manual"]).optional().describe("none sirve para JS/TS, Python, Ruby, Java, C#; go/cpp/swift usan autobuild"),
      build_command: z.string().optional().describe("Comando de compilación para build_mode manual"),
      suite: z.string().optional().describe("Suite/paquete de consultas alternativo (por defecto <lenguaje>-security-extended)"),
      timeout_minutes: z.number().min(5).max(360).optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args, extra) => {
    let root: string;
    try {
      root = resolveDir(args.path);
    } catch (e) {
      return fail((e as Error).message);
    }
    const { meta, dir } = newRun("codeql", root, { language: args.language });
    progress(extra as Extra, 0, 1, "creando base de datos CodeQL");
    const ctx: ScanCtx = { root, dir, excludes: DEFAULT_EXCLUDES, timeoutMs: minutes(args.timeout_minutes ?? 90) };
    const o = await scanCodeql(ctx, { language: args.language, buildMode: args.build_mode, buildCommand: args.build_command, suite: args.suite });
    return text(await finishRun(meta, [o], root));
  },
);

server.registerTool(
  "scan_container_image",
  {
    title: "Escanear imagen de contenedor",
    description: "Trivy sobre una imagen (registro, local o archivo .tar): paquetes del SO y de lenguajes con CVE, secretos y configuración embebidos.",
    inputSchema: {
      image: z.string().describe("Referencia de imagen, p. ej. nginx:1.27 o ghcr.io/org/app:tag"),
      scanners: z.array(z.enum(["vuln", "secret", "misconfig", "license"])).optional().describe("Por defecto vuln, secret"),
      timeout_minutes: z.number().min(1).max(120).optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    const { meta, dir } = newRun("image", args.image);
    const o = await scanTrivyImage(dir, args.image, args.scanners?.length ? args.scanners : ["vuln", "secret"], minutes(args.timeout_minutes ?? 30));
    return text(await finishRun(meta, [o], null));
  },
);

server.registerTool(
  "scan_iac",
  {
    title: "Escanear infraestructura como código",
    description: "Trivy config: Dockerfile, docker-compose, manifiestos Kubernetes y Helm, Terraform, CloudFormation, Azure ARM.",
    inputSchema: {
      path: z.string().describe("Carpeta con los archivos de infraestructura"),
      timeout_minutes: z.number().min(1).max(60).optional(),
    },
    annotations: { readOnlyHint: true },
  },
  async (args) => {
    let root: string;
    try {
      root = resolveDir(args.path);
    } catch (e) {
      return fail((e as Error).message);
    }
    const { meta, dir } = newRun("iac", root);
    const o = await scanTrivyFs({ root, dir, excludes: DEFAULT_EXCLUDES, timeoutMs: minutes(args.timeout_minutes ?? 15) }, [], "config");
    return text(await finishRun(meta, [o], root));
  },
);

server.registerTool(
  "dast_scope",
  {
    title: "Alcance autorizado para DAST",
    description:
      "Lista, agrega o quita objetivos autorizados para pruebas dinámicas. Agregar exige quién autorizó y la evidencia (contrato, ticket, ser dueño del sistema). Solo agrega objetivos que el usuario confirmó explícitamente que puede probar.",
    inputSchema: {
      action: z.enum(["list", "add", "remove"]),
      target: z.string().optional().describe("URL, host, host:puerto, *.dominio o CIDR IPv4 (/16 o más pequeño)"),
      authorized_by: z.string().optional().describe("Nombre de quien autoriza (obligatorio para add)"),
      evidence: z.string().optional().describe("Base de la autorización: ticket, contrato, propietario… (obligatorio para add)"),
    },
  },
  async (args) => {
    try {
      if (args.action === "add") {
        if (!args.target || !args.authorized_by?.trim() || !args.evidence?.trim()) {
          return fail("Para agregar un objetivo se necesitan target, authorized_by y evidence.");
        }
        const e = addScope(args.target, args.authorized_by.trim(), args.evidence.trim());
        return text(`Agregado al alcance: ${e.value} (autoriza ${e.authorized_by}: ${e.evidence}).`);
      }
      if (args.action === "remove") {
        if (!args.target) return fail("Falta target.");
        return text(removeScope(args.target) ? `Quitado: ${args.target}` : `No estaba en el alcance: ${args.target}`);
      }
      const rows = [...builtinScope(), ...loadScope()].map((e) => `- ${e.value} — ${e.authorized_by}${e.evidence ? `: ${e.evidence}` : ""}${e.added_at ? ` (${e.added_at.slice(0, 10)})` : ""}`);
      return text(`Alcance DAST (${SCOPE_FILE}):\n${rows.join("\n")}`);
    } catch (e) {
      return fail((e as Error).message);
    }
  },
);

server.registerTool(
  "scan_dast",
  {
    title: "Prueba dinámica con Nuclei",
    description:
      "Lanza Nuclei contra aplicaciones, APIs o servicios en ejecución. Solo corre contra objetivos dentro de dast_scope. Perfiles: baseline (tecnologías, malas configuraciones, exposiciones, CVE, TLS), automatic (elige plantillas por la tecnología detectada), full (todas salvo intrusivas), custom (templates/tags indicados). Excluye plantillas intrusivas (dos, fuzz, fuerza bruta, rce) y la interacción fuera de banda salvo que se habiliten.",
    inputSchema: {
      targets: z.array(z.string()).min(1).max(50).describe("URLs o host:puerto a probar"),
      profile: z.enum(["baseline", "automatic", "full", "custom"]).optional().describe("Por defecto baseline"),
      templates: z.array(z.string()).optional().describe("Plantillas o carpetas de plantillas (perfil custom)"),
      tags: z.array(z.string()).optional().describe("Etiquetas de plantillas, p. ej. xss, sqli, wordpress, apache"),
      severity: z.array(z.enum(["info", "low", "medium", "high", "critical"])).optional(),
      rate_limit: z.number().min(1).max(500).optional().describe("Peticiones por segundo (por defecto 30)"),
      concurrency: z.number().min(1).max(50).optional().describe("Plantillas en paralelo (por defecto 10)"),
      headers: z.array(z.string()).optional().describe('Cabeceras para pruebas autenticadas, p. ej. "Cookie: session=…". Se redactan en los resultados guardados'),
      allow_intrusive: z.boolean().optional().describe("Permite plantillas intrusivas (dos/fuzz/bruteforce/rce). Solo con autorización explícita para ello"),
      allow_oob: z.boolean().optional().describe("Permite interactsh (detección fuera de banda vía servidores externos)"),
      timeout_minutes: z.number().min(1).max(240).optional(),
    },
    annotations: { openWorldHint: true, destructiveHint: false },
  },
  async (args, extra) => {
    const outOfScope = args.targets.filter((t) => !matchScope(t));
    if (outOfScope.length) {
      return fail(
        `Fuera del alcance autorizado: ${outOfScope.join(", ")}.\n` +
          "Confirma con el usuario que tiene autorización para probarlos y regístralos con dast_scope action=add (authorized_by + evidence).",
      );
    }
    const profile = args.profile ?? (args.templates?.length || args.tags?.length ? "custom" : "baseline");
    const { meta, dir } = newRun("dast", args.targets.join(" "), {
      profile,
      tags: args.tags,
      templates: args.templates,
      allowIntrusive: !!args.allow_intrusive,
      scope: args.targets.map((t) => matchScope(t)!.value),
    });
    progress(extra as Extra, 0, 1, `nuclei (${profile}) contra ${args.targets.length} objetivo(s)`);
    const o = await scanNuclei(dir, {
      targets: args.targets,
      profile,
      templates: args.templates,
      tags: args.tags,
      severity: args.severity,
      rateLimit: args.rate_limit ?? 30,
      concurrency: args.concurrency ?? 10,
      headers: args.headers,
      allowIntrusive: !!args.allow_intrusive,
      allowOob: !!args.allow_oob,
      timeoutMs: minutes(args.timeout_minutes ?? 60),
    });
    return text(await finishRun(meta, [o], null));
  },
);

// ═════════════ Consulta y triage ═════════════

server.registerTool(
  "runs_list",
  {
    title: "Corridas anteriores",
    description: "Lista las corridas de escaneo guardadas, de la más reciente a la más antigua.",
    inputSchema: { limit: z.number().min(1).max(100).optional() },
    annotations: { readOnlyHint: true },
  },
  async ({ limit }) => {
    const runs = listRuns(limit ?? 15);
    if (!runs.length) return text("No hay corridas todavía.");
    return text(
      runs
        .map((r) => {
          // Recalculado al leer: el triage posterior al escaneo cambia lo que sigue activo.
          const s = loadRun(r.id).meta.summary;
          const sev = s ? SEVERITIES.map((x) => `${s.bySeverity[x]}${x[0].toUpperCase()}`).join(" ") : "";
          return `${r.id} · ${r.kind} · ${r.target} · ${s?.total ?? 0} activos (${sev})`;
        })
        .join("\n"),
    );
  },
);

server.registerTool(
  "findings_query",
  {
    title: "Consultar hallazgos",
    description: "Filtra los hallazgos de una corrida (por defecto la última) por severidad mínima, categoría, herramienta, estado de triage, archivo o texto.",
    inputSchema: {
      run_id: z.string().optional().describe("ID de la corrida; por defecto la más reciente"),
      min_severity: z.enum(SEVERITIES).optional(),
      category: z.array(z.enum(CATEGORIES)).optional(),
      tool: z.string().optional(),
      status: z.array(z.enum(TRIAGE_STATUSES)).optional().describe("Por defecto solo los no descartados"),
      file: z.string().optional().describe("Fragmento de ruta de archivo o URL"),
      search: z.string().optional().describe("Texto a buscar en título, regla, CVE, CWE o paquete"),
      limit: z.number().min(1).max(500).optional(),
      offset: z.number().min(0).optional(),
    },
    annotations: { readOnlyHint: true },
  },
  async (a) => {
    try {
      const { meta, findings } = loadRun(a.run_id);
      const q = a.search?.toLowerCase();
      const list = findings.filter((f) => {
        const st = f.triage?.status ?? "open";
        if (a.status?.length ? !a.status.includes(st) : isSuppressed(f)) return false;
        if (a.min_severity && sevRank(f.severity) > sevRank(a.min_severity)) return false;
        if (a.category?.length && !a.category.includes(f.category)) return false;
        if (a.tool && !f.tools.includes(a.tool)) return false;
        if (a.file && !`${f.location?.file ?? ""} ${f.location?.url ?? ""}`.toLowerCase().includes(a.file.toLowerCase())) return false;
        if (q) {
          const hay = [f.title, f.ruleId, ...(f.cve ?? []), ...(f.cwe ?? []), ...(f.ids ?? []), f.package?.name ?? ""].join(" ").toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });
      const off = a.offset ?? 0;
      const page = list.slice(off, off + (a.limit ?? 50));
      const head = `Corrida ${meta.id}: ${list.length} hallazgos coinciden (mostrando ${page.length} desde ${off}).`;
      return text([head, ...page.map(oneLine)].join("\n"));
    } catch (e) {
      return fail((e as Error).message);
    }
  },
);

server.registerTool(
  "finding_get",
  {
    title: "Detalle de un hallazgo",
    description: "Detalle completo de un hallazgo con el código alrededor de la línea afectada, para decidir si es explotable o falso positivo.",
    inputSchema: {
      finding_id: z.string().describe("ID tipo F-001"),
      run_id: z.string().optional(),
      context_lines: z.number().min(0).max(60).optional().describe("Líneas de contexto antes y después (por defecto 12)"),
    },
    annotations: { readOnlyHint: true },
  },
  async (a) => {
    try {
      const { meta, findings } = loadRun(a.run_id);
      const f = findings.find((x) => x.id.toLowerCase() === a.finding_id.toLowerCase());
      if (!f) return fail(`No existe ${a.finding_id} en ${meta.id}.`);
      const out: string[] = [oneLine(f), "", JSON.stringify({ ...f, snippet: undefined }, null, 2)];
      const root = meta.kind === "static" || meta.kind === "codeql" || meta.kind === "iac" ? meta.target : null;
      const loc = f.location;
      if (root && loc?.file && loc.startLine && f.category !== "secret") {
        const n = a.context_lines ?? 12;
        const start = Math.max(1, loc.startLine - n);
        const code = readLines(root, loc.file, start, (loc.endLine ?? loc.startLine) + n);
        if (code) {
          const numbered = code
            .split("\n")
            .map((l, i) => {
              const ln = start + i;
              const mark = ln >= loc.startLine! && ln <= (loc.endLine ?? loc.startLine!) ? ">" : " ";
              return `${mark}${String(ln).padStart(5)} | ${l}`;
            })
            .join("\n");
          out.push("", `Código (${path.join(root, loc.file)}):`, numbered);
        }
      }
      return text(out.join("\n"));
    } catch (e) {
      return fail((e as Error).message);
    }
  },
);

server.registerTool(
  "finding_triage",
  {
    title: "Clasificar hallazgos",
    description:
      "Marca uno o varios hallazgos como confirmed, false_positive, accepted_risk, fixed u open, con una nota que justifique la decisión. Se recuerda por huella: aplica también a escaneos futuros del mismo proyecto.",
    inputSchema: {
      finding_ids: z.array(z.string()).min(1),
      status: z.enum(TRIAGE_STATUSES),
      note: z.string().optional().describe("Justificación (obligatoria salvo para open/confirmed)"),
      run_id: z.string().optional(),
    },
  },
  async (a) => {
    try {
      if (["false_positive", "accepted_risk", "fixed"].includes(a.status) && !a.note?.trim()) {
        return fail("Para descartar un hallazgo se necesita una nota con la justificación.");
      }
      const { meta, findings } = loadRun(a.run_id);
      const wanted = new Set(a.finding_ids.map((i) => i.toUpperCase()));
      const hit = findings.filter((f) => wanted.has(f.id.toUpperCase()));
      const missing = [...wanted].filter((i) => !hit.some((f) => f.id.toUpperCase() === i));
      setTriage(hit, a.status, a.note?.trim());
      return text(`${hit.length} hallazgo(s) de ${meta.id} marcados como ${a.status}.${missing.length ? ` No encontrados: ${missing.join(", ")}` : ""}`);
    } catch (e) {
      return fail((e as Error).message);
    }
  },
);

server.registerTool(
  "runs_diff",
  {
    title: "Comparar corridas",
    description: "Compara dos corridas por huella: hallazgos nuevos, resueltos y persistentes. Úsalo para verificar que un parche corrigió el problema sin introducir otros.",
    inputSchema: {
      base_run_id: z.string().describe("Corrida anterior (antes del cambio)"),
      head_run_id: z.string().optional().describe("Corrida posterior; por defecto la más reciente"),
    },
    annotations: { readOnlyHint: true },
  },
  async (a) => {
    try {
      const base = loadRun(a.base_run_id);
      const head = loadRun(a.head_run_id);
      const baseFp = new Set(base.findings.map((f) => f.fingerprint));
      const headFp = new Set(head.findings.map((f) => f.fingerprint));
      const added = head.findings.filter((f) => !baseFp.has(f.fingerprint));
      const resolved = base.findings.filter((f) => !headFp.has(f.fingerprint));
      const kept = head.findings.filter((f) => baseFp.has(f.fingerprint));
      const out = [
        `Base ${base.meta.id} → ${head.meta.id}`,
        `Resueltos: ${resolved.length} · Nuevos: ${added.length} · Persisten: ${kept.length}`,
        ...(resolved.length ? ["", "Resueltos:", ...resolved.map((f) => `  ${oneLine(f)}`)] : []),
        ...(added.length ? ["", "Nuevos (revisar):", ...added.map((f) => `  ${oneLine(f)}`)] : []),
      ];
      return text(out.join("\n"));
    } catch (e) {
      return fail((e as Error).message);
    }
  },
);

server.registerTool(
  "report_generate",
  {
    title: "Generar informe",
    description: "Genera el informe de una corrida en Markdown, HTML autocontenido, SARIF 2.1.0 (para GitHub/GitLab code scanning o VS Code) o JSON.",
    inputSchema: {
      run_id: z.string().optional(),
      format: z.enum(["md", "html", "sarif", "json"]).optional().describe("Por defecto md"),
      output_path: z.string().optional().describe("Ruta del archivo; por defecto dentro de la carpeta de la corrida"),
      include_suppressed: z.boolean().optional().describe("Incluye la tabla de descartados con su justificación (por defecto true)"),
    },
  },
  async (a) => {
    try {
      const { meta, findings } = loadRun(a.run_id);
      const fmt = a.format ?? "md";
      const incl = a.include_suppressed ?? true;
      const body =
        fmt === "md"
          ? toMarkdown(meta, findings, incl)
          : fmt === "html"
            ? toHtml(meta, findings, incl)
            : JSON.stringify(fmt === "sarif" ? toSarif(meta, findings) : { meta, findings }, null, 2);
      const file = path.resolve(a.output_path ?? path.join(runDir(meta.id), `informe.${fmt}`));
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, body);
      return text(`Informe ${fmt.toUpperCase()} escrito en ${file} (${meta.summary!.total} hallazgos activos).`);
    } catch (e) {
      return fail((e as Error).message);
    }
  },
);

// ═════════════ Prompts para la capa de IA ═════════════

server.registerPrompt(
  "triage_run",
  {
    title: "Triage asistido de una corrida",
    description: "Revisa los hallazgos de una corrida, descarta falsos positivos con justificación y prioriza lo explotable.",
    argsSchema: { run_id: z.string().optional() },
  },
  ({ run_id }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            `Haz el triage de la corrida ${run_id ?? "más reciente"} de xolotl.\n` +
            "1. findings_query con min_severity=medium para ver el panorama.\n" +
            "2. Para cada hallazgo crítico/alto, finding_get y lee el código: ¿la entrada la controla un atacante? ¿llega al sumidero sin sanitizar? ¿el código es alcanzable en producción (no tests, no ejemplos)? Para dependencias: ¿se usa la función vulnerable? ¿hay versión corregida?\n" +
            "3. Marca con finding_triage: confirmed (explotable), false_positive (explica por qué), accepted_risk (explica el control compensatorio).\n" +
            "4. Entrega una tabla priorizada: ID, riesgo real, por qué, arreglo propuesto y esfuerzo. Termina con report_generate.",
        },
      },
    ],
  }),
);

server.registerPrompt(
  "fix_finding",
  {
    title: "Corregir y verificar un hallazgo",
    description: "Propone el parche mínimo para un hallazgo y lo verifica volviendo a escanear.",
    argsSchema: { finding_id: z.string(), run_id: z.string().optional() },
  },
  ({ finding_id, run_id }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            `Corrige el hallazgo ${finding_id} (corrida ${run_id ?? "más reciente"}).\n` +
            "1. finding_get para entender el problema y el código.\n" +
            "2. Aplica el cambio mínimo que elimina la causa (validación/escape en el punto correcto, consulta parametrizada, actualizar la dependencia a la versión corregida, sacar el secreto a variable de entorno…). No silencies la regla.\n" +
            "3. Vuelve a escanear solo con la herramienta que lo encontró y usa runs_diff contra la corrida original: el hallazgo debe aparecer como resuelto y no debe haber nuevos.\n" +
            "4. Si es un secreto: recuerda que hay que revocarlo y rotarlo aunque se borre del código.",
        },
      },
    ],
  }),
);

server.registerPrompt(
  "review_patch",
  {
    title: "Revisión de seguridad de un parche",
    description: "Compara dos corridas y revisa el diff de código para confirmar que el parche corrige sin introducir riesgos.",
    argsSchema: { base_run_id: z.string(), head_run_id: z.string().optional() },
  },
  ({ base_run_id, head_run_id }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text:
            `Revisa el parche entre las corridas ${base_run_id} y ${head_run_id ?? "la más reciente"}.\n` +
            "1. runs_diff para ver resueltos y nuevos.\n" +
            "2. Revisa el diff de git del proyecto: ¿el arreglo ataca la causa o solo el síntoma que la regla detecta? ¿cubre todas las rutas de entrada? ¿rompe funcionalidad?\n" +
            "3. Cualquier hallazgo nuevo es bloqueante hasta revisarlo.\n" +
            "4. Veredicto: aprobar / cambios requeridos, con la razón.",
        },
      },
    ],
  }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`xolotl listo (datos en ${HOME})`);
