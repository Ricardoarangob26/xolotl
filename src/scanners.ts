import fs from "node:fs";
import path from "node:path";
import { resolveTool, ResolvedTool, ToolId, toolVersion } from "./binaries.js";
import { run, tail, which } from "./exec.js";
import { buildSbom, checksToFindings, hardeningChecks, HostInfo, hostInfo, parseCollected, writeArtifacts } from "./host.js";
import { HostResult, inventoryFinding, networkFindings, scanHostPorts } from "./network.js";
import { RawFinding } from "./findings.js";
import { parseBandit, parseGitleaks, parseNuclei, parseOsv, parseSarif, parseSemgrep, parseTrivy } from "./parsers.js";
import { ToolRun } from "./store.js";

export interface ScanCtx {
  root: string;
  dir: string;
  excludes: string[];
  timeoutMs: number;
}

export interface Outcome {
  run: ToolRun;
  findings: RawFinding[];
}

const exe = (t: ResolvedTool, args: string[], opts: { cwd?: string; timeoutMs: number; env?: Record<string, string> }) =>
  run(t.cmd, [...t.prefix, ...args], opts);

function readJson(file: string): any {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Envuelve cada escáner: resuelve el binario, mide, y convierte cualquier fallo en un estado legible. */
async function guarded(id: ToolId, body: (t: ResolvedTool) => Promise<{ findings: RawFinding[]; message?: string }>): Promise<Outcome> {
  const tool = resolveTool(id);
  if (!tool) {
    return { run: { tool: id, status: "skipped", message: `no instalado — usa xolotl_install con ["${id}"]` }, findings: [] };
  }
  const started = Date.now();
  const version = await toolVersion(tool);
  try {
    const { findings, message } = await body(tool);
    return {
      run: { tool: id, status: "ok", version, durationMs: Date.now() - started, count: findings.length, message },
      findings,
    };
  } catch (e) {
    return { run: { tool: id, status: "error", version, durationMs: Date.now() - started, message: (e as Error).message }, findings: [] };
  }
}

function needOutput(file: string, r: Awaited<ReturnType<typeof run>>, what: string) {
  if (r.timedOut) throw new Error(`${what} superó el tiempo límite`);
  if (!fs.existsSync(file) || fs.statSync(file).size === 0) {
    throw new Error(`${what} no produjo resultados (código ${r.code}): ${tail(r)}`);
  }
}

/** Hay archivos con esa extensión fuera de las carpetas excluidas (búsqueda acotada). */
export function hasFiles(root: string, exts: string[], excludes: string[], budget = 30_000): boolean {
  const stack = [root];
  let seen = 0;
  while (stack.length && seen < budget) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      seen++;
      if (e.isDirectory()) {
        if (!excludes.includes(e.name) && !e.name.startsWith(".")) stack.push(path.join(dir, e.name));
      } else if (exts.some((x) => e.name.endsWith(x))) return true;
    }
  }
  return false;
}

// ───────────── SAST ─────────────
export function scanSemgrep(ctx: ScanCtx, configs: string[]): Promise<Outcome> {
  return guarded("semgrep", async (t) => {
    const out = path.join(ctx.dir, "semgrep.json");
    const args = [
      "scan",
      "--json",
      "--output",
      out,
      "--metrics",
      "off",
      "--disable-version-check",
      "--quiet",
      ...configs.flatMap((c) => ["--config", c]),
      ...ctx.excludes.flatMap((e) => ["--exclude", e]),
      ctx.root,
    ];
    const opts = { cwd: ctx.root, timeoutMs: ctx.timeoutMs, env: { PYTHONUTF8: "1" } };
    let r = await exe(t, args, opts);
    // Un corte al bajar las reglas del registro sale como código 2 sin mensaje (por --quiet):
    // se reintenta una vez sin --quiet, que además deja el motivo si vuelve a fallar.
    if (!r.timedOut && (!fs.existsSync(out) || fs.statSync(out).size === 0)) {
      r = await exe(t, args.filter((a) => a !== "--quiet"), opts);
    }
    needOutput(out, r, "semgrep");
    const data = readJson(out);
    const errors = (data.errors ?? []).length;
    return { findings: parseSemgrep(data, ctx.root), message: `reglas: ${configs.join(", ")}${errors ? ` · ${errors} archivos con errores de análisis` : ""}` };
  });
}

export function scanBandit(ctx: ScanCtx): Promise<Outcome> {
  if (!hasFiles(ctx.root, [".py"], ctx.excludes)) {
    return Promise.resolve({ run: { tool: "bandit", status: "skipped", message: "no hay archivos Python" }, findings: [] });
  }
  return guarded("bandit", async (t) => {
    const out = path.join(ctx.dir, "bandit.json");
    const exclude = ctx.excludes.flatMap((e) => [path.join(ctx.root, e), `*/${e}/*`]).join(",");
    const r = await exe(t, ["-r", ctx.root, "-f", "json", "-o", out, "-q", "-x", exclude], { timeoutMs: ctx.timeoutMs });
    needOutput(out, r, "bandit");
    return { findings: parseBandit(readJson(out), ctx.root) };
  });
}

const CODEQL_NO_BUILD = ["javascript", "python", "ruby", "java", "csharp", "actions", "rust"];

export function scanCodeql(
  ctx: ScanCtx,
  opts: { language: string; buildMode?: string; buildCommand?: string; suite?: string; keepDb?: boolean },
): Promise<Outcome> {
  return guarded("codeql", async (t) => {
    const lang = opts.language === "typescript" || opts.language === "javascript-typescript" ? "javascript" : opts.language;
    const db = path.join(ctx.dir, "codeql-db");
    const out = path.join(ctx.dir, "codeql.sarif");
    const buildMode = opts.buildCommand ? "manual" : opts.buildMode ?? (CODEQL_NO_BUILD.includes(lang) ? "none" : "autobuild");
    const create = [
      "database",
      "create",
      db,
      `--language=${lang}`,
      `--source-root=${ctx.root}`,
      "--overwrite",
      "--threads=0",
      `--build-mode=${buildMode}`,
      ...(opts.buildCommand ? [`--command=${opts.buildCommand}`] : []),
    ];
    const r1 = await exe(t, create, { cwd: ctx.root, timeoutMs: ctx.timeoutMs });
    if (r1.code !== 0) throw new Error(`no se pudo crear la base de CodeQL: ${tail(r1)}`);
    const suite = opts.suite ?? `codeql/${lang}-queries:codeql-suites/${lang}-security-extended.qls`;
    const r2 = await exe(t, ["database", "analyze", db, suite, "--format=sarif-latest", `--output=${out}`, "--download", "--threads=0"], {
      cwd: ctx.root,
      timeoutMs: ctx.timeoutMs,
    });
    needOutput(out, r2, "codeql analyze");
    if (!opts.keepDb) fs.rmSync(db, { recursive: true, force: true });
    return { findings: parseSarif(readJson(out), ctx.root, "codeql"), message: `lenguaje ${lang}, suite ${suite}` };
  });
}

// ───────────── SCA ─────────────
export function scanOsv(ctx: ScanCtx): Promise<Outcome> {
  return guarded("osv-scanner", async (t) => {
    const out = path.join(ctx.dir, "osv.json");
    const v = (await toolVersion(t)) ?? "2";
    const args = v.startsWith("1.")
      ? ["--format", "json", "--output", out, "-r", ctx.root]
      : ["scan", "source", "-r", "--format", "json", "--output", out, ctx.root];
    const r = await exe(t, args, { cwd: ctx.root, timeoutMs: ctx.timeoutMs });
    // 0 = limpio, 1 = hay vulnerabilidades, 128 = no encontró manifiestos/lockfiles.
    if (r.code === 128) return { findings: [], message: "no encontró lockfiles ni manifiestos" };
    needOutput(out, r, "osv-scanner");
    // OSV entra en node_modules/.package-lock.json: descarta esos duplicados.
    const findings = parseOsv(readJson(out), ctx.root).filter((f) => !ctx.excludes.some((e) => f.location?.file?.split("/").includes(e)));
    return { findings };
  });
}

// ───────────── Trivy: dependencias, secretos, IaC, imágenes ─────────────
export function scanTrivyFs(ctx: ScanCtx, scanners: string[], subcommand: "fs" | "config" = "fs"): Promise<Outcome> {
  return guarded("trivy", async (t) => {
    const out = path.join(ctx.dir, `trivy-${subcommand}.json`);
    const args = [
      subcommand,
      ...(subcommand === "fs" ? ["--scanners", scanners.join(",")] : []),
      "--format",
      "json",
      "--output",
      out,
      "--quiet",
      "--timeout",
      `${Math.round(ctx.timeoutMs / 60_000)}m`,
      ...ctx.excludes.flatMap((e) => ["--skip-dirs", `**/${e}`]),
      ctx.root,
    ];
    const r = await exe(t, args, { cwd: ctx.root, timeoutMs: ctx.timeoutMs });
    needOutput(out, r, `trivy ${subcommand}`);
    return {
      findings: parseTrivy(readJson(out), ctx.root, subcommand === "config" ? "config" : "fs"),
      message: subcommand === "fs" ? `escáneres: ${scanners.join(", ")}` : "solo IaC",
    };
  });
}

export function scanTrivyImage(dir: string, image: string, scanners: string[], timeoutMs: number): Promise<Outcome> {
  return guarded("trivy", async (t) => {
    const out = path.join(dir, "trivy-image.json");
    const r = await exe(
      t,
      ["image", "--scanners", scanners.join(","), "--format", "json", "--output", out, "--quiet", "--timeout", `${Math.round(timeoutMs / 60_000)}m`, image],
      { timeoutMs },
    );
    needOutput(out, r, "trivy image");
    return { findings: parseTrivy(readJson(out), null, "image"), message: `imagen ${image}` };
  });
}

// ───────────── Secretos ─────────────
export function scanGitleaks(ctx: ScanCtx, mode: "auto" | "git" | "dir"): Promise<Outcome> {
  return guarded("gitleaks", async (t) => {
    const useGit = mode === "git" || (mode === "auto" && fs.existsSync(path.join(ctx.root, ".git")));
    const out = path.join(ctx.dir, "gitleaks.json");
    const args = [useGit ? "git" : "dir", ctx.root, "--report-format", "json", "--report-path", out, "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error"];
    // En modo carpeta, excluye node_modules & cía., salvo que el repo traiga su propia configuración.
    if (!useGit && !fs.existsSync(path.join(ctx.root, ".gitleaks.toml"))) {
      const cfg = path.join(ctx.dir, "gitleaks.toml");
      const paths = ctx.excludes.map((e) => `  '''(^|[\\\\/])${e.replace(/\./g, "\\.")}([\\\\/]|$)''',`).join("\n");
      fs.writeFileSync(cfg, `[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "carpetas excluidas por xolotl"\npaths = [\n${paths}\n]\n`);
      args.push("--config", cfg);
    }
    const r = await exe(t, args, { cwd: ctx.root, timeoutMs: ctx.timeoutMs });
    needOutput(out, r, "gitleaks");
    return { findings: parseGitleaks(readJson(out), ctx.root), message: useGit ? "historial completo de git" : "árbol de archivos (sin historial)" };
  });
}

// ───────────── DAST ─────────────
export interface NucleiOpts {
  targets: string[];
  profile: "baseline" | "automatic" | "full" | "custom";
  templates?: string[];
  tags?: string[];
  severity?: string[];
  rateLimit: number;
  concurrency: number;
  headers?: string[];
  allowIntrusive: boolean;
  allowOob: boolean;
  timeoutMs: number;
}

const BASELINE_TAGS = ["tech", "misconfig", "exposure", "cve", "ssl", "panel"];
const INTRUSIVE_TAGS = ["dos", "intrusive", "fuzz", "bruteforce", "default-login", "rce"];

export function scanNuclei(dir: string, o: NucleiOpts): Promise<Outcome> {
  return guarded("nuclei", async (t) => {
    const out = path.join(dir, "nuclei.jsonl");
    const list = path.join(dir, "targets.txt");
    fs.writeFileSync(list, o.targets.join("\n"));
    const args = ["-l", list, "-jsonl", "-o", out, "-silent", "-nc", "-duc", "-or", "-rl", String(o.rateLimit), "-c", String(o.concurrency), "-timeout", "10", "-retries", "1"];
    if (o.profile === "baseline") args.push("-tags", BASELINE_TAGS.join(","));
    if (o.profile === "automatic") args.push("-as");
    for (const tpl of o.templates ?? []) args.push("-t", tpl);
    if (o.tags?.length) args.push("-tags", o.tags.join(","));
    if (o.severity?.length) args.push("-s", o.severity.join(","));
    if (!o.allowIntrusive) args.push("-etags", INTRUSIVE_TAGS.join(","));
    if (!o.allowOob) args.push("-ni");
    for (const h of o.headers ?? []) args.push("-H", h);

    const r = await exe(t, args, { timeoutMs: o.timeoutMs });
    if (r.timedOut) throw new Error("nuclei superó el tiempo límite (los resultados parciales quedan en nuclei.jsonl)");
    if (!fs.existsSync(out)) {
      if (r.code === 0) return { findings: [], message: "sin coincidencias" };
      throw new Error(`nuclei falló (código ${r.code}): ${tail(r)}`);
    }
    const secretValues = (o.headers ?? []).map((h) => h.split(":").slice(1).join(":").trim());
    const findings = parseNuclei(fs.readFileSync(out, "utf8"), secretValues);
    // El archivo crudo puede traer cabeceras de sesión: se reescribe ya redactado.
    if (secretValues.length) {
      let raw = fs.readFileSync(out, "utf8");
      for (const s of secretValues) if (s.length >= 6) raw = raw.split(s).join("[REDACTADO]");
      fs.writeFileSync(out, raw);
    }
    return { findings, message: `perfil ${o.profile}, ${o.targets.length} objetivo(s), ${o.rateLimit} req/s` };
  });
}

/** Corre tareas con un tope de concurrencia (los escáneres son pesados en CPU y RAM). */
export async function limited<T>(tasks: (() => Promise<T>)[], max: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(max, tasks.length) }, async () => {
      while (next < tasks.length) {
        const i = next++;
        results[i] = await tasks[i]();
      }
    }),
  );
  return results;
}

// ───────────── Servidores (recolector + Trivy sobre SBOM + endurecimiento) ─────────────
export interface SshOpts {
  target: string;
  port?: number;
  identityFile?: string;
  sudo: boolean;
  timeoutMs: number;
}

/** Ejecuta el recolector en el servidor por SSH, solo con llave o agente (BatchMode: nunca pide contraseña). */
export async function collectViaSsh(o: SshOpts, script: string): Promise<string> {
  const ssh = which("ssh");
  if (!ssh) throw new Error("No se encontró el cliente ssh en el PATH.");
  // Ni usuario ni host pueden empezar con "-" (se leerían como opciones de ssh); el "--" de abajo es la segunda barrera.
  if (!/^[A-Za-z0-9_][A-Za-z0-9._-]*(@[A-Za-z0-9_[][A-Za-z0-9._:[\]-]*)?$/.test(o.target)) throw new Error(`Destino SSH no válido: ${o.target}`);
  const args = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    "-o", "StrictHostKeyChecking=accept-new",
    ...(o.port ? ["-p", String(o.port)] : []),
    ...(o.identityFile ? ["-i", o.identityFile] : []),
    "--",
    o.target,
    o.sudo ? "sudo -n sh -s" : "sh -s",
  ];
  const r = await run(ssh, args, { input: script, timeoutMs: o.timeoutMs, maxStdout: 32 * 1024 * 1024 });
  if (r.timedOut) throw new Error("La recolección por SSH superó el tiempo límite.");
  if (!r.stdout.includes("===XOLOTL meta===")) {
    const why = tail(r, 6);
    const hint = /a password is required|sudo:/.test(why) ? " (sudo pide contraseña: usa sudo=false, o el modo collected_file desde tu terminal)" : "";
    throw new Error(`No se pudo recolectar por SSH (código ${r.code}): ${why}${hint}`);
  }
  return r.stdout;
}

export async function scanHostText(dir: string, text: string, ignoreUnfixed: boolean, timeoutMs: number): Promise<{ info: HostInfo; outcomes: Outcome[] }> {
  const sections = parseCollected(text);
  const info = hostInfo(sections);
  const checks = hardeningChecks(sections, info);
  const config: Outcome = {
    run: { tool: "xolotl-host", status: "ok", count: checks.length, message: `${info.osName} · kernel ${info.kernel} · ${info.root ? "con root" : "sin root (parcial)"}` },
    findings: checksToFindings(checks, info),
  };

  if (!info.trivyType) {
    fs.writeFileSync(path.join(dir, "host-collect.txt"), text);
    return { info, outcomes: [config, { run: { tool: "trivy", status: "skipped", message: `distribución no soportada para vulnerabilidades (${info.osId})` }, findings: [] }] };
  }
  const sbomFile = writeArtifacts(dir, text, buildSbom(sections, info));
  const vulns = await guarded("trivy", async (t) => {
    const out = path.join(dir, "trivy-host.json");
    const args = ["sbom", "--scanners", "vuln", "--format", "json", "--output", out, "--quiet", "--timeout", `${Math.round(timeoutMs / 60_000)}m`, ...(ignoreUnfixed ? ["--ignore-unfixed"] : []), sbomFile];
    const r = await exe(t, args, { timeoutMs });
    needOutput(out, r, "trivy sbom");
    const findings = parseTrivy(readJson(out), null, "host", info.hostname);
    const fixable = findings.filter((f) => f.package?.fixedVersion).length;
    return { findings, message: `${info.packages} paquetes de ${info.osName}; ${fixable} de ${findings.length} con parche publicado` };
  });
  return { info, outcomes: [config, vulns] };
}

// ───────────── Red sin credenciales (TCP/TLS nativo + ssh-audit opcional) ─────────────
export interface NetScanOpts {
  hosts: string[];
  ports: number[];
  connectTimeoutMs: number;
  concurrency: number;
  sshAudit: boolean;
  timeoutMs: number;
}

/** ssh-audit (vía uvx) contra los hosts con 22 abierto: algoritmos débiles y CVE del servidor SSH. */
async function runSshAudit(targets: { host: string; port: number }[], timeoutMs: number): Promise<Outcome | null> {
  if (!targets.length) return null;
  const uvx = which("uvx");
  if (!uvx) return { run: { tool: "ssh-audit", status: "skipped", message: "no disponible (instala uv para usarlo)" }, findings: [] };
  const findings: RawFinding[] = [];
  const started = Date.now();
  for (const t of targets) {
    const r = await run(uvx, ["ssh-audit", "-j", "-p", String(t.port), t.host], { timeoutMs: Math.min(timeoutMs, 60_000) });
    const line = r.stdout.split(/\r?\n/).find((l) => l.trim().startsWith("{"));
    if (!line) continue;
    let data: any;
    try {
      data = JSON.parse(line);
    } catch {
      continue;
    }
    const sev = (lvl: string): RawFinding["severity"] => (lvl === "fail" ? "medium" : lvl === "warn" ? "low" : "info");
    for (const [kind, recs] of Object.entries(data.recommendations ?? {})) {
      for (const [action, byType] of Object.entries(recs as Record<string, any>)) {
        for (const [algType, algs] of Object.entries(byType as Record<string, any>)) {
          const list = Array.isArray(algs) ? algs.map((a: any) => (typeof a === "string" ? a : a.name)) : [];
          if (list.length) findings.push({ tool: "ssh-audit", category: "network", severity: kind === "critical" ? "medium" : "low", ruleId: `XOL-SSH-ALGO-${action}`, title: `SSH en ${t.host}:${t.port}: ${action === "del" ? "quitar" : "cambiar"} ${algType} débiles`, description: `ssh-audit recomienda ${action === "del" ? "eliminar" : "revisar"} estos algoritmos de ${algType}: ${list.join(", ")}.`, remediation: "Ajustar Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms en sshd_config a valores modernos.", location: { target: `${t.host}:${t.port}` } });
        }
      }
    }
    for (const c of data.cves ?? []) {
      findings.push({ tool: "ssh-audit", category: "network", severity: c.cvssv2 >= 7 ? "high" : "medium", ruleId: c.name, title: `${c.name} en el servidor SSH de ${t.host}:${t.port}`, description: c.description ?? "Vulnerabilidad conocida en la versión de OpenSSH detectada.", cve: [c.name].filter((x) => x.startsWith("CVE-")), location: { target: `${t.host}:${t.port}` } });
    }
  }
  return { run: { tool: "ssh-audit", status: "ok", durationMs: Date.now() - started, count: findings.length, message: `${targets.length} servidor(es) SSH` }, findings };
}

export async function scanNetwork(o: NetScanOpts, onProgress?: (done: number, total: number, msg: string) => void): Promise<{ outcomes: Outcome[]; hostsUp: number }> {
  const started = Date.now();
  const results: HostResult[] = [];
  let done = 0;
  await limited(
    o.hosts.map((host) => async () => {
      const hr = await scanHostPorts(host, { ports: o.ports, connectTimeoutMs: o.connectTimeoutMs, concurrency: o.concurrency });
      results.push(hr);
      onProgress?.(++done, o.hosts.length, `${host}: ${hr.ports.length} puerto(s)`);
    }),
    Math.min(16, o.hosts.length),
  );

  const netFindings: RawFinding[] = [];
  for (const hr of results.filter((r) => r.up)) {
    const inv = inventoryFinding(hr);
    if (inv) netFindings.push(inv);
    netFindings.push(...networkFindings(hr));
  }
  const scan: Outcome = {
    run: { tool: "xolotl-net", status: "ok", durationMs: Date.now() - started, count: netFindings.length, message: `${results.filter((r) => r.up).length}/${o.hosts.length} host(s) con puertos abiertos, ${o.ports.length} puertos sondeados` },
    findings: netFindings,
  };

  const outcomes = [scan];
  if (o.sshAudit) {
    const sshTargets = results.flatMap((r) => r.ports.filter((p) => p.service === "ssh").map((p) => ({ host: r.host, port: p.port })));
    const audit = await runSshAudit(sshTargets, o.timeoutMs);
    if (audit) outcomes.push(audit);
  }
  return { outcomes, hostsUp: results.filter((r) => r.up).length };
}
