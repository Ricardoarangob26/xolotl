import fs from "node:fs";
import path from "node:path";
import { TOOLS_DIR } from "./config.js";
import { run, which } from "./exec.js";

export const TOOL_IDS = ["semgrep", "bandit", "codeql", "osv-scanner", "trivy", "gitleaks", "nuclei"] as const;
export type ToolId = (typeof TOOL_IDS)[number];

export type InstallSpec =
  | { kind: "uv"; pkg: string }
  | { kind: "github"; repo: string; assetFilter?: RegExp };

export interface ToolSpec {
  id: ToolId;
  bin: string;
  purpose: string;
  versionArgs: string[];
  install: InstallSpec;
  /** Si no está instalado, se puede correr al vuelo con `uvx <args>`. */
  uvx?: string[];
  homepage: string;
}

export const SPECS: Record<ToolId, ToolSpec> = {
  semgrep: {
    id: "semgrep",
    bin: "semgrep",
    purpose: "SAST multi-lenguaje con reglas del registro (OWASP, secretos, frameworks)",
    versionArgs: ["--version"],
    install: { kind: "uv", pkg: "semgrep" },
    uvx: ["semgrep"],
    homepage: "https://github.com/semgrep/semgrep",
  },
  bandit: {
    id: "bandit",
    bin: "bandit",
    purpose: "SAST específico de Python",
    versionArgs: ["--version"],
    install: { kind: "uv", pkg: "bandit" },
    uvx: ["bandit"],
    homepage: "https://github.com/PyCQA/bandit",
  },
  codeql: {
    id: "codeql",
    bin: "codeql",
    purpose: "SAST semántico con flujo de datos (taint) — más lento y profundo",
    versionArgs: ["version", "--format=terse"],
    install: { kind: "github", repo: "github/codeql-action", assetFilter: /^codeql-bundle-/ },
    homepage: "https://github.com/github/codeql",
  },
  "osv-scanner": {
    id: "osv-scanner",
    bin: "osv-scanner",
    purpose: "SCA: dependencias con vulnerabilidades conocidas (base OSV.dev)",
    versionArgs: ["--version"],
    install: { kind: "github", repo: "google/osv-scanner" },
    homepage: "https://github.com/google/osv-scanner",
  },
  trivy: {
    id: "trivy",
    bin: "trivy",
    purpose: "SCA, secretos, IaC (Docker/K8s/Terraform) e imágenes de contenedor",
    versionArgs: ["--version"],
    install: { kind: "github", repo: "aquasecurity/trivy" },
    homepage: "https://github.com/aquasecurity/trivy",
  },
  gitleaks: {
    id: "gitleaks",
    bin: "gitleaks",
    purpose: "Secretos filtrados en el código y en todo el historial de git",
    versionArgs: ["version"],
    install: { kind: "github", repo: "gitleaks/gitleaks" },
    homepage: "https://github.com/gitleaks/gitleaks",
  },
  nuclei: {
    id: "nuclei",
    bin: "nuclei",
    purpose: "DAST por plantillas contra aplicaciones, APIs y servicios expuestos",
    versionArgs: ["-version"],
    install: { kind: "github", repo: "projectdiscovery/nuclei" },
    homepage: "https://github.com/projectdiscovery/nuclei",
  },
};

export interface ResolvedTool {
  id: ToolId;
  cmd: string;
  prefix: string[];
  source: "path" | "managed" | "uvx";
}

export const managedDir = (id: ToolId) => path.join(TOOLS_DIR, id);

/** Búsqueda en anchura: el ejecutable menos profundo gana (el bundle de CodeQL trae otros .exe adentro). */
export function findBinary(root: string, bin: string, maxDepth = 4): string | null {
  const names = process.platform === "win32" ? [bin + ".exe"] : [bin];
  let level = [root];
  for (let depth = 0; depth <= maxDepth && level.length; depth++) {
    const next: string[] = [];
    for (const dir of level) {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        if (e.isFile() && names.includes(e.name)) return path.join(dir, e.name);
      }
      for (const e of entries) if (e.isDirectory() && !e.name.startsWith(".")) next.push(path.join(dir, e.name));
    }
    level = next;
  }
  return null;
}

export function resolveTool(id: ToolId): ResolvedTool | null {
  const spec = SPECS[id];
  const managed = findBinary(managedDir(id), spec.bin);
  if (managed) return { id, cmd: managed, prefix: [], source: "managed" };
  const onPath = which(spec.bin);
  if (onPath) return { id, cmd: onPath, prefix: [], source: "path" };
  const uvx = spec.uvx && which("uvx");
  if (uvx && spec.uvx) return { id, cmd: uvx, prefix: spec.uvx, source: "uvx" };
  return null;
}

const versionCache = new Map<string, string | null>();

export async function toolVersion(tool: ResolvedTool): Promise<string | null> {
  const key = `${tool.cmd} ${tool.prefix.join(" ")}`;
  if (versionCache.has(key)) return versionCache.get(key)!;
  const r = await run(tool.cmd, [...tool.prefix, ...SPECS[tool.id].versionArgs], { timeoutMs: 180_000 });
  const m = `${r.stdout}\n${r.stderr}`.match(/v?(\d+\.\d+\.\d+)/);
  const v = m ? m[1] : null;
  versionCache.set(key, v);
  return v;
}

export function forgetVersions(): void {
  versionCache.clear();
}
