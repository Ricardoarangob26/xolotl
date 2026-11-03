import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Carpeta de trabajo: binarios gestionados, corridas, alcance DAST y triage. */
export const HOME = process.env.XOLOTL_HOME ?? path.join(os.homedir(), ".xolotl");
export const TOOLS_DIR = path.join(HOME, "tools");
export const RUNS_DIR = path.join(HOME, "runs");
export const SCOPE_FILE = path.join(HOME, "scope.json");
export const TRIAGE_FILE = path.join(HOME, "triage.json");

/** Carpetas que casi nunca son código propio y solo meten ruido. */
export const DEFAULT_EXCLUDES = [
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "out",
  "coverage",
  "vendor",
  ".venv",
  "venv",
  "__pycache__",
  ".tox",
  "target",
  ".terraform",
];

export function ensureDirs(): void {
  for (const dir of [HOME, TOOLS_DIR, RUNS_DIR]) fs.mkdirSync(dir, { recursive: true });
}

export const minutes = (n: number) => Math.round(n * 60_000);
