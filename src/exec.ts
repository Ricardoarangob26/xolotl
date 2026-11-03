import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
  error?: string;
}

export interface RunOptions {
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  maxStdout?: number;
  /** Texto para la entrada estándar (p. ej. el script que ejecuta `ssh host sh -s`). */
  input?: string;
}

const IS_WIN = process.platform === "win32";

/** Busca un ejecutable en el PATH. En Windows solo .exe/.com: sin shell no se pueden lanzar .cmd/.bat. */
export function which(cmd: string): string | null {
  const exts = IS_WIN ? [".exe", ".com"] : [""];
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, cmd + ext);
      try {
        const st = fs.statSync(candidate);
        if (st.isFile()) return candidate;
      } catch {
        /* sigue buscando */
      }
    }
  }
  return null;
}

const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
export const stripAnsi = (s: string) => s.replace(ANSI, "");

function killTree(pid: number | undefined) {
  if (!pid) return;
  if (IS_WIN) {
    spawn("taskkill", ["/pid", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
  } else {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* ya terminó */
    }
  }
}

/** Ejecuta sin shell (argumentos como arreglo: nada de inyección por comillas). */
export function run(file: string, args: string[], opts: RunOptions = {}): Promise<ExecResult> {
  return new Promise((resolve) => {
    const started = Date.now();
    const maxOut = opts.maxStdout ?? 8 * 1024 * 1024;
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    const child = spawn(file, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
      windowsHide: true,
      stdio: [opts.input !== undefined ? "pipe" : "ignore", "pipe", "pipe"],
    });
    if (opts.input !== undefined && child.stdin) {
      child.stdin.on("error", () => {}); // el proceso pudo cerrar antes de leer todo
      child.stdin.end(opts.input);
    }

    const finish = (code: number | null, error?: string) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({
        code,
        stdout: stripAnsi(stdout),
        stderr: stripAnsi(stderr),
        timedOut,
        durationMs: Date.now() - started,
        error,
      });
    };

    child.stdout!.on("data", (d: Buffer) => {
      if (stdout.length < maxOut) stdout += d.toString("utf8");
    });
    child.stderr!.on("data", (d: Buffer) => {
      stderr += d.toString("utf8");
      if (stderr.length > 128 * 1024) stderr = stderr.slice(-64 * 1024);
    });

    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          killTree(child.pid);
        }, opts.timeoutMs)
      : undefined;

    child.on("error", (err) => finish(null, err.message));
    child.on("close", (code) => finish(code));
  });
}

/** Últimas líneas útiles de stderr/stdout para explicar un fallo. */
export function tail(r: ExecResult, lines = 12): string {
  const text = (r.stderr.trim() || r.stdout.trim() || r.error || "").split(/\r?\n/);
  return text.slice(-lines).join("\n");
}
