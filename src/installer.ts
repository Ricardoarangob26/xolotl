import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { ensureDirs } from "./config.js";
import { findBinary, forgetVersions, managedDir, resolveTool, SPECS, ToolId } from "./binaries.js";
import { run, tail, which } from "./exec.js";

interface Asset {
  name: string;
  browser_download_url: string;
  size: number;
}

const GH_HEADERS: Record<string, string> = {
  "User-Agent": "xolotl",
  Accept: "application/vnd.github+json",
  ...(process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
};

const OS_TOKENS: Record<string, string[]> = {
  win32: ["windows", "win64", "win"],
  linux: ["linux", "linux64"],
  darwin: ["darwin", "macos", "osx", "osx64"],
};
const ARCH_TOKENS: Record<string, string[]> = {
  x64: ["x64", "amd64", "x86_64", "64bit", "win64", "linux64", "osx64"],
  arm64: ["arm64", "aarch64"],
};
const NOT_BINARY = /(sha256|checksum|\.sig$|\.pem$|\.sbom|\.spdx|\.json$|\.deb$|\.rpm$|\.apk$|\.msi$|\.pkg$|\.txt$|intoto|\.zst$|sigstore|\.cert?$|\.asc$)/i;

function hasToken(name: string, tokens: string[]): boolean {
  const lower = name.toLowerCase();
  const parts = lower.split(/[^a-z0-9]+/);
  return tokens.some((t) => parts.includes(t) || (t.includes("_") && lower.includes(t)));
}

export function pickAsset(assets: Asset[], filter?: RegExp): Asset | null {
  const osT = OS_TOKENS[process.platform];
  const archT = ARCH_TOKENS[process.arch];
  if (!osT || !archT) return null;
  const candidates = assets.filter(
    (a) => !NOT_BINARY.test(a.name) && (!filter || filter.test(a.name)) && hasToken(a.name, osT) && hasToken(a.name, archT),
  );
  const score = (n: string) =>
    process.platform === "win32"
      ? n.endsWith(".zip") ? 0 : n.endsWith(".exe") ? 1 : n.endsWith(".tar.gz") ? 2 : 3
      : n.endsWith(".tar.gz") ? 0 : n.endsWith(".zip") ? 1 : 2;
  candidates.sort((a, b) => score(a.name) - score(b.name));
  return candidates[0] ?? null;
}

async function expectedSha256(assets: Asset[], target: Asset): Promise<string | null> {
  const specific = assets.find((a) => a.name.startsWith(target.name) && /(sha256|checksum)/i.test(a.name) && !/\.(sig|pem)$/.test(a.name));
  const shared = assets.find((a) => /(checksums?|sha256sums?)(\.txt)?$/i.test(a.name));
  const source = specific ?? shared;
  if (!source) return null;
  const res = await fetch(source.browser_download_url, { headers: { "User-Agent": "xolotl" } });
  if (!res.ok) return null;
  const text = await res.text();
  const lines = text.split(/\r?\n/);
  const line = specific ? lines.find((l) => /[a-f0-9]{64}/i.test(l)) : lines.find((l) => l.trim().endsWith(target.name));
  return line?.match(/[a-f0-9]{64}/i)?.[0].toLowerCase() ?? null;
}

async function fetchRetry(url: string, headers: Record<string, string>, tries = 3): Promise<Response> {
  for (let i = 1; ; i++) {
    try {
      const res = await fetch(url, { headers });
      if (res.status < 500 || i >= tries) return res;
    } catch (e) {
      if (i >= tries) throw new Error(`sin conexión a ${new URL(url).host}: ${(e as Error).message}`);
    }
    await new Promise((r) => setTimeout(r, 2000 * i));
  }
}

async function sha256File(file: string): Promise<string> {
  const hash = crypto.createHash("sha256");
  await pipeline(fs.createReadStream(file), hash);
  return hash.digest("hex");
}

async function extract(archive: string, dest: string): Promise<void> {
  const isZip = archive.endsWith(".zip");
  let r;
  if (process.platform === "win32") {
    // El tar de Windows (bsdtar) abre zip y tar.gz; el de Git Bash no abre zip.
    const tar = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe");
    r = await run(tar, ["-xf", archive, "-C", dest], { timeoutMs: 30 * 60_000 });
  } else if (isZip) {
    const unzip = which("unzip");
    r = unzip ? await run(unzip, ["-o", "-q", archive, "-d", dest]) : await run("tar", ["-xf", archive, "-C", dest]);
  } else {
    r = await run("tar", ["-xzf", archive, "-C", dest], { timeoutMs: 30 * 60_000 });
  }
  if (r.code !== 0) throw new Error(`No se pudo descomprimir ${path.basename(archive)}: ${tail(r)}`);
}

async function installFromGitHub(id: ToolId): Promise<string> {
  const spec = SPECS[id];
  if (spec.install.kind !== "github") throw new Error("no es un binario de GitHub");
  const { repo, assetFilter } = spec.install;

  const relRes = await fetchRetry(`https://api.github.com/repos/${repo}/releases/latest`, GH_HEADERS);
  if (!relRes.ok) throw new Error(`GitHub respondió ${relRes.status} al consultar ${repo} (¿límite de la API? define GITHUB_TOKEN)`);
  const rel = (await relRes.json()) as { tag_name: string; assets: Asset[] };
  const asset = pickAsset(rel.assets, assetFilter);
  if (!asset) throw new Error(`La versión ${rel.tag_name} de ${repo} no publica binario para ${process.platform}/${process.arch}`);

  const dir = managedDir(id);
  const staging = `${dir}.tmp`;
  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });
  const file = path.join(staging, asset.name);

  const res = await fetchRetry(asset.browser_download_url, { "User-Agent": "xolotl" });
  if (!res.ok || !res.body) throw new Error(`Descarga fallida (${res.status}) de ${asset.name}`);
  await pipeline(Readable.fromWeb(res.body as any), fs.createWriteStream(file));

  const expected = await expectedSha256(rel.assets, asset);
  const actual = await sha256File(file);
  if (expected && expected !== actual) {
    fs.rmSync(staging, { recursive: true, force: true });
    throw new Error(`Checksum SHA-256 no coincide para ${asset.name}: se esperaba ${expected}, llegó ${actual}. Instalación abortada.`);
  }

  if (/\.(zip|tar\.gz|tgz)$/.test(asset.name)) {
    await extract(file, staging);
    fs.rmSync(file);
  } else {
    fs.renameSync(file, path.join(staging, spec.bin + (process.platform === "win32" ? ".exe" : "")));
  }

  const bin = findBinary(staging, spec.bin);
  if (!bin) throw new Error(`El paquete ${asset.name} no contiene ${spec.bin}`);
  if (process.platform !== "win32") fs.chmodSync(bin, 0o755);

  // En Windows el antivirus bloquea por momentos los .exe recién extraídos: reintentar.
  for (let attempt = 1; ; attempt++) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.renameSync(staging, dir);
      break;
    } catch (e) {
      if (attempt >= 8) throw new Error(`no se pudo mover la instalación a ${dir}: ${(e as Error).message}`);
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  const verified = expected ? "SHA-256 verificado" : "sin checksum publicado (no verificado)";
  return `${id} ${rel.tag_name} instalado desde ${asset.name} (${(asset.size / 1e6).toFixed(1)} MB, ${verified})`;
}

async function installWithUv(id: ToolId): Promise<string> {
  const spec = SPECS[id];
  if (spec.install.kind !== "uv") throw new Error("no es un paquete de Python");
  const uv = which("uv");
  if (!uv) throw new Error(`Instala uv (https://docs.astral.sh/uv/) o ejecuta: pipx install ${spec.install.pkg}`);
  const r = await run(uv, ["tool", "install", "--upgrade", spec.install.pkg], { timeoutMs: 15 * 60_000 });
  if (r.code !== 0) throw new Error(tail(r));
  return `${id} instalado con uv tool (${spec.install.pkg})`;
}

/** Tras instalar nuclei hay que bajar las plantillas, si no la primera corrida tarda y puede fallar. */
async function postInstall(id: ToolId): Promise<string | null> {
  if (id !== "nuclei") return null;
  const tool = resolveTool("nuclei");
  if (!tool) return null;
  const r = await run(tool.cmd, ["-update-templates", "-silent", "-nc"], { timeoutMs: 15 * 60_000 });
  return r.code === 0 ? "plantillas de nuclei actualizadas" : `no se pudieron bajar las plantillas: ${tail(r, 4)}`;
}

export async function installTool(id: ToolId): Promise<{ ok: boolean; message: string }> {
  ensureDirs();
  try {
    const msg = SPECS[id].install.kind === "github" ? await installFromGitHub(id) : await installWithUv(id);
    const extra = await postInstall(id);
    forgetVersions();
    return { ok: true, message: extra ? `${msg}; ${extra}` : msg };
  } catch (e) {
    fs.rmSync(`${managedDir(id)}.tmp`, { recursive: true, force: true });
    return { ok: false, message: `${id}: ${(e as Error).message}` };
  }
}
