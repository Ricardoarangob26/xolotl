/*
 * Alcance autorizado para pruebas dinámicas. Nuclei solo corre contra objetivos
 * que estén aquí, y cada alta queda registrada con quién la autorizó y con qué evidencia.
 */
import fs from "node:fs";
import net from "node:net";
import { ensureDirs, SCOPE_FILE } from "./config.js";

export interface ScopeEntry {
  value: string;
  authorized_by: string;
  evidence: string;
  added_at: string;
}

const BUILTIN: ScopeEntry[] = ["localhost", "127.0.0.1", "::1"].map((value) => ({
  value,
  authorized_by: "predeterminado",
  evidence: "equipo local",
  added_at: "",
}));

export function loadScope(): ScopeEntry[] {
  try {
    const data = JSON.parse(fs.readFileSync(SCOPE_FILE, "utf8"));
    return Array.isArray(data?.targets) ? data.targets : [];
  } catch {
    return [];
  }
}

function saveScope(entries: ScopeEntry[]) {
  ensureDirs();
  fs.writeFileSync(SCOPE_FILE, JSON.stringify({ targets: entries }, null, 2));
}

/** Acepta URL, host, host:puerto, comodín *.dominio o CIDR IPv4. */
export function normalizeEntry(value: string): string {
  const v = value.trim().toLowerCase();
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(v)) return new URL(v).host;
  return v.replace(/\/+$/, "");
}

export function addScope(value: string, authorizedBy: string, evidence: string): ScopeEntry {
  const v = normalizeEntry(value);
  if (!v || v === "*" || v === "0.0.0.0/0" || /^\*\.[a-z]+$/.test(v)) throw new Error(`Alcance demasiado amplio: ${value}`);
  const cidr = v.match(/^(.+)\/(\d+)$/);
  if (cidr && Number(cidr[2]) < 16) throw new Error("Rangos más grandes que /16 no se aceptan: divídelos.");
  const entries = loadScope().filter((e) => e.value !== v);
  const entry = { value: v, authorized_by: authorizedBy, evidence, added_at: new Date().toISOString() };
  entries.push(entry);
  saveScope(entries);
  return entry;
}

export function removeScope(value: string): boolean {
  const v = normalizeEntry(value);
  const entries = loadScope();
  const kept = entries.filter((e) => e.value !== v);
  saveScope(kept);
  return kept.length !== entries.length;
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const intToIpv4 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

/** Expande "host", "host:puerto" o un CIDR IPv4 (/22 o más pequeño) a direcciones concretas. */
export function expandTargets(value: string, maxHosts = 1024): { hosts: string[]; port?: number } {
  const v = value.trim();
  const cidr = v.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (cidr) {
    const bits = Number(cidr[2]);
    if (!net.isIPv4(cidr[1]) || bits < 0 || bits > 32) throw new Error(`CIDR no válido: ${v}`);
    const count = 2 ** (32 - bits);
    if (count > maxHosts) throw new Error(`El rango ${v} tiene ${count} direcciones (máximo ${maxHosts}). Divídelo en bloques más pequeños.`);
    const base = ipv4ToInt(cidr[1]) & (bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0);
    // En /31 y /32 todas las direcciones son host; en el resto se omiten red y broadcast.
    const skipEnds = bits <= 30 && count > 2;
    const hosts: string[] = [];
    for (let i = skipEnds ? 1 : 0; i < (skipEnds ? count - 1 : count); i++) hosts.push(intToIpv4(base + i));
    return { hosts };
  }
  const m = v.match(/^([^:]+):(\d+)$/);
  if (m && net.isIPv4(m[1])) return { hosts: [m[1]], port: Number(m[2]) };
  if (m && !v.includes("::")) return { hosts: [m[1]], port: Number(m[2]) };
  return { hosts: [v] };
}

function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  if (!net.isIPv4(ip) || !net.isIPv4(base)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

function splitHostPort(target: string): { host: string; port?: string } {
  const t = target.trim().toLowerCase();
  let hostPort = t;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(t)) hostPort = new URL(t).host;
  else hostPort = t.split("/")[0];
  const m = hostPort.match(/^\[([^\]]+)\](?::(\d+))?$/) ?? hostPort.match(/^([^:]+)(?::(\d+))?$/);
  if (m) return { host: m[1], port: m[2] };
  return { host: hostPort };
}

export function matchScope(target: string): ScopeEntry | null {
  const { host, port } = splitHostPort(target);
  for (const e of [...BUILTIN, ...loadScope()]) {
    const v = e.value;
    if (v.includes("/")) {
      if (inCidr(host, v)) return e;
      continue;
    }
    const { host: eh, port: ep } = splitHostPort(v);
    if (ep && ep !== port) continue;
    if (eh.startsWith("*.")) {
      if (host.endsWith(eh.slice(1))) return e;
    } else if (eh === host) return e;
  }
  return null;
}

export const builtinScope = () => BUILTIN;
