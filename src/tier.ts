/*
 * Niveles de ejecución (inspirados en los "tiers" de un compromiso de pentest):
 *
 *   Tier 2 · execute  — el servidor se conecta al objetivo y corre el escaneo (lo de siempre).
 *   Tier 1 · advisory — el servidor NO toca el objetivo: entrega el comando exacto para que lo
 *                       corras tú (MobaXterm, bastión, consola) y te dice cómo traer el resultado.
 *
 * Sirve donde el equipo de Claude no debe (o no puede) alcanzar el objetivo: redes aisladas,
 * cumplimiento, o un host que ya nos bloqueó (fail2ban). El modo por defecto se fija con la
 * variable XOLOTL_MODE; cada herramienta puede forzarlo con el parámetro `mode`.
 */
import { matchScope } from "./scope.js";

export type Mode = "advisory" | "execute";

export const defaultMode = (): Mode => ((process.env.XOLOTL_MODE ?? "").trim().toLowerCase() === "advisory" ? "advisory" : "execute");
export const resolveMode = (requested?: Mode): Mode => requested ?? defaultMode();

function scopeNote(hosts: string[]): string {
  const out = hosts.filter((h) => !matchScope(h));
  if (!out.length) return "Alcance: todos los objetivos están autorizados en dast_scope.";
  return `Alcance: ⚠️ fuera de dast_scope → ${out.join(", ")}. Corre esto solo si tienes autorización escrita; regístralo con dast_scope si procede.`;
}

const portsSpec = (ports: number[]): string => {
  if (ports.length <= 40) return `-p${ports.join(",")}`;
  return "--top-ports 1000";
};

/** Comando manual equivalente a scan_network, para correr en un host autorizado. */
export function advisoryNetwork(hosts: string[], ports: number[]): string {
  const h = hosts.join(" ");
  return [
    "## Tier 1 · advisory — reconocimiento de red",
    scopeNote(hosts),
    "",
    "Corre esto desde un host autorizado y pégame la salida; la interpreto y la cargo como hallazgos.",
    "",
    "Puertos y versiones de servicio:",
    `  nmap -Pn -sV ${portsSpec(ports)} ${h}`,
    "",
    "Postura TLS (en los puertos con HTTPS/TLS, p. ej. 443):",
    `  nmap -Pn --script ssl-enum-ciphers,ssl-cert -p443 ${h}`,
    "",
    "Configuración SSH (en los hosts con 22 abierto):",
    `  ssh-audit ${hosts[0]}        # uno por host; requiere pip install ssh-audit o 'uvx ssh-audit'`,
    "",
    "Volver: pega la salida de texto aquí. (El ingreso estructurado de nmap está en la hoja de ruta.)",
  ].join("\n");
}

/** Comando manual equivalente a scan_dast (Nuclei), para correr en un host autorizado. */
export function advisoryDast(opts: { targets: string[]; profile: string; tags?: string[]; templates?: string[]; severity?: string[]; rateLimit: number; concurrency: number }): string {
  const flags = [
    opts.targets.length === 1 ? `-u ${opts.targets[0]}` : `-l objetivos.txt   # un objetivo por línea: ${opts.targets.join(", ")}`,
    opts.profile === "automatic" ? "-as" : "",
    opts.tags?.length ? `-tags ${opts.tags.join(",")}` : "",
    opts.templates?.length ? `-t ${opts.templates.join(" -t ")}` : "",
    opts.severity?.length ? `-severity ${opts.severity.join(",")}` : "",
    `-rl ${opts.rateLimit} -c ${opts.concurrency}`,
    "-etags dos,fuzz,brute-force,intrusive",
    "-je nuclei-salida.json",
  ]
    .filter(Boolean)
    .join(" ");
  return [
    "## Tier 1 · advisory — prueba dinámica (Nuclei)",
    scopeNote(opts.targets),
    "",
    "Corre esto desde un host autorizado (-etags excluye intrusivas, como hace Xolotl):",
    `  nuclei ${flags}`,
    "",
    "Volver: pega la salida, o el contenido de nuclei-salida.json, aquí.",
  ].join("\n");
}

/** Pasos manuales equivalentes a scan_host, con ingreso ya soportado por collected_file. */
export function advisoryHost(scriptPath: string): string {
  return [
    "## Tier 1 · advisory — servidor Linux (recolector de solo lectura)",
    `Script escrito en ${scriptPath}. No instala ni cambia nada y no copia secretos.`,
    "",
    "En el servidor (MobaXterm, consola, bastión):",
    "  1. Subir el script (SFTP/scp) o pegarlo:  cat > ~/xolotl-collect.sh   (pegar, Ctrl+D)",
    "  2. sudo sh ~/xolotl-collect.sh > ~/xolotl-$(hostname -s).txt",
    "     (sin sudo también corre, con menos comprobaciones)",
    "  3. Descargar el .txt.",
    "",
    "Volver: scan_host con collected_file=<ruta del .txt>. El ingreso es completo (no es texto libre).",
  ].join("\n");
}
