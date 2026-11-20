/*
 * Auditoría de configuración de bases de datos (Fase 2, vía azul). Sin driver ni conexión propia:
 * fiel al principio "depende de ti". Entregamos un script SQL de SOLO LECTURA; tú lo corres con una
 * cuenta de lectura (psql) y traes la salida; Xolotl la parsea a hallazgos de configuración.
 *
 * Primer motor: PostgreSQL. El parser y los checks están separados por motor para sumar
 * MySQL y SQL Server después con el mismo armazón.
 */
import type { RawFinding, Severity } from "./findings.js";

export type DbEngine = "postgresql";

// ───────────────────────────── Recolector (Tier 1) ─────────────────────────────

/** Script psql de solo lectura: emite secciones con marcas y filas «a|b|c». */
const PG_COLLECTOR = [
  "\\echo ===XOLOTL meta===",
  "SELECT 'version'||'|'||version();",
  "\\echo ===XOLOTL settings===",
  "SELECT name||'|'||setting FROM pg_settings WHERE name IN (" +
    "'ssl','password_encryption','listen_addresses','log_connections','log_disconnections'," +
    "'log_statement','shared_preload_libraries','ssl_min_protocol_version') ORDER BY name;",
  "\\echo ===XOLOTL roles===",
  "SELECT rolname||'|'||rolsuper||'|'||rolcanlogin FROM pg_roles ORDER BY rolname;",
  "\\echo ===XOLOTL hba===",
  "SELECT COALESCE(type,'')||'|'||COALESCE(array_to_string(database,','),'')||'|'||" +
    "COALESCE(array_to_string(user_name,','),'')||'|'||COALESCE(address,'')||'|'||COALESCE(auth_method,'') " +
    "FROM pg_hba_file_rules ORDER BY line_number;",
].join("\n");

export function dbAdvisory(engine: DbEngine, target?: string): string {
  const where = target ? `la base ${target}` : "la base PostgreSQL";
  return [
    `## Tier 1 · advisory — auditoría de configuración de ${where} (solo lectura)`,
    "Ninguna consulta cambia datos. Basta una cuenta de lectura con permiso para ver la",
    "configuración y los roles (por ejemplo un rol con pg_read_all_settings, o el propietario).",
    "",
    "1. Guarda este script como pg-collect.sql:",
    "",
    PG_COLLECTOR,
    "",
    "2. Ejecútalo en modo no alineado y vuelca la salida a un archivo:",
    "     psql -X -A -t -h <host> -U <usuario_lectura> -d <base> -f pg-collect.sql > pg-audit.txt",
    "   (pg_hba_file_rules necesita un rol con privilegio de lectura de configuración; si no lo",
    "    tienes, el resto igual se audita y esa sección vendrá vacía.)",
    "",
    "3. Volver: scan_db con engine=postgresql y collected_file=<ruta de pg-audit.txt>.",
  ].join("\n");
}

// ───────────────────────────── Parseo y checks ─────────────────────────────

interface Hba {
  type: string;
  database: string;
  user: string;
  address: string;
  method: string;
}

function sections(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  let cur = "";
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.match(/^===XOLOTL (\w+)===/);
    if (m) {
      cur = m[1];
      out[cur] = [];
      continue;
    }
    if (cur && raw.trim()) out[cur].push(raw.trim());
  }
  return out;
}

function pgChecks(sec: Record<string, string[]>, host: string): { findings: RawFinding[]; version?: string } {
  const settings: Record<string, string> = {};
  for (const l of sec.settings ?? []) {
    const i = l.indexOf("|");
    if (i > 0) settings[l.slice(0, i)] = l.slice(i + 1).trim();
  }
  const version = (sec.meta ?? []).map((l) => l.split("|").slice(1).join("|")).find(Boolean);
  const hba: Hba[] = (sec.hba ?? [])
    .map((l) => l.split("|"))
    .filter((p) => p.length >= 5)
    .map((p) => ({ type: p[0], database: p[1], user: p[2], address: p[3], method: p[4].toLowerCase() }));
  const roles = (sec.roles ?? [])
    .map((l) => l.split("|"))
    .filter((p) => p.length >= 3)
    .map((p) => ({ name: p[0], super: p[1] === "t", login: p[2] === "t" }));

  const out: RawFinding[] = [];
  const add = (rule: string, severity: Severity, title: string, description: string, remediation: string, evidence?: string) =>
    out.push({ tool: "db-audit", category: "config", severity, ruleId: rule, title, description, remediation, evidence, location: { target: host } });

  const s = (k: string) => (settings[k] ?? "").toLowerCase();

  if (s("ssl") === "off")
    add("XOL-PG-SSL", "high", "PostgreSQL acepta conexiones sin cifrar", "Con ssl=off, las credenciales y los datos viajan en claro por la red y pueden interceptarse.", "Habilitar TLS (ssl=on) con certificado de la PKI interna y exigirlo en pg_hba (hostssl).", "ssl=off");

  const ver = s("ssl_min_protocol_version");
  if (ver === "tlsv1" || ver === "tlsv1.1")
    add("XOL-PG-TLSMIN", "medium", `TLS mínimo obsoleto en PostgreSQL (${settings.ssl_min_protocol_version})`, "Permite negociar TLS 1.0/1.1, con debilidades conocidas.", "ssl_min_protocol_version = 'TLSv1.2' (o TLSv1.3).", `ssl_min_protocol_version=${settings.ssl_min_protocol_version}`);

  if (s("password_encryption") === "md5")
    add("XOL-PG-PWENC", "medium", "Hashing de contraseñas MD5 en PostgreSQL", "MD5 para autenticación es débil y se puede atacar; scram-sha-256 es el estándar actual.", "password_encryption = scram-sha-256 y volver a fijar las contraseñas para que se rehasheen.", "password_encryption=md5");

  if (settings.listen_addresses && /(^|,)\s*\*/.test(settings.listen_addresses))
    add("XOL-PG-LISTEN", "medium", "PostgreSQL escucha en todas las interfaces", "listen_addresses='*' expone el puerto a toda la red; combinado con reglas pg_hba amplias es alcanzable desde fuera.", "Escuchar solo en la interfaz interna/necesaria y filtrar el puerto en el firewall.", `listen_addresses=${settings.listen_addresses}`);

  const trust = hba.filter((h) => h.method === "trust");
  if (trust.length)
    add("XOL-PG-HBA-TRUST", "critical", "Reglas pg_hba con autenticación 'trust'", "El método trust entra sin contraseña: cualquiera que alcance el puerto con ese usuario y base entra sin credenciales.", "Cambiar trust por scram-sha-256 (o cert) en todas las reglas salvo, como mucho, el socket local.", trust.map((h) => `${h.type} ${h.database} ${h.user} ${h.address} ${h.method}`).join("\n"));

  const cleartext = hba.filter((h) => h.method === "password");
  if (cleartext.length)
    add("XOL-PG-HBA-PASSWORD", "high", "Reglas pg_hba con contraseña en claro ('password')", "El método password envía la contraseña en claro (solo protegido si además hay TLS).", "Usar scram-sha-256; si se usa password, exigir hostssl.", cleartext.map((h) => `${h.type} ${h.database} ${h.user} ${h.address} ${h.method}`).join("\n"));

  const anyAddr = hba.filter((h) => /^(0\.0\.0\.0(\/0)?|::\/0|all)$/i.test(h.address) && h.type.toLowerCase().startsWith("host"));
  if (anyAddr.length)
    add("XOL-PG-HBA-ANY", "high", "Reglas pg_hba que aceptan cualquier origen", "Una regla host con origen 0.0.0.0/0 permite conexiones desde cualquier IP; reduce el control a la sola autenticación.", "Restringir el origen a las redes/hosts que de verdad se conectan.", anyAddr.map((h) => `${h.type} ${h.database} ${h.user} ${h.address} ${h.method}`).join("\n"));

  const extraSupers = roles.filter((r) => r.super && r.login && r.name !== "postgres");
  if (extraSupers.length)
    add("XOL-PG-SUPERUSER", "medium", `Cuentas superusuario además de postgres (${extraSupers.length})`, "Cada superusuario puede leerlo y cambiarlo todo, incluida la auditoría. Son objetivos de alto valor y rompen el menor privilegio.", "Dejar superuser solo donde sea imprescindible; dar a las apps un rol acotado (sin SUPERUSER/CREATEROLE).", extraSupers.map((r) => r.name).join(", "));

  if (s("log_connections") === "off" || s("log_disconnections") === "off")
    add("XOL-PG-LOGCONN", "low", "PostgreSQL no registra conexiones", "Sin log_connections/log_disconnections no queda rastro de quién se conectó y cuándo, lo que dificulta investigar un incidente.", "log_connections=on y log_disconnections=on.", `log_connections=${settings.log_connections} log_disconnections=${settings.log_disconnections}`);

  if (!/pgaudit/i.test(settings.shared_preload_libraries ?? "") && s("log_statement") !== "all")
    add("XOL-PG-AUDIT", "low", "Auditoría de sentencias limitada en PostgreSQL", "Sin pgaudit y con log_statement distinto de ddl/all no hay traza de las operaciones sensibles sobre los datos.", "Cargar pgaudit (shared_preload_libraries) y configurar su política, o al menos log_statement='ddl'.", `shared_preload_libraries=${settings.shared_preload_libraries ?? "(vacío)"} log_statement=${settings.log_statement ?? "?"}`);

  return { findings: out, version };
}

export interface DbParse {
  findings: RawFinding[];
  version?: string;
  host: string;
}

export function parseDbCollected(engine: DbEngine, text: string, host = "base-de-datos"): DbParse {
  if (!/===XOLOTL (meta|settings|roles|hba)===/.test(text))
    throw new Error("La salida no trae las marcas ===XOLOTL …===. Genera el archivo con el script que da scan_db en modo advisory (psql -A -t -f pg-collect.sql).");
  const sec = sections(text);
  const { findings, version } = pgChecks(sec, host);
  return { findings, version, host };
}
