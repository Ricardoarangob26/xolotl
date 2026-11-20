/*
 * Auditoría de configuración de bases de datos (Fase 2, vía azul). Sin driver ni conexión propia:
 * fiel al principio "depende de ti". Entregamos un script SQL de SOLO LECTURA; tú lo corres con una
 * cuenta de lectura (psql) y traes la salida; Xolotl la parsea a hallazgos de configuración.
 *
 * Primer motor: PostgreSQL. El parser y los checks están separados por motor para sumar
 * MySQL y SQL Server después con el mismo armazón.
 */
import type { RawFinding, Severity } from "./findings.js";

export type DbEngine = "postgresql" | "mysql" | "mssql";

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

/** Script mysql de solo lectura: filas «a|b|c» y marcas de sección como filas literales. */
const MYSQL_COLLECTOR = [
  "SELECT '===XOLOTL meta===';",
  "SELECT CONCAT('version|', VERSION());",
  "SELECT '===XOLOTL settings===';",
  "SELECT CONCAT(VARIABLE_NAME,'|',VARIABLE_VALUE) FROM performance_schema.global_variables WHERE VARIABLE_NAME IN (" +
    "'require_secure_transport','have_ssl','tls_version','local_infile','secure_file_priv'," +
    "'default_authentication_plugin','general_log','skip_name_resolve','validate_password.policy');",
  "SELECT '===XOLOTL users===';",
  "SELECT CONCAT(User,'|',Host,'|',IF(authentication_string='' OR authentication_string IS NULL,'EMPTY','set'),'|'," +
    "COALESCE(plugin,''),'|',Super_priv,'|',Grant_priv) FROM mysql.user;",
].join("\n");

function mysqlAdvisory(target?: string): string {
  const where = target ? `la base ${target}` : "la base MySQL/MariaDB";
  return [
    `## Tier 1 · advisory — auditoría de configuración de ${where} (solo lectura)`,
    "Ninguna consulta cambia datos. Una cuenta de lectura con SELECT sobre mysql.user y acceso a las",
    "variables globales basta (en MariaDB usa information_schema.global_variables en vez de performance_schema).",
    "",
    "1. Guarda este script como mysql-collect.sql:",
    "",
    MYSQL_COLLECTOR,
    "",
    "2. Ejecútalo sin encabezados y vuelca la salida a un archivo:",
    "     mysql -N -s -h <host> -u <usuario_lectura> -p <base> < mysql-collect.sql > mysql-audit.txt",
    "   (si no tienes SELECT sobre mysql.user, esa sección vendrá vacía y el resto igual se audita.)",
    "",
    "3. Volver: scan_db con engine=mysql y collected_file=<ruta de mysql-audit.txt>.",
  ].join("\n");
}

/** Script T-SQL de solo lectura para SQL Server (sqlcmd). Marcas y filas «a|b|c». */
const MSSQL_COLLECTOR = [
  "SET NOCOUNT ON;",
  "SELECT '===XOLOTL meta===';",
  "SELECT 'version|' + CAST(SERVERPROPERTY('ProductVersion') AS varchar(50)) + ' ' + CAST(SERVERPROPERTY('Edition') AS varchar(80));",
  "SELECT 'auth_mode|' + CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'windows' ELSE 'mixed' END;",
  "SELECT '===XOLOTL settings===';",
  "SELECT name + '|' + CAST(value_in_use AS varchar(20)) FROM sys.configurations WHERE name IN (" +
    "'xp_cmdshell','Ole Automation Procedures','Ad Hoc Distributed Queries','clr enabled'," +
    "'cross db ownership chaining','remote access','scan for startup procs');",
  "SELECT '===XOLOTL logins===';",
  "SELECT name + '|' + CAST(is_disabled AS varchar(1)) + '|' + CAST(is_policy_checked AS varchar(1)) FROM sys.sql_logins;",
  "SELECT '===XOLOTL sysadmins===';",
  "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id " +
    "JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE r.name = 'sysadmin';",
].join("\n");

function mssqlAdvisory(target?: string): string {
  const where = target ? `la instancia ${target}` : "la instancia SQL Server";
  return [
    `## Tier 1 · advisory — auditoría de configuración de ${where} (solo lectura)`,
    "Ninguna consulta cambia datos. Una cuenta con VIEW SERVER STATE y lectura del catálogo basta",
    "(por ejemplo un login con el rol de servidor ##MS_DefinitionReader## / VIEW ANY DEFINITION).",
    "",
    "1. Guarda este script como mssql-collect.sql:",
    "",
    MSSQL_COLLECTOR,
    "",
    "2. Ejecútalo con sqlcmd sin encabezados y vuelca la salida a un archivo:",
    '     sqlcmd -S <host> -U <usuario_lectura> -P <clave> -d master -h -1 -W -s "|" -i mssql-collect.sql -o mssql-audit.txt',
    "   (con autenticación de Windows usa -E en vez de -U/-P.)",
    "",
    "3. Volver: scan_db con engine=mssql y collected_file=<ruta de mssql-audit.txt>.",
  ].join("\n");
}

export function dbAdvisory(engine: DbEngine, target?: string): string {
  if (engine === "mysql") return mysqlAdvisory(target);
  if (engine === "mssql") return mssqlAdvisory(target);
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

const SYSTEM_MYSQL_USERS = new Set(["root", "mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys", "debian-sys-maint"]);

function mysqlChecks(sec: Record<string, string[]>, host: string): { findings: RawFinding[]; version?: string } {
  const settings: Record<string, string> = {};
  for (const l of sec.settings ?? []) {
    const i = l.indexOf("|");
    if (i > 0) settings[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim();
  }
  const version = (sec.meta ?? []).map((l) => l.split("|").slice(1).join("|")).find(Boolean);
  const users = (sec.users ?? [])
    .map((l) => l.split("|"))
    .filter((p) => p.length >= 6)
    .map((p) => ({ user: p[0], host: p[1], auth: p[2], plugin: p[3].toLowerCase(), super: p[4] === "Y", grant: p[5] === "Y" }));

  const out: RawFinding[] = [];
  const add = (rule: string, severity: Severity, title: string, description: string, remediation: string, evidence?: string) =>
    out.push({ tool: "db-audit", category: "config", severity, ruleId: rule, title, description, remediation, evidence, location: { target: host } });
  const s = (k: string) => (settings[k] ?? "").toLowerCase();
  const has = (k: string) => k in settings;

  if (has("require_secure_transport") && s("require_secure_transport") === "off")
    add("XOL-MY-TLS", "high", "MySQL no exige TLS en las conexiones", "Con require_secure_transport=OFF se aceptan conexiones sin cifrar: credenciales y datos viajan en claro.", "require_secure_transport=ON y configurar certificados TLS del servidor.", "require_secure_transport=OFF");

  if (/tlsv1($|,|\.1)/.test(s("tls_version")))
    add("XOL-MY-TLSVER", "medium", `MySQL permite versiones TLS obsoletas (${settings.tls_version})`, "TLS 1.0/1.1 tienen debilidades conocidas.", "tls_version='TLSv1.2,TLSv1.3'.", `tls_version=${settings.tls_version}`);

  if (s("local_infile") === "on")
    add("XOL-MY-LOCALINFILE", "medium", "LOAD DATA LOCAL INFILE habilitado en MySQL", "Con local_infile=ON un servidor o una inyección pueden hacer que el cliente lea archivos locales y los envíe.", "local_infile=OFF salvo que una carga concreta lo requiera.", "local_infile=ON");

  if (has("secure_file_priv") && settings.secure_file_priv === "")
    add("XOL-MY-FILEPRIV", "high", "secure_file_priv sin restricción en MySQL", "Vacío permite LOAD_FILE e INTO OUTFILE sobre cualquier ruta: un usuario con FILE puede leer o escribir archivos del servidor.", "Fijar secure_file_priv a una carpeta dedicada, o a NULL para deshabilitar la importación/exportación por archivo.", "secure_file_priv= (vacío)");

  if (s("default_authentication_plugin") === "mysql_native_password")
    add("XOL-MY-AUTHPLUGIN", "medium", "Plugin de autenticación débil por defecto en MySQL", "mysql_native_password usa un hash SHA-1 simple; caching_sha2_password es más fuerte y es el estándar en MySQL 8.", "default_authentication_plugin=caching_sha2_password y migrar las cuentas.", "default_authentication_plugin=mysql_native_password");

  if (!has("validate_password.policy"))
    add("XOL-MY-PWPOLICY", "low", "Sin validación de complejidad de contraseñas en MySQL", "El componente validate_password no está activo: se pueden fijar contraseñas débiles.", "Instalar el componente validate_password y fijar una política (LENGTH/MIXED/number/special).", "validate_password no instalado");

  if (s("general_log") === "on")
    add("XOL-MY-GENLOG", "low", "general_log activo en MySQL", "El log general registra todas las sentencias en claro (incluidas las que llevan datos sensibles) y degrada el rendimiento; no es auditoría de seguridad.", "Desactivar general_log en producción; para auditoría usar el audit log plugin.", "general_log=ON");

  if (users.length) {
    const noPass = users.filter((u) => u.auth === "EMPTY" && u.user !== "" && !SYSTEM_MYSQL_USERS.has(u.user.toLowerCase()));
    if (noPass.length) add("XOL-MY-NOPASS", "critical", `Cuentas MySQL sin contraseña (${noPass.length})`, "Una cuenta sin contraseña permite entrar sin credenciales por cualquier host que la regla permita.", "Fijar contraseña (ALTER USER … IDENTIFIED BY …) o eliminar la cuenta.", noPass.map((u) => `${u.user}@${u.host}`).join("\n"));

    const anon = users.filter((u) => u.user === "");
    if (anon.length) add("XOL-MY-ANON", "high", "Cuentas anónimas en MySQL", "Las cuentas anónimas (User vacío) permiten conexiones sin usuario nombrado y complican la trazabilidad.", "DROP USER ''@'host' para todas las cuentas anónimas.", anon.map((u) => `''@${u.host}`).join("\n"));

    const anyHost = users.filter((u) => u.host === "%" && !SYSTEM_MYSQL_USERS.has(u.user.toLowerCase()) && u.user !== "");
    if (anyHost.length) add("XOL-MY-ANYHOST", "medium", `Cuentas MySQL accesibles desde cualquier host (${anyHost.length})`, "Con Host='%' la cuenta acepta conexiones desde cualquier IP; reduce el control a la sola contraseña.", "Restringir el Host a las redes/hosts que de verdad se conectan.", anyHost.map((u) => `${u.user}@%`).join(", "));

    const supers = users.filter((u) => (u.super || u.grant) && !SYSTEM_MYSQL_USERS.has(u.user.toLowerCase()));
    if (supers.length) add("XOL-MY-SUPER", "medium", `Cuentas MySQL con privilegios de administración (${supers.length})`, "SUPER o GRANT OPTION fuera de las cuentas de sistema rompen el menor privilegio y son objetivos de alto valor.", "Dar a las aplicaciones solo los privilegios que usan; reservar SUPER/GRANT a la administración.", supers.map((u) => `${u.user}@${u.host}${u.super ? " SUPER" : ""}${u.grant ? " GRANT" : ""}`).join("\n"));

    const weakPlugin = users.filter((u) => u.plugin === "mysql_native_password" && !SYSTEM_MYSQL_USERS.has(u.user.toLowerCase()));
    if (weakPlugin.length) add("XOL-MY-WEAKPLUGIN", "low", `Cuentas MySQL con hashing de contraseña débil (${weakPlugin.length})`, "mysql_native_password usa SHA-1; caching_sha2_password es más resistente.", "Migrar las cuentas a caching_sha2_password (ALTER USER … IDENTIFIED WITH caching_sha2_password).", weakPlugin.map((u) => `${u.user}@${u.host}`).join(", "));
  }

  return { findings: out, version };
}

const SYSTEM_MSSQL_LOGINS = /^(##|NT SERVICE\\|NT AUTHORITY\\)/i;

function mssqlChecks(sec: Record<string, string[]>, host: string): { findings: RawFinding[]; version?: string } {
  const settings: Record<string, string> = {};
  let authMode = "";
  let version: string | undefined;
  for (const l of sec.meta ?? []) {
    const [k, ...rest] = l.split("|");
    if (k === "version") version = rest.join("|");
    if (k === "auth_mode") authMode = rest.join("|").trim().toLowerCase();
  }
  for (const l of sec.settings ?? []) {
    const i = l.indexOf("|");
    if (i > 0) settings[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim();
  }
  const logins = (sec.logins ?? [])
    .map((l) => l.split("|"))
    .filter((p) => p.length >= 3)
    .map((p) => ({ name: p[0], disabled: p[1] === "1", policy: p[2] === "1" }));
  const sysadmins = (sec.sysadmins ?? []).map((l) => l.trim()).filter(Boolean);

  const out: RawFinding[] = [];
  const add = (rule: string, severity: Severity, title: string, description: string, remediation: string, evidence?: string) =>
    out.push({ tool: "db-audit", category: "config", severity, ruleId: rule, title, description, remediation, evidence, location: { target: host } });
  const on = (k: string) => settings[k] === "1";

  if (on("xp_cmdshell"))
    add("XOL-MS-XPCMD", "critical", "xp_cmdshell habilitado en SQL Server", "xp_cmdshell ejecuta comandos del sistema operativo desde SQL: una inyección o un login comprometido se convierte en ejecución en el servidor.", "Deshabilitar: EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE. Dejarlo solo si un proceso lo exige, muy acotado.", "xp_cmdshell=1");
  if (on("ole automation procedures"))
    add("XOL-MS-OLE", "high", "Ole Automation Procedures habilitado", "Permite instanciar objetos COM desde T-SQL (sp_OACreate), otra vía de ejecución y acceso al sistema.", "Deshabilitar Ole Automation Procedures salvo que una aplicación lo requiera.", "Ole Automation Procedures=1");
  if (on("ad hoc distributed queries"))
    add("XOL-MS-ADHOC", "medium", "Ad Hoc Distributed Queries habilitado", "OPENROWSET/OPENDATASOURCE permiten consultar orígenes externos y se abusan para exfiltración o relay de credenciales.", "Deshabilitar Ad Hoc Distributed Queries si no se usa.", "Ad Hoc Distributed Queries=1");
  if (on("clr enabled"))
    add("XOL-MS-CLR", "medium", "CLR habilitado en SQL Server", "El CLR permite ejecutar ensamblados .NET dentro de SQL; sin control de ensamblados firmados amplía la superficie de ejecución.", "Deshabilitar CLR si no se usa, o exigir 'clr strict security' y ensamblados firmados.", "clr enabled=1");
  if (on("cross db ownership chaining"))
    add("XOL-MS-XDBCHAIN", "medium", "Cross DB Ownership Chaining habilitado a nivel de instancia", "Permite que permisos crucen bases por cadena de propiedad, facilitando la escalada entre bases.", "Deshabilitar a nivel de instancia; habilitarlo por base solo si es imprescindible.", "cross db ownership chaining=1");

  if (authMode === "mixed")
    add("XOL-MS-AUTH", "medium", "SQL Server en modo de autenticación mixto", "El modo mixto habilita logins SQL (usuario/clave), susceptibles de fuerza bruta y sin la gestión centralizada de AD.", "Preferir autenticación de Windows/AD; si se necesita el modo mixto, aplicar políticas de contraseña fuertes y monitoreo.", "IsIntegratedSecurityOnly=0 (mixto)");

  const sa = logins.find((l) => l.name.toLowerCase() === "sa");
  if (sa && !sa.disabled)
    add("XOL-MS-SA", "medium", "Cuenta 'sa' habilitada", "La cuenta sa es el superusuario conocido de SQL Server y blanco de fuerza bruta.", "Deshabilitar sa (ALTER LOGIN sa DISABLE) o al menos renombrarla y ponerle una contraseña larga y aleatoria.", "sa habilitada");

  const noPolicy = logins.filter((l) => !l.policy && !l.disabled && l.name.toLowerCase() !== "sa");
  if (noPolicy.length)
    add("XOL-MS-POLICY", "medium", `Logins SQL sin política de contraseñas (${noPolicy.length})`, "Con CHECK_POLICY desactivado, esos logins aceptan contraseñas débiles y no se bloquean por intentos.", "ALTER LOGIN … WITH CHECK_POLICY = ON (y CHECK_EXPIRATION según el caso).", noPolicy.map((l) => l.name).join(", "));

  const extraSa = sysadmins.filter((n) => n.toLowerCase() !== "sa" && !SYSTEM_MSSQL_LOGINS.test(n));
  if (extraSa.length > 2)
    add("XOL-MS-SYSADMIN", "medium", `Muchos miembros del rol sysadmin (${extraSa.length})`, "Cada sysadmin tiene control total de la instancia; cuantos más, mayor superficie y menor control.", "Reducir sysadmin al mínimo; dar permisos acotados por base/rol a las aplicaciones.", extraSa.join(", "));

  if (on("remote access"))
    add("XOL-MS-REMOTE", "low", "Opción 'remote access' habilitada", "La opción heredada remote access permite procedimientos almacenados remotos (sp_addserver), rara vez necesaria.", "Deshabilitar: EXEC sp_configure 'remote access',0; RECONFIGURE.", "remote access=1");

  return { findings: out, version };
}

export interface DbParse {
  findings: RawFinding[];
  version?: string;
  host: string;
}

export function parseDbCollected(engine: DbEngine, text: string, host = "base-de-datos"): DbParse {
  if (!/===XOLOTL (meta|settings|roles|hba|users|logins|sysadmins)===/.test(text))
    throw new Error("La salida no trae las marcas ===XOLOTL …===. Genera el archivo con el script que da scan_db en modo advisory.");
  const sec = sections(text);
  const { findings, version } = engine === "mysql" ? mysqlChecks(sec, host) : engine === "mssql" ? mssqlChecks(sec, host) : pgChecks(sec, host);
  return { findings, version, host };
}
