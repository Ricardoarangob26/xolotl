/*
 * Servidores Linux: del texto del recolector (src/collector.sh) a hallazgos.
 *  - Vulnerabilidades: los paquetes se vuelven un SBOM CycloneDX con la distribución y el paquete
 *    fuente, y Trivy los cruza con los avisos de la propia distribución (así entiende los parches
 *    que RHEL y Debian aplican sin cambiar la versión, que un escaneo por banner no ve).
 *  - Endurecimiento: comprobaciones propias sobre SSH, cuentas, firewall, kernel, servicios…
 */
import fs from "node:fs";
import path from "node:path";
import { RawFinding, Severity } from "./findings.js";

export type Sections = Map<string, string[]>;

export function parseCollected(text: string): Sections {
  const out: Sections = new Map();
  let current: string | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.match(/^===XOLOTL ([a-z_]+)===$/);
    if (m) {
      current = m[1];
      if (!out.has(current)) out.set(current, []);
      continue;
    }
    if (current && raw.trim()) out.get(current)!.push(raw);
  }
  if (!out.has("meta") || !out.has("os_release")) {
    throw new Error("El archivo no parece salida del recolector de Xolotl (faltan las secciones meta/os_release).");
  }
  return out;
}

const kv = (lines: string[] = []) =>
  Object.fromEntries(
    lines
      .map((l) => l.match(/^([^=]+)=(.*)$/))
      .filter((m): m is RegExpMatchArray => !!m)
      .map((m) => [m[1].trim(), m[2].trim().replace(/^"(.*)"$/, "$1")]),
  ) as Record<string, string>;

export interface HostInfo {
  hostname: string;
  osId: string;
  osName: string;
  osVersion: string;
  trivyType: string | null;
  kernel: string;
  root: boolean;
  packages: number;
}

/** ID de os-release → tipo de SO de Trivy (nombre del componente y espacio del purl). */
const TRIVY_OS: Record<string, string> = {
  debian: "debian",
  ubuntu: "ubuntu",
  rhel: "redhat",
  centos: "centos",
  rocky: "rocky",
  almalinux: "alma",
  ol: "oracle",
  amzn: "amazon",
  fedora: "fedora",
  alpine: "alpine",
};

export function hostInfo(s: Sections): HostInfo {
  const meta = kv(s.get("meta"));
  const os = kv(s.get("os_release"));
  const osId = (os.ID ?? "").toLowerCase();
  const trivyType = TRIVY_OS[osId] ?? null;
  // Debian guarda el punto de versión en /etc/debian_version (os-release solo dice "12").
  const debVer = s.get("debian_version")?.[0]?.trim();
  const osVersion = osId === "debian" && debVer && /^\d/.test(debVer) ? debVer : os.VERSION_ID ?? "";
  const packages = (s.get("pkgs_deb")?.length ?? 0) + (s.get("pkgs_rpm")?.length ?? 0) + (s.get("pkgs_apk")?.length ?? 0);
  return {
    hostname: meta.fqdn || meta.hostname || "host",
    osId,
    osName: os.PRETTY_NAME ?? osId,
    osVersion,
    trivyType,
    kernel: meta.kernel ?? "",
    root: meta.uid === "0",
    packages,
  };
}

// ───────────── SBOM CycloneDX para `trivy sbom` ─────────────

const splitEpoch = (v: string) => {
  const m = v.match(/^(\d+):(.*)$/);
  return m ? { epoch: m[1], rest: m[2] } : { epoch: "0", rest: v };
};

/** "1.2.3-4ubuntu1" → versión "1.2.3", release "4ubuntu1" (paquetes nativos de Debian no traen release). */
function splitDebVersion(v: string) {
  const { epoch, rest } = splitEpoch(v);
  const i = rest.lastIndexOf("-");
  return i > 0 ? { epoch, version: rest.slice(0, i), release: rest.slice(i + 1) } : { epoch, version: rest, release: "" };
}

/** "openssl-3.0.7-24.el9.src.rpm" → nombre, versión y release del paquete fuente. */
function splitSourceRpm(src: string) {
  const base = src.replace(/\.(no)?src\.rpm$/, "");
  const r = base.lastIndexOf("-");
  const v = base.lastIndexOf("-", r - 1);
  if (r < 0 || v < 0) return null;
  return { name: base.slice(0, v), version: base.slice(v + 1, r), release: base.slice(r + 1) };
}

const enc = (s: string) => encodeURIComponent(s).replace(/%3A/g, ":");

interface Component {
  "bom-ref": string;
  type: string;
  name: string;
  version: string;
  purl?: string;
  properties?: { name: string; value: string }[];
}

export function buildSbom(s: Sections, info: HostInfo): object {
  if (!info.trivyType) throw new Error(`Distribución no soportada para vulnerabilidades: ${info.osId || "desconocida"}`);
  const t = info.trivyType;
  const distro = `${t}-${info.osVersion}`;
  const osRef = `os-${t}`;
  const prop = (name: string, value: string | undefined) => (value ? [{ name: `aquasecurity:trivy:${name}`, value }] : []);
  const comps: Component[] = [];

  for (const line of s.get("pkgs_deb") ?? []) {
    const [, name, version, arch, srcName, srcVersion] = line.split("\t");
    if (!name || !version) continue;
    const bin = splitDebVersion(version);
    const src = splitDebVersion(srcVersion || version);
    const purlVer = bin.release ? `${bin.version}-${bin.release}` : bin.version;
    const purl = `pkg:deb/${t}/${name}@${enc(purlVer)}?arch=${arch}&distro=${distro}${bin.epoch !== "0" ? `&epoch=${bin.epoch}` : ""}`;
    comps.push({
      "bom-ref": purl,
      type: "library",
      name,
      version: bin.epoch !== "0" ? `${bin.epoch}:${purlVer}` : purlVer,
      purl,
      properties: [
        ...prop("PkgID", `${name}@${purlVer}`),
        ...prop("PkgType", t),
        ...prop("SrcName", srcName || name),
        ...prop("SrcVersion", src.version),
        ...prop("SrcRelease", src.release),
        ...(src.epoch !== "0" ? prop("SrcEpoch", src.epoch) : []),
      ],
    });
  }

  for (const line of s.get("pkgs_rpm") ?? []) {
    const [name, epochRaw, version, release, arch, sourceRpm] = line.split("\t");
    if (!name || !version) continue;
    const epoch = /^\d+$/.test(epochRaw ?? "") ? epochRaw : "0";
    const src = sourceRpm && sourceRpm !== "(none)" ? splitSourceRpm(sourceRpm) : null;
    const purl = `pkg:rpm/${t}/${name}@${enc(`${version}-${release}`)}?arch=${arch}&distro=${distro}${epoch !== "0" ? `&epoch=${epoch}` : ""}`;
    comps.push({
      "bom-ref": purl,
      type: "library",
      name,
      version: `${epoch !== "0" ? `${epoch}:` : ""}${version}-${release}`,
      purl,
      properties: [
        ...prop("PkgID", `${name}@${version}-${release}.${arch}`),
        ...prop("PkgType", t),
        ...(src ? [...prop("SrcName", src.name), ...prop("SrcVersion", src.version), ...prop("SrcRelease", src.release)] : []),
        ...(epoch !== "0" ? prop("SrcEpoch", epoch) : []),
      ],
    });
  }

  for (const line of s.get("pkgs_apk") ?? []) {
    const m = line.trim().match(/^(.+)-([^-]+-r\d+)$/);
    if (!m) continue;
    const purl = `pkg:apk/alpine/${m[1]}@${enc(m[2])}?distro=${info.osVersion}`;
    comps.push({ "bom-ref": purl, type: "library", name: m[1], version: m[2], purl, properties: [...prop("PkgType", "alpine")] });
  }

  const hostRef = `host-${info.hostname}`;
  return {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: "application", name: "xolotl" }] },
      component: { "bom-ref": hostRef, type: "application", name: info.hostname },
    },
    components: [
      { "bom-ref": osRef, type: "operating-system", name: t, version: info.osVersion, properties: [...prop("Class", "os-pkgs"), ...prop("Type", t)] },
      ...comps,
    ],
    dependencies: [
      { ref: hostRef, dependsOn: [osRef] },
      { ref: osRef, dependsOn: comps.map((c) => c["bom-ref"]) },
      ...comps.map((c) => ({ ref: c["bom-ref"], dependsOn: [] })),
    ],
  };
}

// ───────────── Endurecimiento ─────────────

interface Check {
  rule: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  file?: string;
  evidence?: string;
}

const WEAK_SSH = /(^|,)(3des-cbc|aes\d+-cbc|blowfish-cbc|cast128-cbc|arcfour\w*|hmac-md5\w*|hmac-sha1(-96)?|umac-64@openssh\.com|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)(,|$)/;
const DB_PORTS: Record<string, string> = {
  "3306": "MySQL/MariaDB",
  "5432": "PostgreSQL",
  "6379": "Redis",
  "27017": "MongoDB",
  "9200": "Elasticsearch",
  "11211": "Memcached",
  "1433": "SQL Server",
  "5984": "CouchDB",
  "2375": "API de Docker sin TLS",
};
const LEGACY_PORTS: Record<string, string> = { "21": "FTP", "23": "Telnet", "69": "TFTP", "512": "rexec", "513": "rlogin", "514": "rsh" };
const STANDARD_SUID = /^\/(usr\/)?(s?bin|lib(exec)?|lib64)\//;

function sshValue(s: Sections, key: string): string | undefined {
  const k = key.toLowerCase();
  // sshd -T da el valor efectivo (incluye valores por defecto); sin root, lo explícito del archivo.
  const eff = (s.get("sshd_effective") ?? []).find((l) => l.toLowerCase().startsWith(k + " "));
  if (eff) return eff.slice(k.length + 1).trim().toLowerCase();
  const cfg = (s.get("sshd_config") ?? []).find((l) => l.trim().toLowerCase().startsWith(k + " ") || l.trim().toLowerCase().startsWith(k + "\t"));
  return cfg?.trim().split(/\s+/).slice(1).join(" ").toLowerCase();
}

export function hardeningChecks(s: Sections, info: HostInfo): Check[] {
  const out: Check[] = [];
  const add = (c: Check) => out.push(c);
  const sshdKnown = (s.get("sshd_effective")?.length ?? 0) + (s.get("sshd_config")?.length ?? 0) > 0;
  const listening = s.get("listening") ?? [];
  const services = kv(s.get("services_active"));
  const isActive = (svc: string) => (services[svc] ?? "").startsWith("active/");

  // ── SSH ──
  if (sshdKnown) {
    const root = sshValue(s, "PermitRootLogin");
    if (root === "yes") {
      add({ rule: "XOL-SSH-001", severity: "high", title: "SSH permite entrar como root con contraseña", file: "/etc/ssh/sshd_config", evidence: `PermitRootLogin ${root}`, description: "Un atacante puede intentar la contraseña de root directamente; si acierta, tiene el servidor completo y no queda rastro de qué persona entró.", remediation: "PermitRootLogin no (o prohibit-password si se administra con llaves) y entrar con un usuario nominal + sudo." });
    }
    const pwd = sshValue(s, "PasswordAuthentication");
    if (pwd === "yes") {
      add({ rule: "XOL-SSH-002", severity: "medium", title: "SSH acepta contraseñas", file: "/etc/ssh/sshd_config", evidence: `PasswordAuthentication ${pwd}`, description: "Las contraseñas se pueden adivinar por fuerza bruta o reutilizar si se filtran en otro sistema.", remediation: "Pasar a llaves (PasswordAuthentication no) o, si no es posible, fail2ban + MFA y limitar el acceso por firewall a la red de administración." });
    }
    if (sshValue(s, "PermitEmptyPasswords") === "yes") {
      add({ rule: "XOL-SSH-003", severity: "critical", title: "SSH permite contraseñas vacías", file: "/etc/ssh/sshd_config", evidence: "PermitEmptyPasswords yes", description: "Cualquier cuenta sin contraseña es accesible desde la red sin credenciales.", remediation: "PermitEmptyPasswords no." });
    }
    if (sshValue(s, "X11Forwarding") === "yes") {
      add({ rule: "XOL-SSH-004", severity: "low", title: "SSH con X11Forwarding activo", file: "/etc/ssh/sshd_config", evidence: "X11Forwarding yes", description: "En un servidor sin escritorio no se usa y amplía la superficie de ataque del cliente.", remediation: "X11Forwarding no." });
    }
    const tries = Number(sshValue(s, "MaxAuthTries"));
    if (tries > 4) {
      add({ rule: "XOL-SSH-005", severity: "low", title: `SSH permite ${tries} intentos por conexión`, file: "/etc/ssh/sshd_config", evidence: `MaxAuthTries ${tries}`, description: "Más intentos por conexión aceleran la fuerza bruta.", remediation: "MaxAuthTries 3 o 4." });
    }
    const weak = ["ciphers", "macs", "kexalgorithms"].flatMap((k) => {
      const v = sshValue(s, k);
      return v ? v.split(",").filter((a) => WEAK_SSH.test(a)).map((a) => `${k}: ${a}`) : [];
    });
    if (weak.length) {
      add({ rule: "XOL-SSH-006", severity: "medium", title: "SSH ofrece algoritmos criptográficos débiles", file: "/etc/ssh/sshd_config", evidence: weak.join("\n"), description: "CBC, SHA-1 y grupos Diffie-Hellman pequeños tienen ataques conocidos o margen de seguridad insuficiente.", remediation: "Definir Ciphers, MACs y KexAlgorithms modernos (chacha20-poly1305, aes-gcm, hmac-sha2-*-etm, curve25519/sntrup) o usar la política criptográfica DEFAULT/FUTURE del sistema (RHEL: update-crypto-policies)." });
    }
  }

  // ── Cuentas ──
  const uid0 = (s.get("passwd") ?? []).map((l) => l.split(":")).filter((p) => p[1] === "0" && p[0] !== "root").map((p) => p[0]);
  if (uid0.length) {
    add({ rule: "XOL-ACC-001", severity: "critical", title: `Cuentas con UID 0 además de root: ${uid0.join(", ")}`, file: "/etc/passwd", evidence: uid0.join(", "), description: "Una cuenta con UID 0 es root con otro nombre: es una técnica clásica de persistencia tras una intrusión.", remediation: "Investigar quién la creó y cuándo; eliminarla o asignarle un UID normal." });
  }
  const empty = (s.get("empty_passwords") ?? []).filter((l) => l !== "__sin_permiso__");
  if (empty.length) {
    add({ rule: "XOL-ACC-002", severity: "critical", title: `Cuentas sin contraseña: ${empty.join(", ")}`, file: "/etc/shadow", evidence: empty.join(", "), description: "Una cuenta sin contraseña permite entrar sin credenciales por cualquier servicio que use PAM.", remediation: "Bloquearlas (passwd -l) o asignarles contraseña." });
  }
  const nopasswd = (s.get("sudoers_nopasswd") ?? []).filter((l) => l !== "__sin_permiso__");
  if (nopasswd.length) {
    const all = nopasswd.filter((l) => /NOPASSWD:\s*ALL\b/.test(l));
    add({ rule: "XOL-ACC-003", severity: all.length ? "medium" : "low", title: `sudo sin contraseña (${nopasswd.length} regla(s)${all.length ? `, ${all.length} con ALL` : ""})`, file: "/etc/sudoers", evidence: nopasswd.slice(0, 10).join("\n"), description: "Quien comprometa una de esas cuentas obtiene root sin conocer ninguna contraseña. Es aceptable para comandos puntuales de automatización, no para ALL.", remediation: "Limitar NOPASSWD a comandos exactos (rutas absolutas) y a cuentas de servicio; quitar NOPASSWD: ALL de usuarios personales." });
  }
  const dockerGroup = (s.get("group_privileged") ?? []).find((l) => l.startsWith("docker:"));
  const dockerMembers = dockerGroup?.split(":")[3]?.split(",").filter(Boolean) ?? [];
  if (dockerMembers.length) {
    add({ rule: "XOL-ACC-004", severity: "medium", title: `Usuarios en el grupo docker: ${dockerMembers.join(", ")}`, file: "/etc/group", evidence: dockerGroup, description: "Pertenecer al grupo docker equivale a ser root: basta montar / en un contenedor.", remediation: "Dejar solo cuentas de servicio que lo necesiten, o usar Docker rootless / sudo para comandos concretos." });
  }

  // ── Parches activos ──
  const running = info.kernel;
  const installedKernels = (s.get("kernels_installed") ?? []).map((l) => l.trim());
  const rebootFlag = (s.get("reboot_required") ?? []).includes("yes");
  // rpm -q no ordena por versión: orden numérico ("…-427.13…" va después de "…-362.8…").
  const newest = installedKernels.slice().sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).pop() ?? "";
  const runningCore = running.replace(/\.(x86_64|aarch64|i686)$/, "");
  const kernelBehind = !!runningCore && !!newest && !newest.includes(runningCore);
  if (rebootFlag || kernelBehind) {
    add({ rule: "XOL-PAT-001", severity: "medium", title: "Hay parches instalados que no están activos (reinicio pendiente)", evidence: `kernel en uso: ${running}${newest ? `\nkernel más reciente instalado: ${newest}` : ""}${rebootFlag ? "\nel sistema marca reinicio requerido" : ""}`, description: "Las actualizaciones del kernel y de librerías base no protegen hasta reiniciar: el escaneo de paquetes las cuenta como corregidas, pero el sistema sigue ejecutando la versión vulnerable.", remediation: "Programar un reinicio en ventana de mantenimiento." });
  }
  const autoUpd = s.get("auto_updates") ?? [];
  const autoOn = autoUpd.some((l) => /"1"|yes|true/i.test(l)) || isActive("dnf-automatic.timer") || isActive("unattended-upgrades");
  if (!autoOn) {
    add({ rule: "XOL-PAT-002", severity: "low", title: "Sin actualizaciones de seguridad automáticas", description: "Los parches dependen de que alguien se acuerde; las ventanas entre aviso y explotación hoy son de días.", remediation: "Debian/Ubuntu: unattended-upgrades solo con el origen -security. RHEL: dnf-automatic con upgrade_type = security. O un proceso de parcheo mensual documentado." });
  }

  // ── Firewall y MAC ──
  const fw = kv(s.get("firewall"));
  const fwActive = ["firewalld", "ufw", "nftables", "iptables", "netfilter-persistent"].some((k) => fw[k] === "active") || Number(fw.nft_rules) > 5 || Number(fw.iptables_rules) > 0 || (s.get("firewall") ?? []).some((l) => /^Status: active/.test(l));
  if (!fwActive) {
    add({ rule: "XOL-NET-001", severity: "medium", title: "No se detectó firewall activo en el host", evidence: Object.entries(fw).map(([k, v]) => `${k}=${v}`).join("\n"), description: "Cualquier servicio que escuche en todas las interfaces queda expuesto a toda la red, aunque solo debiera usarse localmente.", remediation: "Activar firewalld/ufw/nftables permitiendo solo los puertos necesarios (y SSH solo desde la red de administración)." + (info.root ? "" : " Nota: sin sudo no siempre se pueden leer las reglas; confirmar con root.") });
  }
  const selinux = s.get("selinux")?.[0]?.trim().toLowerCase();
  if (selinux === "disabled") add({ rule: "XOL-MAC-001", severity: "medium", title: "SELinux deshabilitado", evidence: "getenforce: Disabled", description: "SELinux contiene el daño cuando se explota un servicio: sin él, el proceso comprometido puede tocar todo lo que su usuario pueda.", remediation: "Volver a Enforcing (pasando primero por Permissive para revisar denegaciones en /var/log/audit/audit.log)." });
  else if (selinux === "permissive") add({ rule: "XOL-MAC-002", severity: "low", title: "SELinux en modo permisivo", evidence: "getenforce: Permissive", description: "Registra pero no bloquea.", remediation: "Revisar denegaciones y pasar a Enforcing." });
  const apparmor = s.get("apparmor")?.[0]?.trim();
  if ((info.osId === "ubuntu" || info.osId === "debian") && apparmor && !/^(yes|y)$/i.test(apparmor)) {
    add({ rule: "XOL-MAC-003", severity: "low", title: "AppArmor no está activo", evidence: `apparmor: ${apparmor}`, description: "Sin perfiles de AppArmor un servicio comprometido no tiene contención adicional.", remediation: "Habilitar AppArmor y los perfiles de los servicios expuestos." });
  }

  // ── Kernel / sysctl ──
  const sc = kv(s.get("sysctl"));
  if (sc["kernel.randomize_va_space"] && sc["kernel.randomize_va_space"] !== "2") add({ rule: "XOL-KRN-001", severity: "medium", title: "ASLR no está completo", evidence: `kernel.randomize_va_space=${sc["kernel.randomize_va_space"]}`, description: "Sin aleatorización completa de memoria, explotar fallos de memoria es mucho más fácil.", remediation: "sysctl kernel.randomize_va_space=2 (persistir en /etc/sysctl.d/)." });
  if (sc["net.ipv4.conf.all.accept_redirects"] === "1" || sc["net.ipv4.conf.all.accept_source_route"] === "1") add({ rule: "XOL-KRN-002", severity: "low", title: "El kernel acepta redirecciones ICMP o enrutamiento de origen", evidence: `accept_redirects=${sc["net.ipv4.conf.all.accept_redirects"]} accept_source_route=${sc["net.ipv4.conf.all.accept_source_route"]}`, description: "Permite a un equipo de la misma red desviar el tráfico del servidor (hombre en el medio).", remediation: "net.ipv4.conf.all.accept_redirects=0 y accept_source_route=0." });
  if (sc["net.ipv4.tcp_syncookies"] === "0") add({ rule: "XOL-KRN-003", severity: "low", title: "SYN cookies desactivadas", evidence: "net.ipv4.tcp_syncookies=0", description: "El servidor es más vulnerable a inundaciones SYN.", remediation: "net.ipv4.tcp_syncookies=1." });
  if (sc["fs.suid_dumpable"] && sc["fs.suid_dumpable"] !== "0") add({ rule: "XOL-KRN-004", severity: "low", title: "Volcados de memoria de programas SUID permitidos", evidence: `fs.suid_dumpable=${sc["fs.suid_dumpable"]}`, description: "Un volcado de un proceso privilegiado puede contener contraseñas o llaves en memoria.", remediation: "fs.suid_dumpable=0." });
  if (sc["net.ipv4.ip_forward"] === "1" && !isActive("docker") && !isActive("containerd")) add({ rule: "XOL-KRN-005", severity: "low", title: "Reenvío de paquetes IP activo sin contenedores que lo justifiquen", evidence: "net.ipv4.ip_forward=1", description: "El servidor puede actuar como enrutador entre redes, saltándose la segmentación.", remediation: "net.ipv4.ip_forward=0 si no es un enrutador, VPN o host de contenedores." });

  // ── Servicios ──
  const listenAll = listening.filter((l) => /(\s|^)(0\.0\.0\.0|\*|\[::\]|::):\d+\s/.test(l));
  const portOf = (l: string) => l.match(/(?:0\.0\.0\.0|\*|\[::\]|::):(\d+)\s/)?.[1];
  const exposedDb = [...new Set(listenAll.map(portOf).filter((p): p is string => !!p && p in DB_PORTS))];
  if (exposedDb.length) {
    add({ rule: "XOL-NET-002", severity: "high", title: `Bases de datos o servicios internos escuchando en todas las interfaces: ${exposedDb.map((p) => `${DB_PORTS[p]} (${p})`).join(", ")}`, evidence: listenAll.filter((l) => exposedDb.includes(portOf(l) ?? "")).join("\n"), description: "Un servicio que solo usa la aplicación local queda alcanzable desde la red; muchos (Redis, Memcached, Elasticsearch, Docker) no traen autenticación por defecto.", remediation: "Escuchar solo en 127.0.0.1 o en la interfaz interna (bind-address), y filtrar el puerto en el firewall." });
  }
  const legacy = [...new Set(listening.map((l) => l.match(/:(\d+)\s/)?.[1]).filter((p): p is string => !!p && p in LEGACY_PORTS))];
  const legacyServices = ["telnet.socket", "rsh.socket", "rlogin.socket", "tftp.socket", "vsftpd", "xinetd"].filter(isActive);
  if (legacy.length || legacyServices.length) {
    add({ rule: "XOL-NET-003", severity: "high", title: `Servicios sin cifrado activos: ${[...legacy.map((p) => LEGACY_PORTS[p]), ...legacyServices].join(", ")}`, evidence: [...legacy, ...legacyServices].join(", "), description: "Telnet, FTP, rsh y TFTP envían credenciales y datos en claro por la red.", remediation: "Deshabilitarlos y usar SSH/SFTP." });
  }
  const extra = ["avahi-daemon", "cups", "rpcbind", "snmpd", "nfs-server", "smb"].filter(isActive);
  if (extra.length) {
    add({ rule: "XOL-SVC-001", severity: "low", title: `Servicios posiblemente innecesarios en un servidor: ${extra.join(", ")}`, evidence: extra.join(", "), description: "Cada servicio activo es superficie de ataque y requiere parches; varios de estos (avahi, cups, rpcbind) rara vez se usan en servidores.", remediation: "Deshabilitar los que no se usen (systemctl disable --now)." });
  }
  if (!isActive("auditd")) add({ rule: "XOL-LOG-001", severity: "low", title: "auditd no está activo", description: "Sin auditoría del kernel es difícil reconstruir qué pasó tras un incidente (quién ejecutó qué, qué archivos cambiaron).", remediation: "Instalar y activar auditd con reglas básicas (por ejemplo las de CIS)." });
  const ntp = s.get("time_sync")?.[0]?.trim();
  if (ntp === "no") add({ rule: "XOL-LOG-002", severity: "low", title: "El reloj no está sincronizado (NTP)", description: "Con la hora corrida, los registros no se pueden correlacionar con otros sistemas y fallan los certificados y tokens con vencimiento.", remediation: "Activar chronyd o systemd-timesyncd contra los servidores NTP de la institución." });

  // ── Archivos ──
  const ww = s.get("world_writable_etc") ?? [];
  if (ww.length) add({ rule: "XOL-FS-001", severity: "high", title: `Archivos de /etc modificables por cualquier usuario (${ww.length})`, evidence: ww.slice(0, 20).join("\n"), description: "Cualquier usuario local puede alterar configuración del sistema, lo que suele llevar a escalar a root.", remediation: "chmod o-w sobre esos archivos y revisar cómo quedaron así." });
  const cronW = s.get("cron_writable") ?? [];
  if (cronW.length) add({ rule: "XOL-FS-002", severity: "high", title: `Tareas programadas modificables por cualquier usuario (${cronW.length})`, evidence: cronW.slice(0, 20).join("\n"), description: "Quien modifique una tarea de cron de root ejecuta comandos como root.", remediation: "chmod o-w y verificar el contenido de esas tareas." });
  const oddSuid = (s.get("suid") ?? []).filter((f) => !STANDARD_SUID.test(f));
  if (oddSuid.length) add({ rule: "XOL-FS-003", severity: "medium", title: `Binarios SUID fuera de las rutas del sistema (${oddSuid.length})`, evidence: oddSuid.slice(0, 20).join("\n"), description: "Un SUID en /opt, /home, /srv o /var no viene del sistema operativo: puede ser una puerta trasera o software que no debería ejecutarse con privilegios.", remediation: "Verificar a qué paquete pertenece cada uno (rpm -qf / dpkg -S); quitar el bit SUID (chmod u-s) si no es necesario." });
  const mounts = s.get("mounts") ?? [];
  const tmp = mounts.find((l) => l.split(" ")[1] === "/tmp");
  if (tmp && !/noexec/.test(tmp)) add({ rule: "XOL-FS-004", severity: "low", title: "/tmp permite ejecutar programas", evidence: tmp, description: "Muchos ataques descargan y ejecutan su carga en /tmp.", remediation: "Montar /tmp con nodev,nosuid,noexec (verificar antes que ninguna aplicación lo necesite)." });

  if (!info.root) {
    add({ rule: "XOL-INFO-001", severity: "info", title: "Recolección sin root: comprobaciones parciales", description: "Sin sudo no se pudo leer la configuración efectiva de SSH, sudoers, /etc/shadow ni las reglas del firewall; esas comprobaciones pueden faltar.", remediation: "Repetir la recolección con sudo para cobertura completa." });
  }
  return out;
}

export function checksToFindings(checks: Check[], info: HostInfo): RawFinding[] {
  return checks.map((c) => ({
    tool: "xolotl-host",
    category: "config",
    severity: c.severity,
    ruleId: c.rule,
    title: c.title,
    description: c.description,
    location: { target: info.hostname, file: c.file },
    evidence: c.evidence,
    remediation: c.remediation,
  }));
}

/** Guarda la recolección cruda y el SBOM en la carpeta de la corrida. */
export function writeArtifacts(dir: string, text: string, sbom: object): string {
  fs.writeFileSync(path.join(dir, "host-collect.txt"), text);
  const file = path.join(dir, "host.cdx.json");
  fs.writeFileSync(file, JSON.stringify(sbom));
  return file;
}
