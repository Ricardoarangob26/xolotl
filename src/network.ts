/*
 * Reconocimiento de red SIN credenciales: descubre puertos y servicios, revisa la postura TLS y
 * marca servicios expuestos de riesgo. El escaneo TCP y la inspección TLS son nativos de Node
 * (no necesitan nmap ni drivers: funcionan igual en Windows, Linux y macOS). ssh-audit (vía uvx)
 * y Nuclei son refuerzos opcionales cuando están disponibles.
 *
 * Solo envía tráfico a objetivos dentro del alcance autorizado (lo aplica scan_network en index.ts).
 */
import net from "node:net";
import tls from "node:tls";
import { RawFinding, Severity } from "./findings.js";

// Puerto → servicio probable. Base para identificar y para las reglas de exposición.
export const COMMON_PORTS: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp", 80: "http", 110: "pop3",
  111: "rpcbind", 135: "msrpc", 137: "netbios", 139: "netbios-ssn", 143: "imap", 161: "snmp",
  389: "ldap", 443: "https", 445: "smb", 465: "smtps", 512: "rexec", 513: "rlogin", 514: "rsh",
  587: "smtp-sub", 623: "ipmi", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
  1433: "mssql", 1521: "oracle", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2375: "docker",
  2376: "docker-tls", 2379: "etcd", 3000: "http-alt", 3128: "proxy", 3306: "mysql", 3389: "rdp",
  4444: "metasploit", 5000: "http-alt", 5432: "postgres", 5601: "kibana", 5672: "amqp", 5900: "vnc",
  5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes", 7001: "weblogic", 8000: "http-alt",
  8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
  9000: "http-alt", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch", 10250: "kubelet",
  11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb", 50070: "hadoop",
};

export const TOP_PORTS = Object.keys(COMMON_PORTS).map(Number);

// Puertos donde se intenta TLS directo (otros servicios usan STARTTLS, que aquí no se prueba).
const TLS_PORTS = new Set([443, 465, 636, 993, 995, 2376, 5986, 6443, 8443, 9200, 9300, 15672]);

// Servicios que casi nunca deberían verse desde fuera del host, con su riesgo.
const EXPOSED: Record<string, { sev: Severity; label: string; note: string }> = {
  telnet: { sev: "high", label: "Telnet", note: "envía credenciales y datos en claro" },
  ftp: { sev: "medium", label: "FTP", note: "normalmente sin cifrado; usar SFTP" },
  tftp: { sev: "high", label: "TFTP", note: "sin autenticación ni cifrado" },
  rsh: { sev: "high", label: "rsh", note: "remoto sin cifrado" },
  rlogin: { sev: "high", label: "rlogin", note: "remoto sin cifrado" },
  rexec: { sev: "high", label: "rexec", note: "ejecución remota sin cifrado" },
  mysql: { sev: "high", label: "MySQL/MariaDB", note: "base de datos expuesta a la red" },
  postgres: { sev: "high", label: "PostgreSQL", note: "base de datos expuesta a la red" },
  mssql: { sev: "high", label: "SQL Server", note: "base de datos expuesta a la red" },
  oracle: { sev: "high", label: "Oracle DB", note: "base de datos expuesta a la red" },
  mongodb: { sev: "critical", label: "MongoDB", note: "sin autenticación por defecto en versiones antiguas" },
  redis: { sev: "critical", label: "Redis", note: "sin autenticación por defecto" },
  memcached: { sev: "critical", label: "Memcached", note: "sin autenticación; usado para amplificación DDoS" },
  elasticsearch: { sev: "high", label: "Elasticsearch", note: "sin autenticación por defecto en versiones antiguas" },
  kibana: { sev: "high", label: "Kibana", note: "panel de datos sin autenticación por defecto" },
  docker: { sev: "critical", label: "API de Docker sin TLS", note: "control total del host de contenedores" },
  etcd: { sev: "critical", label: "etcd", note: "almacén de claves de Kubernetes" },
  kubelet: { sev: "high", label: "Kubelet", note: "API de nodo de Kubernetes" },
  kubernetes: { sev: "medium", label: "API de Kubernetes", note: "plano de control expuesto" },
  vnc: { sev: "high", label: "VNC", note: "escritorio remoto, a menudo sin o con débil autenticación" },
  rdp: { sev: "medium", label: "RDP", note: "escritorio remoto; objetivo frecuente de fuerza bruta y CVE" },
  winrm: { sev: "medium", label: "WinRM sin TLS", note: "administración remota de Windows en claro" },
  smb: { sev: "medium", label: "SMB", note: "compartición de archivos; objetivo de EternalBlue y ransomware" },
  snmp: { sev: "medium", label: "SNMP", note: "a menudo con comunidad 'public' por defecto" },
  ipmi: { sev: "high", label: "IPMI/BMC", note: "controladora de gestión (iLO/iDRAC); CVE graves conocidos" },
  rpcbind: { sev: "low", label: "rpcbind", note: "expone servicios RPC/NFS" },
  nfs: { sev: "medium", label: "NFS", note: "compartición de archivos por red" },
  memcached_udp: { sev: "critical", label: "Memcached", note: "amplificación DDoS" },
  ldap: { sev: "low", label: "LDAP sin cifrar", note: "directorio accesible; preferir LDAPS" },
  amqp: { sev: "medium", label: "RabbitMQ/AMQP", note: "cola de mensajes expuesta" },
  kafka: { sev: "medium", label: "Kafka", note: "bus de mensajes expuesto" },
  hadoop: { sev: "high", label: "Hadoop", note: "interfaz sin autenticación por defecto" },
  weblogic: { sev: "high", label: "WebLogic", note: "servidor con CVE críticos frecuentes" },
};

export interface PortResult {
  port: number;
  service: string;
  banner?: string;
  tls?: TlsInfo;
}

export interface TlsInfo {
  protocol?: string;
  cipher?: string;
  subject?: string;
  issuer?: string;
  selfSigned: boolean;
  notAfter?: string;
  notBefore?: string;
  daysLeft?: number;
  san?: string[];
  keyBits?: number;
  error?: string;
}

export interface HostResult {
  host: string;
  up: boolean;
  ports: PortResult[];
}

function tcpProbe(host: string, port: number, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let banner = "";
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(open ? banner : null);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => {
      // Para web, un GET mínimo provoca respuesta; para el resto, lo que el servicio salude.
      if ([80, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000, 3128].includes(port)) {
        sock.write(`GET / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      }
      setTimeout(() => finish(true), Math.min(600, timeoutMs));
    });
    sock.on("data", (d) => {
      banner += d.toString("latin1");
      if (banner.length > 512) finish(true);
    });
    sock.once("timeout", () => finish(false));
    sock.once("error", () => finish(false));
    sock.connect(port, host);
  });
}

function inspectTls(host: string, port: number, timeoutMs: number): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    let done = false;
    const sock = tls.connect(
      { host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs, ALPNProtocols: ["h2", "http/1.1"] },
      () => {
        if (done) return;
        done = true;
        const cert = sock.getPeerCertificate();
        const cipher = sock.getCipher();
        const now = Date.now();
        const notAfter = cert?.valid_to ? new Date(cert.valid_to).getTime() : undefined;
        const cn = (v: unknown): string | undefined => (Array.isArray(v) ? v.join(", ") : typeof v === "string" ? v : undefined);
        const subjectCN = cn(cert?.subject?.CN);
        const issuerCN = cn(cert?.issuer?.CN);
        const info: TlsInfo = {
          protocol: sock.getProtocol() ?? undefined,
          cipher: cipher?.name,
          subject: subjectCN,
          issuer: issuerCN,
          selfSigned: !!cert && !!subjectCN && subjectCN === issuerCN,
          notAfter: cert?.valid_to,
          notBefore: cert?.valid_from,
          daysLeft: notAfter ? Math.round((notAfter - now) / 86400000) : undefined,
          san: cert?.subjectaltname?.split(",").map((s) => s.trim()),
          keyBits: (cert as { bits?: number })?.bits,
        };
        sock.destroy();
        resolve(info);
      },
    );
    sock.setTimeout(timeoutMs);
    const bail = (error?: string) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(error ? { selfSigned: false, error } : null);
    };
    sock.once("timeout", () => bail());
    // Un error de certificado (p. ej. autofirmado) no impide el handshake con rejectUnauthorized:false;
    // un error aquí suele ser que el puerto no habla TLS.
    sock.once("error", () => bail());
  });
}

async function pool<T>(items: T[], worker: (t: T) => Promise<void>, max: number): Promise<void> {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(max, items.length) }, async () => {
      while (i < items.length) await worker(items[i++]);
    }),
  );
}

export interface ScanNetOpts {
  ports: number[];
  connectTimeoutMs: number;
  concurrency: number;
}

export async function scanHostPorts(host: string, o: ScanNetOpts): Promise<HostResult> {
  const open: PortResult[] = [];
  await pool(
    o.ports,
    async (port) => {
      const banner = await tcpProbe(host, port, o.connectTimeoutMs);
      if (banner === null) return;
      const pr: PortResult = { port, service: COMMON_PORTS[port] ?? "desconocido", banner: banner.trim().slice(0, 200) || undefined };
      if (TLS_PORTS.has(port)) {
        const t = await inspectTls(host, port, o.connectTimeoutMs * 2);
        if (t && !t.error) pr.tls = t;
      }
      open.push(pr);
    },
    o.concurrency,
  );
  open.sort((a, b) => a.port - b.port);
  return { host, up: open.length > 0, ports: open };
}

const WEAK_TLS_PROTO = new Set(["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]);
const WEAK_CIPHER = /(RC4|DES|3DES|NULL|EXPORT|MD5|anon)/i;

function serviceFromBanner(pr: PortResult): string | undefined {
  const b = pr.banner;
  if (!b) return undefined;
  const server = b.match(/^Server:\s*(.+)$/im)?.[1];
  if (server) return server.trim();
  const ssh = b.match(/^SSH-[\d.]+-(.+)$/im)?.[1];
  if (ssh) return `SSH ${ssh.trim()}`;
  const first = b.split(/\r?\n/)[0].trim();
  return first && first.length < 80 ? first : undefined;
}

export function networkFindings(hr: HostResult): RawFinding[] {
  const out: RawFinding[] = [];
  const emit = (port: number, rule: string, severity: Severity, title: string, description: string, remediation: string, evidence?: string) =>
    out.push({ tool: "xolotl-net", category: "network", severity, ruleId: rule, title, description, remediation, evidence, location: { target: `${hr.host}:${port}` } });

  for (const pr of hr.ports) {
    const exp = EXPOSED[pr.service];
    const ver = serviceFromBanner(pr);
    if (exp) {
      emit(pr.port, `XOL-NET-EXP-${pr.port}`, exp.sev, `${exp.label} accesible por red en ${hr.host}:${pr.port}`,
        `Puerto ${pr.port}/${pr.service} alcanzable: ${exp.note}. Un servicio que solo debería usarse localmente o desde la red de administración está expuesto más allá.`,
        "Restringir con firewall a la red de administración, o hacer que el servicio escuche solo en la interfaz interna. Deshabilitarlo si no se usa.",
        ver ? `banner: ${ver}` : undefined);
    }

    const t = pr.tls;
    if (t) {
      if (t.protocol && WEAK_TLS_PROTO.has(t.protocol)) {
        emit(pr.port, "XOL-TLS-PROTO", "medium", `TLS obsoleto (${t.protocol}) en ${hr.host}:${pr.port}`,
          `El servicio negocia ${t.protocol}, con debilidades conocidas (POODLE, BEAST). Los navegadores y clientes modernos ya lo rechazan.`,
          "Desactivar TLS 1.0/1.1 y SSLv3; permitir solo TLS 1.2 y 1.3.", `protocolo: ${t.protocol}, cifrado: ${t.cipher ?? "?"}`);
      }
      if (t.cipher && WEAK_CIPHER.test(t.cipher)) {
        emit(pr.port, "XOL-TLS-CIPHER", "medium", `Cifrado TLS débil en ${hr.host}:${pr.port}`,
          `El servidor aceptó el cifrado ${t.cipher}, considerado inseguro.`,
          "Configurar una suite de cifrados moderna (sin RC4/3DES/DES/MD5/EXPORT).", `cifrado: ${t.cipher}`);
      }
      if (t.daysLeft !== undefined && t.daysLeft < 0) {
        emit(pr.port, "XOL-TLS-EXPIRED", "high", `Certificado TLS vencido en ${hr.host}:${pr.port}`,
          `El certificado venció hace ${-t.daysLeft} día(s) (${t.notAfter}). Los clientes lo rechazan o los usuarios se acostumbran a ignorar la advertencia.`,
          "Renovar el certificado y automatizar la renovación (ACME/Let's Encrypt o la PKI interna).", `vence: ${t.notAfter}`);
      } else if (t.daysLeft !== undefined && t.daysLeft < 21) {
        emit(pr.port, "XOL-TLS-EXPIRING", "low", `Certificado TLS por vencer en ${hr.host}:${pr.port}`,
          `El certificado vence en ${t.daysLeft} día(s) (${t.notAfter}).`,
          "Renovarlo antes del vencimiento; automatizar la renovación.", `vence: ${t.notAfter}`);
      }
      if (t.selfSigned) {
        emit(pr.port, "XOL-TLS-SELFSIGNED", "low", `Certificado TLS autofirmado en ${hr.host}:${pr.port}`,
          `El certificado lo emite el propio host (CN ${t.subject ?? "?"}): no lo valida ninguna autoridad, así que no protege contra suplantación.`,
          "Usar un certificado de una CA (pública o interna de la institución). Aceptable solo en servicios internos con confianza explícita.", `emisor: ${t.issuer ?? "?"}`);
      }
      if (t.keyBits && t.keyBits < 2048) {
        emit(pr.port, "XOL-TLS-WEAKKEY", "medium", `Clave TLS corta (${t.keyBits} bits) en ${hr.host}:${pr.port}`,
          `La clave del certificado es de ${t.keyBits} bits; por debajo de 2048 bits RSA se considera débil.`,
          "Reemisión con clave RSA de 2048+ bits o ECDSA P-256.", `bits: ${t.keyBits}`);
      }
    }
  }
  return out;
}

/** Resumen de puertos abiertos como un hallazgo informativo, para el inventario. */
export function inventoryFinding(hr: HostResult): RawFinding | null {
  if (!hr.ports.length) return null;
  const lista = hr.ports.map((p) => `${p.port}/${p.service}${p.tls?.protocol ? ` (${p.tls.protocol})` : ""}${serviceFromBanner(p) ? ` — ${serviceFromBanner(p)}` : ""}`);
  return {
    tool: "xolotl-net",
    category: "network",
    severity: "info",
    ruleId: "XOL-NET-INVENTORY",
    title: `${hr.host}: ${hr.ports.length} puerto(s) abierto(s)`,
    description: "Servicios alcanzables por red (inventario de superficie expuesta):\n" + lista.join("\n"),
    location: { target: hr.host },
    evidence: lista.join("\n"),
  };
}
