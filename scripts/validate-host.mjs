// Valida scan_host contra la verdad de Trivy: toma una imagen real, convierte su lista de paquetes
// en la salida que daría el recolector en ese sistema (con fallas de configuración sembradas),
// la pasa por scan_host y compara paquete+CVE+versión corregida con `trivy image` sobre la misma imagen.
//   node scripts/validate-host.mjs                     (debian:12 y rockylinux:9)
//   node scripts/validate-host.mjs ubuntu:24.04=ubuntu:24.04
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const home = process.env.XOLOTL_HOME ?? path.join(os.homedir(), ".xolotl");
const trivy = [path.join(home, "tools", "trivy", process.platform === "win32" ? "trivy.exe" : "trivy"), "trivy"].find((p) => p === "trivy" || fs.existsSync(p));
const work = fs.mkdtempSync(path.join(os.tmpdir(), "xolotl-validate-"));

// imagen=id:version_os  (id de os-release)
const cases = process.argv.slice(2).length ? process.argv.slice(2) : ["debian:12=debian:12", "rockylinux:9=rocky:9"];

const prop = (c, n) => c.properties?.find((p) => p.name === `aquasecurity:trivy:${n}`)?.value;

function collectorText(sbom, id, versionId, debVersion) {
  const L = [];
  const sec = (n) => L.push("", `===XOLOTL ${n}===`);
  sec("meta");
  L.push("version=1", `hostname=validacion-${id}`, "uid=0", "kernel=5.14.0-362.8.1.el9_3.x86_64");
  sec("os_release");
  L.push(`ID=${id}`, `VERSION_ID="${versionId}"`, `PRETTY_NAME="${id} ${versionId}"`);
  if (debVersion) {
    sec("debian_version");
    L.push(debVersion);
  }
  const pkgs = sbom.components.filter((c) => c.type === "library" && c.purl);
  const deb = id === "debian" || id === "ubuntu";
  sec(deb ? "pkgs_deb" : "pkgs_rpm");
  for (const c of pkgs) {
    const u = new URL(c.purl.replace(/^pkg:/, "pkg://"));
    const ver = decodeURIComponent(u.pathname.split("@")[1]);
    const epoch = u.searchParams.get("epoch");
    if (deb) {
      const [se, sv, sr] = [prop(c, "SrcEpoch"), prop(c, "SrcVersion"), prop(c, "SrcRelease")];
      L.push(["ii ", c.name, `${epoch ? epoch + ":" : ""}${ver}`, u.searchParams.get("arch"), prop(c, "SrcName") ?? c.name, `${se ? se + ":" : ""}${sv}${sr ? "-" + sr : ""}`].join("\t"));
    } else {
      const i = ver.lastIndexOf("-");
      const src = prop(c, "SrcName") ? `${prop(c, "SrcName")}-${prop(c, "SrcVersion")}-${prop(c, "SrcRelease")}.src.rpm` : "(none)";
      L.push([c.name, epoch ?? "0", ver.slice(0, i), ver.slice(i + 1), u.searchParams.get("arch"), src].join("\t"));
    }
  }
  // Fallas sembradas: cada línea debe producir un hallazgo de endurecimiento.
  sec("kernels_installed"), L.push("kernel-core-5.14.0-362.8.1.el9_3.x86_64", "kernel-core-5.14.0-427.13.1.el9_4.x86_64");
  sec("listening"), L.push("tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:*", "tcp LISTEN 0 80 127.0.0.1:3306 0.0.0.0:*");
  sec("sshd_effective"), L.push("permitrootlogin yes", "passwordauthentication yes", "maxauthtries 6", "ciphers aes128-cbc");
  sec("passwd"), L.push("root:0:0:/root:/bin/bash", "toor:0:0:/root:/bin/bash");
  sec("sudoers_nopasswd"), L.push("ops ALL=(ALL) NOPASSWD: ALL");
  sec("group_privileged"), L.push("docker:x:990:ops");
  sec("selinux"), L.push("Disabled");
  sec("firewall"), L.push("firewalld=inactive", "nft_rules=0", "iptables_rules=0");
  sec("sysctl"), L.push("kernel.randomize_va_space=1");
  sec("services_active"), L.push("auditd=active/enabled", "cups=active/enabled");
  sec("time_sync"), L.push("yes");
  sec("suid"), L.push("/usr/bin/sudo", "/opt/x/bin/ayudante");
  return L.join("\n") + "\n";
}

const EXPECTED_RULES = ["XOL-ACC-001", "XOL-NET-002", "XOL-SSH-001", "XOL-SSH-002", "XOL-SSH-005", "XOL-SSH-006", "XOL-ACC-003", "XOL-ACC-004", "XOL-MAC-001", "XOL-NET-001", "XOL-KRN-001", "XOL-FS-003", "XOL-PAT-001", "XOL-PAT-002", "XOL-SVC-001"];

const client = new Client({ name: "validate-host", version: "0" });
await client.connect(new StdioClientTransport({ command: process.execPath, args: [path.join(here, "..", "dist", "index.js")] }));
const call = async (name, args) => (await client.callTool({ name, arguments: args }, undefined, { timeout: 30 * 60_000 })).content[0].text;

let ok = true;
for (const c of cases) {
  const [image, osSpec] = c.split("=");
  const [id, versionId] = osSpec.split(":");
  const sbomFile = path.join(work, "img.cdx.json");
  const truthFile = path.join(work, "truth.json");
  execFileSync(trivy, ["image", "--quiet", "--format", "cyclonedx", "--output", sbomFile, image]);
  execFileSync(trivy, ["image", "--quiet", "--scanners", "vuln", "--format", "json", "--output", truthFile, image]);
  const sbom = JSON.parse(fs.readFileSync(sbomFile, "utf8"));
  const osComp = sbom.components.find((x) => x.type === "operating-system");
  const collected = path.join(work, `${id}.txt`);
  fs.writeFileSync(collected, collectorText(sbom, id, versionId, id === "debian" ? osComp?.version : null));

  const out = await call("scan_host", { collected_file: collected });
  const runId = out.match(/Corrida: (\S+)/)?.[1];
  const pairs = (f) => new Set(JSON.parse(fs.readFileSync(f, "utf8")).Results?.flatMap((r) => (r.Vulnerabilities ?? []).map((v) => `${v.PkgName}|${v.VulnerabilityID}|${v.FixedVersion ?? ""}`)) ?? []);
  const mine = pairs(path.join(home, "runs", runId, "trivy-host.json"));
  const truth = pairs(truthFile);
  const missing = [...truth].filter((x) => !mine.has(x));
  const extra = [...mine].filter((x) => !truth.has(x));
  const findings = JSON.parse(fs.readFileSync(path.join(home, "runs", runId, "findings.json"), "utf8"));
  const rules = new Set(findings.filter((f) => f.category === "config").map((f) => f.ruleId));
  const missedRules = EXPECTED_RULES.filter((r) => !rules.has(r));
  const pass = !missing.length && !extra.length && !missedRules.length;
  ok &&= pass;
  console.log(`${pass ? "✓" : "✗"} ${image}: ${mine.size}/${truth.size} paquete+CVE iguales a trivy image` + (missing.length ? ` · faltan ${missing.length} (${missing.slice(0, 3).join(", ")})` : "") + (extra.length ? ` · sobran ${extra.length}` : "") + ` · endurecimiento ${EXPECTED_RULES.length - missedRules.length}/${EXPECTED_RULES.length}` + (missedRules.length ? ` (faltan ${missedRules.join(", ")})` : ""));
}
await client.close();
fs.rmSync(work, { recursive: true, force: true });
process.exit(ok ? 0 : 1);
