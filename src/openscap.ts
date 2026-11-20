/*
 * Benchmarks formales CIS/STIG con OpenSCAP (Fase 2, vía azul). OpenSCAP (oscap) evalúa un sistema
 * contra contenido SCAP (SCAP Security Guide: perfiles CIS, DISA STIG, etc.) y escribe un XML de
 * resultados XCCDF. Fiel a "depende de ti": tú corres oscap con una cuenta de lectura y traes el
 * results.xml; Xolotl lo parsea a hallazgos (las reglas que fallan), con su severidad y sus CCI
 * de STIG. oscap en modo eval solo lee: no cambia el sistema (remediation es otro modo, no este).
 */
import { normSeverity, type RawFinding, type Severity } from "./findings.js";

export function openscapAdvisory(target?: string): string {
  return [
    `## Tier 1 · advisory — benchmark formal con OpenSCAP (CIS/STIG)${target ? ` · ${target}` : ""}`,
    "oscap evalúa el sistema contra contenido SCAP (SCAP Security Guide). El modo eval solo lee.",
    "",
    "En el servidor (RHEL/Rocky/Alma/Ubuntu):",
    "  1. Instala OpenSCAP y el contenido:",
    "       RHEL/Rocky:  sudo dnf install -y openscap-scanner scap-security-guide",
    "       Ubuntu:      sudo apt-get install -y libopenscap8 ssg-debian ssg-base",
    "  2. Lista los perfiles disponibles del contenido de tu SO y elige uno (CIS o STIG):",
    "       oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
    "  3. Evalúa y guarda el XML de resultados (ajusta el datastream y el --profile a tu SO):",
    "       sudo oscap xccdf eval --profile <id_del_perfil_stig_o_cis> \\",
    "         --results oscap-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
    "",
    "Volver: scan_openscap con collected_file=<ruta de oscap-results.xml>.",
  ].join("\n");
}

const decode = (s: string) =>
  s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();

const attr = (tag: string, name: string): string | undefined => {
  const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`));
  return m ? m[1] : undefined;
};

const shortId = (idref: string) => idref.replace(/^xccdf_[^_]+(?:\.[^_]+)*_rule_/, "").replace(/^xccdf_.*_rule_/, "");

export interface OscapParse {
  findings: RawFinding[];
  host: string;
  profile?: string;
  totals: { fail: number; pass: number; other: number };
}

export function parseOscapResults(xml: string, host = "sistema"): OscapParse {
  if (!/<(?:\w+:)?(?:Benchmark|TestResult|rule-result)\b/.test(xml))
    throw new Error("El archivo no parece un XML de resultados XCCDF de OpenSCAP. Genéralo con oscap xccdf eval --results.");

  // Definiciones de reglas: título y severidad por id.
  const rules = new Map<string, { title: string; severity?: string }>();
  for (const m of xml.matchAll(/<(?:\w+:)?Rule\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?Rule>/g)) {
    const id = attr(m[1], "id");
    if (!id) continue;
    const severity = attr(m[1], "severity");
    const t = m[2].match(/<(?:\w+:)?title\b[^>]*>([\s\S]*?)<\/(?:\w+:)?title>/);
    rules.set(id, { title: t ? decode(t[1]) : shortId(id), severity });
  }

  const profile = (xml.match(/<(?:\w+:)?TestResult\b[^>]*>[\s\S]*?<(?:\w+:)?profile\b[^>]*idref="([^"]+)"/) ?? [])[1];
  const totals = { fail: 0, pass: 0, other: 0 };
  const findings: RawFinding[] = [];
  const seen = new Set<string>();

  for (const m of xml.matchAll(/<(?:\w+:)?rule-result\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?rule-result>/g)) {
    const idref = attr(m[1], "idref");
    if (!idref) continue;
    const res = (m[2].match(/<(?:\w+:)?result\b[^>]*>([^<]+)<\/(?:\w+:)?result>/) ?? [])[1]?.trim().toLowerCase();
    if (res === "pass") {
      totals.pass++;
      continue;
    }
    if (res !== "fail" && res !== "error") {
      totals.other++;
      continue; // notapplicable / notchecked / notselected / informational
    }
    totals.fail++;
    if (seen.has(idref)) continue;
    seen.add(idref);
    const rule = rules.get(idref);
    const sevRaw = (attr(m[1], "severity") || rule?.severity || "").toLowerCase();
    const severity: Severity = sevRaw === "" || sevRaw === "unknown" ? "medium" : normSeverity(sevRaw);
    const ccis = [...m[2].matchAll(/<(?:\w+:)?ident\b[^>]*>(CCI-\d+)<\/(?:\w+:)?ident>/g)].map((x) => x[1]);
    findings.push({
      tool: "openscap",
      category: "config",
      severity,
      ruleId: `OSCAP-${shortId(idref)}`,
      title: rule?.title || shortId(idref),
      description: `OpenSCAP${profile ? ` · perfil ${profile.replace(/^xccdf_.*_profile_/, "")}` : ""}${ccis.length ? ` · ${ccis.slice(0, 4).join(", ")}` : ""}${res === "error" ? " · error al evaluar" : ""}.`,
      remediation: "Aplica la remediación del benchmark (CIS/STIG); el contenido SSG trae la corrección por regla.",
      cwe: [],
      references: ccis.length ? [`https://www.cyber.mil/stigs/cci/`] : undefined,
      location: { target: host },
    });
  }
  return { findings, host, profile, totals };
}
