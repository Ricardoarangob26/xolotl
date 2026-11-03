/* Traducen la salida nativa de cada herramienta al formato común RawFinding. */
import { Category, cweList, normSeverity, RawFinding, relPath, sevFromScore, Severity, strList } from "./findings.js";

const firstSentence = (s: string, max = 140) => {
  const line = (s ?? "").split(/\r?\n/)[0].trim();
  const cut = line.match(/^(.{20,}?[.!?])\s/);
  const t = cut ? cut[1] : line;
  return t.length > max ? t.slice(0, max) + "…" : t;
};

// ───────────── Semgrep (JSON) ─────────────
export function parseSemgrep(data: any, root: string): RawFinding[] {
  return (data?.results ?? []).map((r: any): RawFinding => {
    const meta = r.extra?.metadata ?? {};
    const sev = String(r.extra?.severity ?? "").toUpperCase();
    // Semgrep usa ERROR/WARNING/INFO; las reglas Pro traen impact/likelihood más finos.
    let severity: Severity = sev === "ERROR" ? "high" : sev === "WARNING" ? "medium" : sev === "INFO" ? "low" : normSeverity(sev);
    if (sev === "ERROR" && String(meta.impact).toUpperCase() === "HIGH" && String(meta.likelihood).toUpperCase() === "HIGH") severity = "critical";
    const rule = String(r.check_id ?? "semgrep");
    return {
      tool: "semgrep",
      category: "sast",
      severity,
      ruleId: rule,
      title: `${rule.split(".").pop()}: ${firstSentence(r.extra?.message ?? "")}`,
      description: r.extra?.message,
      location: { file: relPath(root, r.path), startLine: r.start?.line, endLine: r.end?.line },
      cwe: cweList(meta.cwe),
      references: strList(meta.references).slice(0, 5),
      confidence: meta.confidence ? String(meta.confidence).toLowerCase() : undefined,
      remediation: r.extra?.fix ? `Arreglo sugerido por la regla: ${r.extra.fix}` : undefined,
    };
  });
}

// ───────────── Bandit (JSON) ─────────────
export function parseBandit(data: any, root: string): RawFinding[] {
  return (data?.results ?? []).map(
    (r: any): RawFinding => ({
      tool: "bandit",
      category: "sast",
      severity: normSeverity(r.issue_severity),
      ruleId: `${r.test_id}:${r.test_name}`,
      title: `${r.test_name}: ${firstSentence(r.issue_text)}`,
      description: r.issue_text,
      location: {
        file: relPath(root, r.filename),
        startLine: r.line_number,
        endLine: Array.isArray(r.line_range) ? r.line_range[r.line_range.length - 1] : undefined,
      },
      cwe: r.issue_cwe?.id ? [`CWE-${r.issue_cwe.id}`] : [],
      references: strList(r.more_info),
      confidence: String(r.issue_confidence ?? "").toLowerCase() || undefined,
    }),
  );
}

// ───────────── SARIF 2.1.0 (CodeQL y cualquier otra) ─────────────
export function parseSarif(data: any, root: string, tool: string): RawFinding[] {
  const out: RawFinding[] = [];
  for (const runObj of data?.runs ?? []) {
    const driver = runObj.tool?.driver ?? {};
    const rules: any[] = [...(driver.rules ?? []), ...(runObj.tool?.extensions ?? []).flatMap((e: any) => e.rules ?? [])];
    const byId = new Map(rules.map((r) => [r.id, r]));
    for (const res of runObj.results ?? []) {
      const rule = byId.get(res.ruleId) ?? (res.rule?.index != null ? rules[res.rule.index] : undefined) ?? {};
      const props = rule.properties ?? {};
      const secSev = parseFloat(props["security-severity"]);
      const severity = !isNaN(secSev) ? sevFromScore(secSev) : normSeverity(res.level ?? rule.defaultConfiguration?.level);
      const loc = res.locations?.[0]?.physicalLocation ?? {};
      out.push({
        tool,
        category: "sast",
        severity,
        ruleId: res.ruleId ?? rule.id ?? tool,
        title: rule.shortDescription?.text ?? rule.name ?? res.ruleId,
        description: res.message?.text,
        location: {
          file: relPath(root, loc.artifactLocation?.uri ? decodeURIComponent(loc.artifactLocation.uri) : undefined),
          startLine: loc.region?.startLine,
          endLine: loc.region?.endLine,
        },
        cwe: cweList(props.tags ?? []),
        references: strList(rule.helpUri),
        confidence: props.precision,
        remediation: rule.help?.text ? rule.help.text.slice(0, 1500) : undefined,
      });
    }
  }
  return out;
}

// ───────────── OSV-Scanner (JSON) ─────────────
function osvSeverity(vulns: any[], group: any): Severity {
  const score = parseFloat(group?.max_severity);
  if (!isNaN(score) && score > 0) return sevFromScore(score);
  for (const v of vulns) {
    const ds = v.database_specific?.severity;
    if (ds) return normSeverity(ds);
  }
  return "medium";
}

const verParts = (v: string) => v.replace(/^v/, "").split(/[.+-]/).map((p) => (/^\d+$/.test(p) ? Number(p) : -1));
function cmpVer(a: string, b: string): number {
  const x = verParts(a);
  const y = verParts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

/** Versión corregida más cercana: la menor mayor que la instalada, preferentemente en la misma rama major.minor. */
export function osvFixed(vulns: any[], pkgName: string, installed?: string): string | undefined {
  const fixed = new Set<string>();
  for (const v of vulns)
    for (const a of v.affected ?? [])
      if (!a.package?.name || a.package.name.toLowerCase() === pkgName.toLowerCase())
        for (const r of a.ranges ?? [])
          if (r.type !== "GIT") for (const e of r.events ?? []) if (e.fixed) fixed.add(String(e.fixed));
  const all = [...fixed].sort(cmpVer);
  if (!all.length) return undefined;
  if (!installed) return all[all.length - 1];
  const newer = all.filter((f) => cmpVer(f, installed) > 0);
  const [maj, min] = verParts(installed);
  const sameLine = newer.find((f) => {
    const [a, b] = verParts(f);
    return a === maj && b === min;
  });
  return sameLine ?? newer[0] ?? all[all.length - 1];
}

export function parseOsv(data: any, root: string): RawFinding[] {
  const out: RawFinding[] = [];
  for (const res of data?.results ?? []) {
    const file = relPath(root, res.source?.path);
    for (const p of res.packages ?? []) {
      const pkg = p.package ?? {};
      const vulns: any[] = p.vulnerabilities ?? [];
      const groups: any[] = p.groups?.length ? p.groups : vulns.map((v) => ({ ids: [v.id] }));
      for (const g of groups) {
        const members = vulns.filter((v) => g.ids?.includes(v.id));
        if (!members.length) continue;
        const main = members.find((v) => v.summary) ?? members[0];
        const ids = [...new Set([...(g.ids ?? []), ...(g.aliases ?? []), ...members.flatMap((v) => v.aliases ?? [])])];
        out.push({
          tool: "osv-scanner",
          category: "sca",
          severity: osvSeverity(members, g),
          ruleId: main.id,
          title: `${main.id}: ${main.summary ?? firstSentence(main.details ?? "vulnerabilidad conocida")}`,
          description: main.details?.slice(0, 2000),
          location: { file },
          ids,
          cve: ids.filter((i) => i.startsWith("CVE-")),
          cwe: cweList(members.flatMap((v) => v.database_specific?.cwe_ids ?? [])),
          package: { name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, fixedVersion: osvFixed(members, pkg.name, pkg.version) },
          references: [`https://osv.dev/vulnerability/${main.id}`],
        });
      }
    }
  }
  return out;
}

// ───────────── Trivy (JSON) ─────────────
export function parseTrivy(data: any, root: string | null, mode: "fs" | "image" | "config"): RawFinding[] {
  const out: RawFinding[] = [];
  const artifact = data?.ArtifactName;
  for (const res of data?.Results ?? []) {
    const file = mode === "image" ? undefined : relPath(root, res.Target);
    const target = mode === "image" ? `${artifact} · ${res.Target}` : undefined;
    for (const v of res.Vulnerabilities ?? []) {
      const category: Category = mode === "image" ? "container" : "sca";
      const ids = [v.VulnerabilityID, ...(v.VendorIDs ?? [])].filter(Boolean);
      out.push({
        tool: "trivy",
        category,
        severity: normSeverity(v.Severity),
        ruleId: v.VulnerabilityID,
        title: `${v.VulnerabilityID}: ${v.Title ?? firstSentence(v.Description ?? "")}`,
        description: v.Description?.slice(0, 2000),
        location: { file, target },
        ids,
        cve: ids.filter((i: string) => i.startsWith("CVE-")),
        cwe: cweList(v.CweIDs),
        package: { name: v.PkgName, version: v.InstalledVersion, ecosystem: res.Type, fixedVersion: v.FixedVersion || undefined },
        references: strList(v.PrimaryURL),
      });
    }
    for (const m of res.Misconfigurations ?? []) {
      if (m.Status && m.Status !== "FAIL") continue;
      out.push({
        tool: "trivy",
        category: "iac",
        severity: normSeverity(m.Severity),
        ruleId: m.AVDID ?? m.ID,
        title: `${m.ID}: ${m.Title}`,
        description: [m.Description, m.Message].filter(Boolean).join("\n\n"),
        location: { file, target, startLine: m.CauseMetadata?.StartLine || undefined, endLine: m.CauseMetadata?.EndLine || undefined },
        references: strList(m.PrimaryURL ?? m.References?.[0]),
        remediation: m.Resolution,
      });
    }
    for (const s of res.Secrets ?? []) {
      out.push({
        tool: "trivy",
        category: "secret",
        severity: normSeverity(s.Severity),
        ruleId: s.RuleID,
        title: `Secreto expuesto: ${s.Title}`,
        description: `Categoría ${s.Category}. Coincidencia (enmascarada por Trivy): ${s.Match}`,
        location: { file, target, startLine: s.StartLine, endLine: s.EndLine },
        remediation: "Revocar y rotar la credencial; luego sacarla del código y del historial.",
      });
    }
  }
  return out;
}

// ───────────── Gitleaks (JSON, con --redact) ─────────────
export function parseGitleaks(data: any, root: string): RawFinding[] {
  return (Array.isArray(data) ? data : []).map(
    (r: any): RawFinding => ({
      tool: "gitleaks",
      category: "secret",
      severity: "high",
      ruleId: r.RuleID,
      title: `Secreto expuesto: ${r.Description ?? r.RuleID}`,
      description: [
        r.Commit ? `En el historial: commit ${String(r.Commit).slice(0, 12)} (${r.Date ?? "fecha ?"}).` : "En el árbol de trabajo actual.",
        `Coincidencia (redactada): ${String(r.Match ?? "").slice(0, 160)}`,
        r.Entropy ? `Entropía: ${Number(r.Entropy).toFixed(2)}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
      location: { file: relPath(root, r.File), startLine: r.StartLine, endLine: r.EndLine, commit: r.Commit || undefined },
      remediation: r.Commit
        ? "Revocar y rotar la credencial ya: borrarla del código no la saca del historial ni de los clones existentes."
        : "Revocar y rotar la credencial; moverla a un gestor de secretos o variable de entorno.",
    }),
  );
}

// ───────────── Nuclei (JSONL) ─────────────
const REDACT_HEADER = /(-H\s+['"]?(?:authorization|cookie|x-api-key|x-auth-token)\s*:\s*)([^'"]+)/gi;

export function parseNuclei(jsonl: string, secrets: string[] = []): RawFinding[] {
  const out: RawFinding[] = [];
  for (const line of jsonl.split(/\r?\n/)) {
    if (!line.trim().startsWith("{")) continue;
    let r: any;
    try {
      r = JSON.parse(line);
    } catch {
      continue;
    }
    const info = r.info ?? {};
    const cls = info.classification ?? {};
    let curl: string = r["curl-command"] ?? "";
    curl = curl.replace(REDACT_HEADER, "$1[REDACTADO]");
    for (const s of secrets) if (s.length >= 6) curl = curl.split(s).join("[REDACTADO]");
    const extracted = strList(r["extracted-results"]).slice(0, 10);
    const cvss = parseFloat(cls["cvss-score"]);
    out.push({
      tool: "nuclei",
      category: "dast",
      severity: info.severity === "unknown" && !isNaN(cvss) ? sevFromScore(cvss) : normSeverity(info.severity),
      // Una plantilla con varios matchers (p. ej. cada cabecera faltante) son hallazgos distintos.
      ruleId: r["matcher-name"] ? `${r["template-id"]}:${r["matcher-name"]}` : r["template-id"],
      title: `${info.name ?? r["template-id"]}${r["matcher-name"] ? ` [${r["matcher-name"]}]` : ""}`,
      description: info.description,
      location: { url: r["matched-at"] ?? r.host, target: r.host },
      cve: strList(cls["cve-id"]).map((c) => c.toUpperCase()),
      cwe: cweList(cls["cwe-id"]),
      references: strList(info.reference).slice(0, 5),
      evidence: [extracted.length ? `Extraído: ${extracted.join(", ")}` : "", curl ? `Reproducir: ${curl}` : ""].filter(Boolean).join("\n") || undefined,
      remediation: info.remediation,
    });
  }
  return out;
}
