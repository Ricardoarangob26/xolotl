/*
 * Postura de Kubernetes (Fase 2, vía azul) con kube-bench (CIS Kubernetes Benchmark). Sin conexión
 * ni binario propio: fiel a "depende de ti". En modo advisory entregamos cómo correr kube-bench
 * (como Job en el clúster —sirve para AKS/EKS/GKE gestionados— o como binario en un nodo) con salida
 * JSON; tú lo corres y traes el JSON; Xolotl lo parsea a hallazgos. kube-bench solo lee: no cambia nada.
 */
import type { RawFinding, Severity } from "./findings.js";

export function k8sAdvisory(target?: string): string {
  return [
    `## Tier 1 · advisory — postura de Kubernetes con kube-bench (CIS)${target ? ` · ${target}` : ""}`,
    "kube-bench comprueba el clúster contra el CIS Kubernetes Benchmark. Solo lee; no cambia nada.",
    "",
    "Opción A — clúster gestionado (AKS, EKS, GKE) o sin acceso a los nodos: córrelo como Job.",
    "  kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml",
    "  kubectl wait --for=condition=complete job/kube-bench --timeout=120s",
    "  kubectl logs job/kube-bench > kube-bench.json   # el Job ya corre con --json",
    "  kubectl delete job kube-bench",
    "  (en AKS solo aplican los controles de nodo; el plano de control es gestionado por Azure.)",
    "",
    "Opción B — tienes acceso al nodo (binario):",
    "  kube-bench run --targets node --json --outputfile kube-bench.json",
    "",
    "Si el Job no sale en JSON, fuerza la bandera en su contenedor: command: [\"kube-bench\",\"--json\"].",
    "",
    "Volver: scan_k8s con collected_file=<ruta de kube-bench.json>.",
  ].join("\n");
}

interface KbResult {
  test_number?: string;
  test_desc?: string;
  status?: string;
  remediation?: string;
  scored?: boolean;
}
interface KbTest {
  section?: string;
  desc?: string;
  results?: KbResult[];
}
interface KbControl {
  text?: string;
  node_type?: string;
  tests?: KbTest[];
}

export interface K8sParse {
  findings: RawFinding[];
  totals: { pass: number; fail: number; warn: number; info: number };
  cluster: string;
}

export function parseKubeBench(text: string, cluster = "cluster"): K8sParse {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("El archivo no es un JSON válido de kube-bench. Genéralo con kube-bench --json (o el Job con --json).");
  }
  const controls: KbControl[] = Array.isArray(data) ? (data as KbControl[]) : ((data as { Controls?: KbControl[] }).Controls ?? []);
  if (!controls.length) throw new Error("No se encontraron controles en el JSON. ¿Es la salida de kube-bench --json?");

  const findings: RawFinding[] = [];
  const totals = { pass: 0, fail: 0, warn: 0, info: 0 };
  const seen = new Set<string>();

  for (const c of controls) {
    for (const t of c.tests ?? []) {
      for (const r of t.results ?? []) {
        const status = String(r.status ?? "").toUpperCase();
        if (status === "PASS") {
          totals.pass++;
          continue;
        }
        if (status === "INFO") {
          totals.info++;
          continue;
        }
        const isFail = status === "FAIL";
        if (isFail) totals.fail++;
        else if (status === "WARN") totals.warn++;
        else continue;

        const num = r.test_number || `${t.section ?? "?"}`;
        const rule = `CIS-K8S-${num}`;
        if (seen.has(rule)) continue; // un mismo control puede repetirse entre targets
        seen.add(rule);
        const severity: Severity = isFail ? "medium" : "low";
        findings.push({
          tool: "kube-bench",
          category: "config",
          severity,
          ruleId: rule,
          title: `${num} ${r.test_desc ?? t.desc ?? "control CIS"}`.trim(),
          description: `CIS Kubernetes Benchmark${c.node_type ? ` · ${c.node_type}` : ""}${isFail ? " · FAIL" : " · WARN (requiere revisión manual)"}${r.scored === false ? " · no puntuado" : ""}.`,
          remediation: r.remediation?.replace(/\s+/g, " ").trim() || undefined,
          location: { target: cluster },
        });
      }
    }
  }
  return { findings, totals, cluster };
}
