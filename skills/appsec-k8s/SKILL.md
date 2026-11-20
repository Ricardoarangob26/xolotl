---
name: appsec-k8s
description: Evaluar la postura de seguridad de un clúster de Kubernetes con el MCP Xolotl, usando el tool scan_k8s y kube-bench (CIS Kubernetes Benchmark) en modo de solo lectura. Úsala cuando pidan auditar o endurecer un clúster de Kubernetes, AKS, EKS o GKE, revisar la configuración del kubelet, API server, RBAC o políticas de admisión, o comparar el clúster con el benchmark CIS. Sin conexión propia: entrega cómo correr kube-bench y parsea su JSON. Nivel de acceso: acceso de lectura al clúster (kubectl) o a un nodo.
---

# Postura de Kubernetes

`scan_k8s` evalúa un clúster contra el **CIS Kubernetes Benchmark** con **kube-bench**, en solo
lectura. No se conecta ni instala nada: entrega cómo correr kube-bench y parsea su salida JSON a
hallazgos.

## El flujo (Tier 1)

1. `scan_k8s` (sin más) devuelve las instrucciones.
2. Corre kube-bench y guarda el JSON:
   - **Clúster gestionado (AKS, EKS, GKE) o sin acceso a nodos** → como Job:
     ```
     kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
     kubectl wait --for=condition=complete job/kube-bench --timeout=120s
     kubectl logs job/kube-bench > kube-bench.json
     kubectl delete job kube-bench
     ```
   - **Con acceso al nodo** → binario: `kube-bench run --targets node --json --outputfile kube-bench.json`.
3. `scan_k8s collected_file=kube-bench.json target=<clúster>` lo parsea.

## Cómo se interpretan los resultados

- **FAIL** → hallazgo **medium**: el control CIS no se cumple.
- **WARN** → hallazgo **low**: requiere **revisión manual** (kube-bench no puede decidirlo solo).
- **PASS / INFO** → no generan hallazgo.

Cada hallazgo trae el número del control (p. ej. `4.2.1`), su descripción y la remediación de CIS.

## AKS / EKS / GKE (plano de control gestionado)

En un clúster gestionado, el **plano de control** (API server, etcd, scheduler) lo opera el
proveedor y kube-bench no lo ve: solo aplican los controles de **nodo** (kubelet, configuración del
worker) y de **políticas** (RBAC, admisión). Es lo esperable; audita lo que de verdad controlas.
La postura del plano de control gestionado se cubre desde la nube (Prowler, en la hoja de ruta).

## Relación con el resto

- Los hallazgos son de categoría **config**: heredan cumplimiento (CIS/NIST), riesgo, inventario,
  revalidación e informes.
- Complementa a `scan_iac` (manifiestos y Dockerfiles antes de desplegar) y `scan_container_image`
  (CVE de la imagen): juntos cubren el artefacto, el manifiesto y el clúster en ejecución.

## Límites

- Mide el benchmark CIS; no inspecciona cada workload ni cada RBAC binding uno por uno (eso es un
  análisis más profundo, p. ej. Kubescape, previsto más adelante).
- Necesita que tú corras kube-bench (Job o binario) y traigas el JSON; Xolotl no se conecta al clúster.
