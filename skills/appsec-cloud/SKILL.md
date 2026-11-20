---
name: appsec-cloud
description: Evaluar la postura de seguridad de una suscripción de nube con el MCP Xolotl, usando el tool scan_cloud y Prowler en modo de solo lectura. Úsala cuando pidan auditar o endurecer una nube, Azure, una suscripción, IAM, almacenamiento, red, Key Vault, Defender o comparar la nube con CIS. Sin conexión propia: entrega cómo correr Prowler con una identidad de solo lectura y parsea su JSON OCSF. Primer proveedor: Azure. Nivel de acceso: identidad de solo lectura en la nube.
---

# Postura de nube (Prowler)

`scan_cloud` evalúa una suscripción de nube contra CIS y otros marcos con **Prowler**, en solo
lectura. No se conecta ni instala nada: entrega cómo correr Prowler y parsea su salida JSON a
hallazgos, respetando la severidad que Prowler asigna por check.

## Proveedores

- **Azure** — disponible, vía **Prowler** (JSON OCSF).
- **Oracle Cloud (OCI)** — disponible, vía el **script CIS oficial de Oracle** (`cis_reports.py`,
  CSV), porque Prowler no cubre OCI.
- AWS y GCP — Prowler los cubre; entran con el mismo armazón (en la hoja de ruta).

## El flujo (Tier 1)

1. `scan_cloud provider=azure` (sin más) devuelve las instrucciones.
2. Con una identidad de **solo lectura** (roles «Reader» + «Security Reader» en la suscripción):
   ```
   pipx install prowler
   az login            # o --sp-env-auth con AZURE_CLIENT_ID/SECRET/TENANT_ID
   prowler azure --az-cli-auth --output-formats json-ocsf --output-directory ./prowler-out
   ```
3. `scan_cloud provider=azure collected_file=./prowler-out/<archivo>.ocsf.json` lo parsea.

### Oracle Cloud (OCI)

1. `scan_cloud provider=oci` devuelve las instrucciones.
2. Con un usuario de **solo lectura** (grupo `Auditors` + política *read all-resources*):
   ```
   git clone https://github.com/oracle-quickstart/oci-cis-landingzone-quickstart
   cd oci-cis-landingzone-quickstart/scripts/cis-reports
   python3 cis_reports.py --report-directory ./oci-cis-out
   ```
3. `scan_cloud provider=oci collected_file=./oci-cis-out/<fecha>/cis_summary_report.csv target=<tenancy>`.
   Cada recomendación no conforme es un hallazgo; Nivel 1 → medium, Nivel 2 → low.

## Cómo se interpretan los resultados (Azure / Prowler)

- **FAIL** → hallazgo con la **severidad que asigna Prowler** (critical/high/medium/low).
- **MANUAL** → hallazgo **info**: Prowler no puede decidirlo solo; requiere revisión.
- **PASS** → no genera hallazgo.

Los hallazgos se **agrupan por control** (un check que falla en varios recursos es un hallazgo con
los recursos listados en la evidencia), y el activo es la **suscripción** (sale del propio JSON).

## Relación con el resto

- Los hallazgos son de categoría **config**: heredan cumplimiento (CIS/NIST/ISO), riesgo,
  inventario, revalidación e informes.
- Complementa a `scan_k8s` (el clúster), `scan_iac` (los manifiestos/Terraform antes de desplegar)
  y `scan_host` (las VMs): juntos cubren el plano de control de la nube, la infraestructura como
  código y las cargas.

## Límites

- Audita la configuración de la nube vía Prowler; no inspecciona cada recurso fuera de los checks
  de Prowler.
- Necesita que tú corras Prowler con una identidad de solo lectura y traigas el JSON; Xolotl no se
  conecta a la nube ni guarda credenciales.
