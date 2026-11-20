---
name: appsec-cloud
description: Evaluar la postura de seguridad de una suscripción de nube con el MCP Xolotl, usando el tool scan_cloud y Prowler en modo de solo lectura. Úsala cuando pidan auditar o endurecer una nube, Azure, una suscripción, IAM, almacenamiento, red, Key Vault, Defender o comparar la nube con CIS. Sin conexión propia: entrega cómo correr Prowler con una identidad de solo lectura y parsea su JSON OCSF. Primer proveedor: Azure. Nivel de acceso: identidad de solo lectura en la nube.
---

# Postura de nube (Prowler)

`scan_cloud` evalúa una suscripción de nube contra CIS y otros marcos con **Prowler**, en solo
lectura. No se conecta ni instala nada: entrega cómo correr Prowler y parsea su salida JSON a
hallazgos, respetando la severidad que Prowler asigna por check.

## Proveedores

- **Azure** — disponible.
- AWS y GCP — Prowler los cubre; entran con el mismo armazón (en la hoja de ruta).
- **Oracle Cloud (OCI)** — Prowler **no** cubre OCI; necesita su propio benchmark CIS (hoja de ruta).

## El flujo (Tier 1)

1. `scan_cloud provider=azure` (sin más) devuelve las instrucciones.
2. Con una identidad de **solo lectura** (roles «Reader» + «Security Reader» en la suscripción):
   ```
   pipx install prowler
   az login            # o --sp-env-auth con AZURE_CLIENT_ID/SECRET/TENANT_ID
   prowler azure --az-cli-auth --output-formats json-ocsf --output-directory ./prowler-out
   ```
3. `scan_cloud provider=azure collected_file=./prowler-out/<archivo>.ocsf.json` lo parsea.

## Cómo se interpretan los resultados

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
