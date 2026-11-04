# Hoja de ruta de Xolotl

> Estado vivo del proyecto. Lo **Hecho** ya está en `main`; lo demás está ordenado por
> cercanía. La estructura del catálogo vive en [`docs/catalogo/`](docs/catalogo/README.md).

## Principio rector

Todo lo que Xolotl haga debe **depender de ti y correr en local**: binarios oficiales
verificados por SHA-256 en una carpeta propia (`~/.xolotl`), base de datos local, y el
cerebro de IA apuntable a un modelo local (`ANTHROPIC_BASE_URL`) si no se quiere la nube.
Ninguna capacidad nueva introduce un servicio externo obligatorio.

---

## Hecho

- **SAST · SCA · Secretos · IaC · Contenedores** sobre código fuente (`scan_static`, `scan_codeql`, `scan_container_image`, `scan_iac`).
- **Servidores Linux** por SSH con llave o recolector de solo lectura (`scan_host`, `host_collector`).
- **Red sin credenciales**: descubrimiento TCP + inspección TLS nativa + ssh-audit (`scan_network`).
- **DAST** por plantillas con alcance autorizado (`scan_dast`, `dast_scope`).
- **Triage con memoria**, comparación de corridas e informes (SARIF/HTML/MD/JSON).

---

## Fase 1 — Memoria y catálogo (en curso)

Lo que destiló la revisión de [`pentest-ai-agents`](https://github.com/0xSteph/pentest-ai-agents):
tomar su estética y su modelo, no su dependencia de la nube.

| Tarea | Estado | Qué agrega | Inspiración |
|---|---|---|---|
| **BD local SQLite** | ✅ | Hallazgos, corridas y enlaces en `~/.xolotl/xolotl.db` con huella estable, columna `tool_used` e índices. Motor `node:sqlite` nativo (Node 22.5+) con respaldo JSON. | Su `findings.sh` + esquema |
| **Inventario / ecosistema** | ✅ | Tool `inventory`: resumen del ecosistema, activos, hallazgos en el tiempo (nuevos/persistentes/desaparecidos) e historia por huella. Crece solo con cada corrida. | Tu petición original |
| **Catálogo de skills por dominio** | 🧭 | Las skills ordenadas por nivel de acceso al objetivo, navegables en markdown. Base en [`docs/catalogo/`](docs/catalogo/README.md). | Su catálogo de agentes `.md` |
| **Niveles de ejecución (Tier 1 / Tier 2)** | 🧭 | *Advisory* (el agente aconseja y tú corres el comando — tu flujo de MobaXterm) vs *Execution* (el agente compone el comando, lo valida contra el alcance y lo muestra para aprobación). | Su modelo de dos niveles |

## Fase 2 — Más superficie de sistema

| Próximo | Motor previsto | Nivel de acceso |
|---|---|---|
| Discos de VM sin encenderlas | `trivy vm` (VMDK, AMI, snapshots EBS) | Credenciales / archivo de disco |
| Benchmarks CIS/STIG formales | OpenSCAP (RHEL), Lynis | Usuario de lectura |
| Nube: plano de control | Prowler con rol de solo lectura | Usuario de lectura |
| Windows Server | Inventario por WinRM + HardeningKitty | Credenciales |
| Monitoreo continuo | API de Wazuh (vulnerabilidades + CIS) | Usuario de lectura |

## Fase 3 — Profundidad ofensiva autorizada

Siempre dentro del alcance registrado y con aprobación por comando.

- DAST más profundo: OWASP ZAP (rastreo autenticado, escaneo activo desde OpenAPI).
- Fuzzing de APIs: Schemathesis / RESTler desde el esquema.
- Reconocimiento autorizado: httpx, katana, subfinder, naabu para alimentar a Nuclei.

---

## No objetivos

- Ningún servicio externo obligatorio ni telemetría.
- Nada de DoS, escaneo masivo, ni evasión de detección para uso malicioso.
- No reemplaza a un pentester ni al monitoreo de producción en tiempo real.
