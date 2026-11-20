# Hoja de ruta de Xolotl

> Estado vivo del proyecto. Lo **Hecho** ya está en `main`; lo demás está ordenado por
> cercanía dentro de cada vía. La estructura del catálogo vive en [`docs/catalogo/`](docs/catalogo/README.md).

## Principios rectores

**1. Local y tuyo.** Todo lo que Xolotl haga debe **depender de ti y correr en local**: binarios
oficiales verificados por SHA-256 en una carpeta propia (`~/.xolotl`), base de datos local, y el
cerebro de IA apuntable a un modelo local (`ANTHROPIC_BASE_URL`) si no se quiere la nube. Ninguna
capacidad nueva introduce un servicio externo obligatorio ni telemetría.

**2. Dos vías, un núcleo.** El proyecto se organiza en dos vías sobre el mismo motor, para cubrir
blue, red y purple team completos:

- 🔵 **Vía Azul (defensa)** — evaluar, priorizar, documentar, endurecer y detectar. Es el grueso
  de lo construido y de lo que falta. No necesita permiso ofensivo.
- 🔴 **Vía Roja (validación ofensiva)** — probar que el endurecimiento aguanta, **solo sobre
  infraestructura propia**, autorizada y acotada. Es el cierre del ciclo, no el comienzo.
- 🟣 **Púrpura (el bucle)** — une las dos: hallazgo azul → validación roja → ingeniería de
  detección → re-endurecer.
- 🧩 **Núcleo compartido** — inventario, riesgo, alcance, Tier 1/2, confirmadores, informes y
  traspaso. Lo usan las dos vías.

**3. El motor decide, el modelo asesora.** La capa de IA planifica y redacta, pero **nunca**
decide un veredicto, el alcance ni ejecuta por su cuenta. Los motores deterministas confirman;
el usuario aprueba.

### El candado de la vía roja (regla dura, sin excepción)

Para que lo ofensivo esté **disponible sin riesgo**, toda capacidad de la Vía Roja exige:

1. **Solo activos propios** dentro del alcance registrado en `dast_scope`, con **referencia de
   autorización**; el objetivo se valida contra el alcance antes de cada acción.
2. **Vía explícita**: la capacidad ofensiva no se activa por accidente — requiere marcarla a
   propósito (`XOLOTL_TRACK=red` o `track:"red"` por tool).
3. **Tier 1 (advisory) por defecto**: el servidor entrega el comando exacto y tú lo corres; Tier 2
   (ejecución) pide aprobación por comando y **registra quién aprobó** (humano/regla/modelo).
4. **Nada destructivo**, nada en producción fuera de ventana acordada, credenciales y artefactos
   de prueba sintéticos, nunca datos reales de clientes.
5. **Nada contra terceros** (ver *No objetivos*).

---

## 🧩 Núcleo — Hecho

- **SAST · SCA · Secretos · IaC · Contenedores** sobre código fuente (`scan_static`, `scan_codeql`, `scan_container_image`, `scan_iac`).
- **Servidores Linux** por SSH con llave o recolector de solo lectura (`scan_host`, `host_collector`).
- **Red sin credenciales**: descubrimiento TCP + inspección TLS nativa + ssh-audit (`scan_network`).
- **DAST** por plantillas con alcance autorizado (`scan_dast`, `dast_scope`).
- **BD local SQLite** con huella estable; **inventario** que crece solo (`inventory`); **Tier 1/Tier 2**.
- **Triage con memoria**, comparación de corridas (`runs_diff`) e informes (SARIF/HTML/MD/JSON).
- **Puntuación de riesgo** (CVSS × EPSS/KEV × criticidad), **resumen ejecutivo**, **traspaso** (`handoff`).
- **Siguiente paso sugerido** (`inventory view=next`), **plan de evaluación** (`eval_plan`), **revalidación no destructiva** (`revalidate`).

El catálogo de skills por dominio y nivel de acceso vive en [`docs/catalogo/`](docs/catalogo/README.md).

---

## 🧩 Inteligencia transversal (Fase 1.5) ✅ completada — sirve a las dos vías

Lo más barato y lo que más valor agrega: todo lo que ya se escanea gana contexto. No toca sistemas.

| Tarea | Estado | Qué agrega |
|---|---|---|
| **Puntuación de riesgo** | ✅ | Base **CVSS** real (NVD/proveedor/GHSA vía OSV, Trivy y Nuclei) × **explotabilidad** (**EPSS** + **CISA KEV**, feeds locales vía `risk_feeds`, funciona sin red) × **criticidad del activo** (`asset_criticality`). Visible en `findings_query`, en el informe, en «Prioridad por riesgo» y en el inventario; el SARIF usa el CVSS real como `security-severity`. |
| **Resumen ejecutivo** | ✅ | Sección de negocio en el informe (MD/HTML): postura, explotabilidad real (KEV, EPSS ≥ 10%), activos de criticidad de negocio, tendencia vs. la corrida anterior, avance de remediación y "lo más urgente", con tira de KPIs. |
| **Traspaso de compromiso** | ✅ | `handoff` (export/import): alcance, triage, criticidad, inventario y artefactos de corrida, para retomar en otra sesión o máquina. |
| **Siguiente paso sugerido** | ✅ | `inventory view=next`: por activo infiere su tipo, muestra la matriz de cobertura y propone los huecos, ordenado por criticidad. |
| **Plan de evaluación por activo** | ✅ | `eval_plan` + skill `appsec-plan`: encadena los huecos en fases (superficie → código → configuración → aplicación) con Tier y acceso; `access=[...]` separa lo ejecutable ahora. |
| **Revalidación no destructiva** | ✅ | `revalidate`: recomprueba un hallazgo local y determinista, **veredicto de 3 estados** (CONFIRMADO/RESUELTO/NO CONCLUYENTE). "No pude comprobarlo" nunca es "ya no existe". Principio «el motor decide, no el modelo». |
| **Mapeo a marcos** | ✅ | Hallazgo → control en 5 marcos (`src/compliance.ts`), determinista y local: clasifica por tema (regla/CWE/categoría) y traduce a **OWASP 2021, PCI DSS 4.0, NIST 800-53, ISO 27001:2022 y CIS v8**. En el informe: línea por hallazgo + **«Brechas de cumplimiento»** (controles con hallazgos abiertos, por marco); etiquetas `external/owasp/*` en el SARIF. Mapeo orientativo, no una auditoría formal. |
| **Mapeo a MITRE ATT&CK** | ✅ | Técnica(s) ATT&CK por hallazgo (`src/attack.ts`), deterministas y locales: de la regla (XOL-* de host/red), del CWE o de la categoría. En el informe (línea por hallazgo + **mapa de cobertura por táctica**, de acceso inicial a recolección), y como etiquetas `external/attack/Txxxx` en el SARIF. Lenguaje común para detección (azul) y para planear la validación (roja/púrpura). |
| **Plan de compromiso** | ✅ | Tool `engagement` + skill `appsec-engagement`: registra el marco de la vía roja (autorización, referencia, vigencia, ventanas, exclusiones, Tier por defecto) sobre `dast_scope`; `status` evalúa si la autorización está vigente; `export` escribe el documento de reglas de enfrentamiento en Markdown (plantilla firmable) con las reglas duras del candado siempre incluidas. Viaja en el `handoff`. Materializa el candado de la vía roja. |
| **Frontera de salida no confiable** | ✅ | `src/untrusted.ts`: el contenido derivado del objetivo/artefacto (código fuente, evidencia, banners, títulos) se envuelve entre marcas con un **nonce único por proceso**, con una nota que indica al modelo tratarlo como **datos, no instrucciones**. El contenido se neutraliza para que no pueda falsificar la marca de cierre. Aplicado en `finding_get`, `findings_query`, `inventory`, `revalidate` y el resumen de cada escaneo. Endurecimiento anti-inyección de prompt. *(Idea rescatada de ARTEX, reimplementada.)* |
| **Migraciones de esquema** | ✅ | Versión del esquema en la BD (`PRAGMA user_version` en SQLite, campo en el JSON de respaldo) y migraciones idempotentes: una BD nueva pasa por todas, una antigua solo por las que le faltan, sin perder datos. v2 añade `risk_score` por hallazgo (prioridad recordada entre corridas, ordena el inventario). Visible en `inventory view=summary` («esquema v2»). |
| **Modelo por skill** | ✅ | Pista `model:` en el encabezado de cada skill: `ligero` (`haiku`, o local vía `ANTHROPIC_BASE_URL`) para las que solo leen/ordenan/rellenan plantillas (`appsec-inventory`, `appsec-plan`, `appsec-engagement`); `capaz` (predeterminado) para las que razonan sobre código (`appsec-audit`, `appsec-triage`, `appsec-fix`…). El trabajo pesado lo hacen los motores, no el modelo. Convención documentada en el catálogo. |

---

## 🔵 Vía Azul — defensa

Evaluar, priorizar, documentar, endurecer y detectar. Siempre de solo lectura o sobre artefactos
que tú entregas; lo que toca un sistema vivo respeta Tier 1/Tier 2 y el alcance.

### Fase 2 — Más superficie de sistema

| Próximo | Motor previsto | Nivel de acceso |
|---|---|---|
| Discos de VM sin encenderlas | `trivy vm` (VMDK, AMI, snapshots EBS) | Credenciales / archivo de disco |
| Benchmarks CIS/STIG formales | ✅ **Lynis** (`scan_lynis`): índice de endurecimiento + avisos/sugerencias, Tier 1 (informe a mano, flujo MobaXterm) o Tier 2 (SSH). Pendiente: OpenSCAP (RHEL) y salida en formato STIG con justificaciones | Usuario de lectura |
| Nube: plano de control | Prowler con rol de solo lectura | Usuario de lectura |
| Kubernetes: postura | kube-bench (CIS) + Kubescape (NSA/MITRE) | Usuario de lectura (kubeconfig RO) |
| Windows Server | Inventario por WinRM + HardeningKitty | Credenciales |
| Directorio Activo: postura | ✅ `scan_ad` (solo lectura, PowerShell): política de contraseñas vs NIST/CIS, cuentas privilegiadas, delegación sin restricción, Kerberoasting/AS-REP, krbtgt, MachineAccountQuota, cuentas inactivas (estilo PingCastle). Los hallazgos Kerberos mapean a ATT&CK T1558. Pendiente: enumeración de ACL riesgosas objeto por objeto | Usuario de lectura del dominio |
| Bases de datos: configuración | ✅ **PostgreSQL y MySQL/MariaDB** (`scan_db`): cifrado (TLS), autenticación (pg_hba / cuentas sin contraseña, anónimas, plugin débil), exposición de red, cuentas privilegiadas y auditoría — con cuenta RO, Tier 1. Pendiente: SQL Server (mismo armazón) | Usuario de lectura |
| Monitoreo continuo | API de Wazuh (vulnerabilidades + CIS) | Usuario de lectura |
| **Hardening de Linux (del diplomado)** | Guías de endurecimiento accionables sobre los hallazgos de `scan_host`: SSH, kernel, SELinux/AppArmor, auditd, firewall, montajes | Usuario de lectura / credenciales |

### Fase 2.5 — Cadena de suministro y CI/CD

| Próximo | Motor previsto | Nivel de acceso |
|---|---|---|
| SBOM del repo y de imágenes | Syft (CycloneDX/SPDX), guardado por corrida para comparar | Código fuente |
| Salud del proyecto y de dependencias | OpenSSF Scorecard (modo local sobre el repo) | Código fuente |
| Pipelines de GitHub Actions | zizmor (inyección de scripts, permisos, `pull_request_target`) | Código fuente |
| Pipelines en general | poutine (GitHub/GitLab/Azure DevOps) | Código fuente |
| Mal uso de criptografía | Reglas Semgrep: algoritmos/modos débiles, IV fijos, RNG inseguro, hashing de contraseñas, JWT `none` | Código fuente |
| **Higiene de releases propios** | SHA256SUMS + SBOM CycloneDX + atestación de procedencia (`gh attestation verify`) para los binarios de Xolotl | Código fuente |

### Fase 3 — Profundidad de evaluación autorizada

Siempre dentro del alcance registrado y con aprobación por comando. Es evaluación (encontrar para
arreglar), no validación ofensiva de TTPs.

- DAST más profundo: OWASP ZAP (rastreo autenticado, escaneo activo desde OpenAPI).
- Fuzzing de APIs: Schemathesis / RESTler desde el esquema (REST, GraphQL); revisión de JWT/OAuth.
- Reconocimiento autorizado: httpx, katana, subfinder, naabu para alimentar a Nuclei.
- Apps con LLM propias: garak / promptfoo contra endpoints en alcance (inyección de prompt, fuga de datos, abuso de herramientas), más descubrimiento de endpoints de IA.
- Lógica de negocio: skill advisory con lista de pruebas por flujo (IDOR, saltos de paso, condiciones de carrera); sin ejecución automática.

### Fase 4 — Análisis offline de artefactos

Todo corre sobre archivos que el usuario entrega; no toca sistemas. (La *ingeniería de detección*
de esta fase es la mitad azul del bucle púrpura, ver abajo.)

| Próximo | Motor previsto | Entrada |
|---|---|---|
| Tráfico capturado | tshark / Zeek: protocolos, anomalías, credenciales en claro | `.pcap` |
| Respuesta a incidentes en Windows | Hayabusa / Chainsaw con reglas Sigma: línea de tiempo | `.evtx` |
| Triage de archivos sospechosos | YARA + capa (capacidades) + hashes | Binario |
| Apps móviles | Análisis estático de APK/IPA (jadx + Semgrep, o MobSF estático) | `.apk` / `.ipa` |
| Firmware | unblob/binwalk para extraer + `trivy`/Syft sobre el filesystem | Imagen de firmware |
| OT/ICS (pasivo) | Parsers ICS de Zeek (Modbus, DNP3, S7) sobre capturas | `.pcap` |
| Modelado de amenazas | STRIDE a partir de `inventory` + IaC: flujos y fronteras de confianza, en diagrama | Inventario |

---

## 🔴 Vía Roja — validación ofensiva de sistemas propios (Fase 5)

Es el **cierre del ciclo, no el comienzo**. Solo se corre cuando el activo ya pasó por escaneo de
vulnerabilidades (Vía Azul), está documentado en el `inventory` y sus arreglos de endurecimiento
están aplicados. Así cada prueba confirma que el hardening resiste, en vez de encontrar lo obvio.

**Aplica el candado de la vía roja** (ver *Principios rectores*): solo activos propios en alcance
con autorización, vía explícita, Tier 1 por defecto, aprobación registrada, nada destructivo.

| Capacidad | Qué valida del hardening | Motor previsto | Del diplomado |
|---|---|---|---|
| **Postura de contraseñas y spraying seguro** | Que la política y el bloqueo de cuentas aguanten; detecta credenciales débiles/reutilizadas sin bloquear cuentas | Pruebas con límite de intentos contra el propio directorio, cruzadas con brechas conocidas | Auditoría de credenciales |
| **Rutas de escalada de privilegios (Linux ofensivo)** | Que el endurecimiento cerró SUID, sudoers, tareas y servicios abusables | Encadenar los hallazgos de `scan_host` en una ruta demostrable (advisory), al estilo GTFOBins/linPEAS | Privesc Linux |
| **Exposición de Directorio Activo** | Que delegaciones, ACL y Kerberos quedaron bien tras el hardening | Pruebas de solo lectura y, en Tier 2, validación controlada (Kerberoasting sobre cuentas propias) | AD / Kerberos |
| **Prueba de concepto de un hallazgo** | Que una vulnerabilidad reportada es real y explotable en tu entorno | Validación acotada por hallazgo, no automática | Explotación acotada |
| **Segmentación y movimiento lateral** | Que la segmentación de red contiene el alcance de un equipo comprometido | Mapa de alcanzabilidad entre segmentos propios (advisory) | Movimiento lateral |

---

## 🟣 Púrpura — el bucle de endurecimiento

Une las dos vías en un ciclo medible: **escanear → documentar → arreglar → validar → detectar →
re-endurecer**. Depende de ítems de ambas vías ya construidos.

| Capacidad | Qué cierra | Depende de |
|---|---|---|
| **Ingeniería de detección** | Regla Sigma sugerida por hallazgo/técnica ATT&CK: que el SIEM detecte lo que el rojo probó | Mapeo ATT&CK (1.5) + Fase 4 |
| **Validación de defensas (purple team)** | Que el EDR/SIEM detecta y alerta lo que debe | Atomic Red Team / Caldera contra hosts propios, cruzado con las reglas Sigma | Vía Roja + Ingeniería de detección |
| **Bucle de revalidación** | Que el arreglo resiste y no hay regresión | `revalidate` + `runs_diff` (ya hechos) + validación roja |

---

## Cómo llegamos aquí

El diseño destiló la revisión de [`pentest-ai-agents`](https://github.com/0xSteph/pentest-ai-agents)
(tomar su modelo, no su dependencia de la nube) y, más tarde, de [ARTEX](https://github.com/BaaRai/ARTEX)
y [Pentester71](https://github.com/secsalem/Pentester71) (ideas de diseño: veredicto de 3 estados,
gate determinista, frontera de salida no confiable, higiene de releases — **ideas, no su código ni
sus capacidades ofensivas**). La tabla de cobertura frente a `pentest-ai-agents` v3.4.0 queda como
referencia histórica.

<details>
<summary>Cobertura frente a <code>pentest-ai-agents</code> v3.4.0 (revisión 2026-11-18)</summary>

| Dominio (sus agentes) | Xolotl hoy | Vía |
|---|---|---|
| Código (`code-auditor`) | ✅ `scan_static`, `scan_codeql` | 🔵 |
| Vulnerabilidades (`vuln-scanner`) | ✅ `scan_network`, `scan_dast`, `scan_host` | 🔵 |
| Verificación de arreglos (`fix-verifier`) | ✅ `runs_diff`, `revalidate` + `appsec-fix` | 🟣 |
| Informes (`report-generator`) | ✅ `report_generate` (técnico + resumen ejecutivo) | 🔵 |
| Memoria (`/memory`, `findings.sh`, `doctor.sh`) | ✅ BD SQLite, `inventory`, `xolotl_doctor`, `handoff` | 🧩 |
| Recomendación (`/recommend`, `/agents-for`) | ✅ `inventory view=next`, `eval_plan` | 🧩 |
| Puntuación de riesgo (`risk-scorer`) | ✅ EPSS + CISA KEV + CVSS (`risk_feeds`) | 🧩 |
| Validación (`poc-validator`) | ✅ `revalidate` (3 estados) + Nuclei por plantilla | 🟣 |
| Orquestación (`swarm-orchestrator`) | ✅ `eval_plan` + skill `appsec-plan` | 🧩 |
| Cumplimiento (`compliance-mapper`, `stig-analyst`) | ✅ mapeo a 5 marcos (OWASP/PCI/NIST/ISO/CIS) | 🔵 STIG/CIS formales (Fase 2) |
| Planeación (`engagement-planner`, `attack-planner`) | ✅ `engagement` (reglas de enfrentamiento) + mapeo ATT&CK | — |
| Nube y contenedores (`cloud-security`, `container-breakout`) | 🟡 imágenes e IaC | 🔵 Prowler + Kubernetes (Fase 2) |
| Directorio Activo (`ad-attacker`, `password-auditor`) | ✅ `scan_ad` (postura de solo lectura) | 🔴 validación (Fase 5) |
| Escalada de privilegios (`privesc-advisor`) | 🟡 SUID/sudoers/kernel en `scan_host` | 🔴 rutas demostrables (Fase 5) |
| Cadena de suministro y CI/CD (`supply-chain-auditor`, `cicd-redteam`) | 🟡 SCA | 🔵 Fase 2.5 |
| Criptografía (`crypto-analyzer`) | 🟡 TLS en red | 🔵 mal uso en código (Fase 2.5) |
| Recon y web/API (`recon-advisor`, `web-hunter`, `api-security`, `bug-bounty`) | 🟡 Nuclei | 🔵 Fase 3 |
| Lógica de negocio (`bizlogic-hunter`) | ❌ | 🔵 lista guiada advisory (Fase 3) |
| IA/LLM (`llm-redteam`, `ai-recon`) | ❌ | 🔵 evaluación de apps LLM propias (Fase 3) |
| Base de datos (`database-attacker`) | ✅ `scan_db` (PostgreSQL, MySQL) + 🟡 DAST genérico | 🔵 SQL Server (Fase 2) |
| Tráfico, IR, malware, reversa | ❌ | 🔵 Fase 4 (offline) |
| Móvil, firmware, OT | ❌ | 🔵 análisis estático/pasivo (Fase 4) |
| Detección y amenazas (`detection-engineer`, `threat-modeler`) | ❌ | 🟣 Fase 4 + bucle púrpura |
| Validación ofensiva (`credential-tester`, `network-attacker`, `lateral-movement`, `exploit-chainer`, `payload-crafter`…) | ❌ | 🔴 Fase 5, sobre sistemas propios |
| Validación de defensas (`evasion-specialist` como purple team) | ❌ | 🟣 bucle púrpura |
| `ctf-solver`, `wireless-pentester` | — | Fuera de foco |

`✅` cubierto · `🟡` parcial · `❌` falta.
</details>

---

## No objetivos

- Ningún servicio externo obligatorio ni telemetría.
- Nada de DoS, escaneo masivo, ni evasión de detección para uso malicioso.
- No reemplaza a un pentester ni al monitoreo de producción en tiempo real.
- **Nada contra sistemas de terceros.** Toda capacidad de la Vía Roja es solo para infraestructura
  propia, dentro del alcance registrado y con aprobación por comando (el candado de la vía roja).
- **Fuera incluso de la Vía Roja**: phishing e ingeniería social contra personas, C2 real,
  exfiltración de datos reales, anonimato del operador y persistencia duradera. Son técnicas de un
  compromiso contratado con terceros, no de endurecer lo propio.
- Pruebas que requieren hardware dedicado (inalámbricas, UART/JTAG) y CTF.
