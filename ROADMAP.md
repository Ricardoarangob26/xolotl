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

## Fase 1 — Memoria y catálogo ✅ (completada)

Lo que destiló la revisión de [`pentest-ai-agents`](https://github.com/0xSteph/pentest-ai-agents):
tomar su estética y su modelo, no su dependencia de la nube.

| Tarea | Estado | Qué agrega | Inspiración |
|---|---|---|---|
| **BD local SQLite** | ✅ | Hallazgos, corridas y enlaces en `~/.xolotl/xolotl.db` con huella estable, columna `tool_used` e índices. Motor `node:sqlite` nativo (Node 22.5+) con respaldo JSON. | Su `findings.sh` + esquema |
| **Inventario / ecosistema** | ✅ | Tool `inventory`: resumen del ecosistema, activos, hallazgos en el tiempo (nuevos/persistentes/desaparecidos) e historia por huella. Crece solo con cada corrida. | Tu petición original |
| **Niveles de ejecución (Tier 1 / Tier 2)** | ✅ | Parámetro `mode` en `scan_network`/`scan_dast`/`scan_host` y variable `XOLOTL_MODE`. *advisory* (Tier 1): no se conecta, entrega el comando exacto para correr a mano (tu flujo de MobaXterm). *execute* (Tier 2): escanea validando el alcance. | Su modelo de dos niveles |
| **Catálogo de skills por dominio** | ✅ | Siete skills por dominio con nivel de acceso y de ejecución, navegables en [`docs/catalogo/`](docs/catalogo/README.md). Nuevas: `appsec-network` (red sin credenciales) y `appsec-inventory` (ecosistema). | Su catálogo de agentes `.md` |

## Cobertura frente a `pentest-ai-agents` v3.4.0 (revisión 2026-11-18)

Segunda pasada, ahora contra los 52 agentes, 3 comandos y la BD de la v3.4.0. Ellos son
*prompts* que asesoran; Xolotl son **motores que ejecutan y recuerdan**. Por eso la meta no es
copiar agentes, sino que cada dominio defensivo o de evaluación tenga motor, skill o ambos.

| Dominio (sus agentes) | Xolotl hoy | Acción |
|---|---|---|
| Código (`code-auditor`) | ✅ `scan_static`, `scan_codeql` | — |
| Vulnerabilidades (`vuln-scanner`) | ✅ `scan_network`, `scan_dast`, `scan_host` | — |
| Verificación de arreglos (`fix-verifier`) | ✅ `runs_diff` + `appsec-fix` | — |
| Informes (`report-generator`) | ✅ `report_generate` (técnico) | Resumen ejecutivo → Fase 1.5 |
| Memoria (`/memory`, `findings.sh`, `doctor.sh`) | ✅ BD SQLite, `inventory`, `xolotl_doctor` | Traspaso de compromiso → Fase 1.5 |
| Recomendación (`/recommend`, `/agents-for`) | ✅ `inventory view=next` propone qué evaluar por activo | — |
| Puntuación de riesgo (`risk-scorer`) | ✅ EPSS + CISA KEV sobre la severidad (`risk_feeds`) | — |
| Cumplimiento (`compliance-mapper`, `stig-analyst`) | 🟡 CWE por hallazgo | Mapeo a marcos → Fase 1.5; STIG/CIS → Fase 2 |
| Validación (`poc-validator`) | 🟡 Nuclei confirma por plantilla | Revalidación no destructiva → Fase 1.5 |
| Planeación (`engagement-planner`, `attack-planner`) | 🟡 `dast_scope` (alcance) | Reglas de enfrentamiento + ATT&CK → Fase 1.5 |
| Nube y contenedores (`cloud-security`, `container-breakout`) | 🟡 imágenes e IaC | Prowler (Fase 2) + postura de Kubernetes → Fase 2 |
| Directorio Activo (`ad-attacker`, `password-auditor`) | ❌ | Postura de AD de solo lectura → Fase 2 |
| Escalada de privilegios (`privesc-advisor`) | 🟡 SUID/sudoers/kernel en `scan_host` | Windows en Fase 2 |
| Cadena de suministro y CI/CD (`supply-chain-auditor`, `cicd-redteam`) | 🟡 SCA | **Fase 2.5** |
| Criptografía (`crypto-analyzer`) | 🟡 TLS en red | Mal uso en código → Fase 2.5 |
| Recon y web/API (`recon-advisor`, `web-hunter`, `api-security`, `bug-bounty`) | 🟡 Nuclei | Fase 3 (ya prevista) |
| Lógica de negocio (`bizlogic-hunter`) | ❌ | Lista de pruebas guiada (solo advisory) → Fase 3 |
| IA/LLM (`llm-redteam`, `ai-recon`) | ❌ | Evaluación de apps LLM propias → Fase 3 |
| Base de datos (`database-attacker`) | 🟡 DAST genérico | Auditoría de configuración de BD → Fase 2 |
| Tráfico, IR, malware, reversa (`traffic-analyzer`, `forensics-analyst`, `malware-analyst`, `reverse-engineer`) | ❌ | **Fase 4** (análisis offline de artefactos) |
| Móvil, firmware, OT (`mobile-pentester`, `iot-pentester`, `scada-attacker`) | ❌ | Análisis estático/pasivo → Fase 4 |
| Detección y amenazas (`detection-engineer`, `threat-modeler`) | ❌ | **Fase 4** |
| Orquestación (`swarm-orchestrator`) | 🟡 tools sueltas | Plan de evaluación por activo → Fase 1.5 |
| Costo de tokens (`-Lite` → Haiku) | 🟡 modelo local posible | Sugerencia de modelo por skill → Fase 1.5 |
| Validación ofensiva (`credential-tester`, `password-auditor`, `network-attacker`, `lateral-movement`, `privesc-advisor`, `exploit-chainer`, `ad-attacker`, `payload-crafter`) | ❌ | **Fase 5**, sobre sistemas propios ya documentados |
| Validación de defensas (`evasion-specialist`, `detection-engineer` como blue/purple team) | ❌ | **Fase 5** (purple team) |
| `ctf-solver`, `wireless-pentester` | — | Fuera de foco (ver *No objetivos*) |

`✅` cubierto · `🟡` parcial · `❌` falta.

## Fase 1.5 — Inteligencia sobre los hallazgos (transversal)

Es lo más barato y lo que más valor agrega: todo lo que ya se escanea gana contexto. No toca sistemas.

| Tarea | Qué agrega | Inspiración |
|---|---|---|
| **Puntuación de riesgo** ✅ | Base **CVSS** real (vector y puntaje de NVD/proveedor/GHSA vía OSV, Trivy y Nuclei) × **explotabilidad** (**EPSS** + **CISA KEV**, feeds opcionales en `~/.xolotl/feeds` vía `risk_feeds`, funciona sin red) × **criticidad del activo** (la fija el usuario con `asset_criticality`: crítica/alta/normal/baja). Visible en `findings_query`, en el detalle del informe (línea CVSS + factores), en la tabla «Prioridad por riesgo» que reordena entre severidades y en el inventario por activo; el SARIF usa el CVSS real como `security-severity`. | `risk-scorer` |
| **Mapeo a marcos** | De CWE/regla a PCI DSS 4.0, NIST 800-53/CSF 2.0, ISO 27001:2022, CIS Controls v8 y OWASP Top 10/ASVS. Informe de brechas por control en `report_generate`. | `compliance-mapper` |
| **Mapeo a MITRE ATT&CK** | Técnica asociada por hallazgo (útil para detección y para planear). | `engagement-planner` |
| **Plan de compromiso** | Skill `appsec-engagement`: reglas de enfrentamiento, alcance y ventanas sobre `dast_scope`, con plantilla exportable. | `engagement-planner` |
| **Resumen ejecutivo** | Sección de negocio en el informe: tendencia (nuevos/persistentes), top de riesgo, avance de remediación. | `report-generator` |
| **Traspaso de compromiso** ✅ | Tool `handoff` (export/import): un archivo JSON con alcance, triage, criticidad de activos, inventario acumulado y los artefactos de cada corrida, para retomar en otra sesión o máquina (fusión o reemplazo). No incluye los feeds (se rebajan con `risk_feeds`). | `handoff.sh` |
| **Siguiente paso sugerido** ✅ | `inventory view=next`: por activo, infiere su tipo (host, web, código, imagen), muestra una matriz de cobertura (qué pruebas aplican y cuáles ya corrieron) y propone las que faltan con su nivel (código/app/máquina) y el acceso que necesitan. Lee señales del propio inventario —puertos abiertos del hallazgo de red, p. ej. "puerto web 8080 abierto y sin DAST"; "host sin revisión de configuración"; "SAST hecho, falta CodeQL/IaC"— y ordena por criticidad del activo. Es el mapa de "qué tanto le puedo evaluar a cada sistema". | `/recommend` |
| **Plan de evaluación por activo** | Skill que encadena las tools según el tipo de activo y el nivel de acceso, respetando Tier 1/Tier 2. | `swarm-orchestrator` |
| **Revalidación no destructiva** | Repetir solo la verificación de un hallazgo (plantilla o regla puntual) para confirmar o descartar sin repetir toda la corrida. | `poc-validator` |
| **Migraciones de esquema** | Versión del esquema en la BD y migraciones idempotentes. | `migrate.sh` |
| **Modelo por skill** | Pista `model:` en skills que solo asesoran (planeación, mapeo, informe), para usar uno barato o local. | `-Lite` |

## Fase 2 — Más superficie de sistema

| Próximo | Motor previsto | Nivel de acceso |
|---|---|---|
| Discos de VM sin encenderlas | `trivy vm` (VMDK, AMI, snapshots EBS) | Credenciales / archivo de disco |
| Benchmarks CIS/STIG formales | OpenSCAP (RHEL), Lynis; salida en formato STIG con justificaciones | Usuario de lectura |
| Nube: plano de control | Prowler con rol de solo lectura | Usuario de lectura |
| Kubernetes: postura | kube-bench (CIS) + Kubescape (NSA/MITRE) | Usuario de lectura (kubeconfig RO) |
| Windows Server | Inventario por WinRM + HardeningKitty | Credenciales |
| Directorio Activo: postura | Consultas LDAP de solo lectura: política de contraseñas vs NIST 800-63B, cuentas privilegiadas, delegaciones, ACL riesgosas, cuentas inactivas (al estilo PingCastle) | Usuario de lectura del dominio |
| Bases de datos: configuración | Auditoría de configuración y privilegios (PostgreSQL, MySQL, SQL Server) con cuenta RO | Usuario de lectura |
| Monitoreo continuo | API de Wazuh (vulnerabilidades + CIS) | Usuario de lectura |

## Fase 2.5 — Cadena de suministro y CI/CD

| Próximo | Motor previsto | Nivel de acceso |
|---|---|---|
| SBOM del repo y de imágenes | Syft (CycloneDX/SPDX), guardado por corrida para comparar | Código fuente |
| Salud del proyecto y de dependencias | OpenSSF Scorecard (modo local sobre el repo) | Código fuente |
| Pipelines de GitHub Actions | zizmor (inyección de scripts, permisos, `pull_request_target`) | Código fuente |
| Pipelines en general | poutine (GitHub/GitLab/Azure DevOps) | Código fuente |
| Mal uso de criptografía | Reglas Semgrep: algoritmos/modos débiles, IV fijos, RNG inseguro, hashing de contraseñas, JWT `none` | Código fuente |

## Fase 3 — Profundidad de evaluación autorizada

Siempre dentro del alcance registrado y con aprobación por comando.

- DAST más profundo: OWASP ZAP (rastreo autenticado, escaneo activo desde OpenAPI).
- Fuzzing de APIs: Schemathesis / RESTler desde el esquema (REST, GraphQL); revisión de JWT/OAuth.
- Reconocimiento autorizado: httpx, katana, subfinder, naabu para alimentar a Nuclei.
- Apps con LLM propias: garak / promptfoo contra endpoints en alcance (inyección de prompt, fuga de datos, abuso de herramientas), más descubrimiento de endpoints de IA.
- Lógica de negocio: skill advisory con lista de pruebas por flujo (IDOR, saltos de paso, condiciones de carrera); sin ejecución automática.

## Fase 4 — Análisis offline de artefactos y defensa

Todo corre sobre archivos que el usuario entrega; no toca sistemas.

| Próximo | Motor previsto | Entrada |
|---|---|---|
| Tráfico capturado | tshark / Zeek: protocolos, anomalías, credenciales en claro (para reportarlas) | `.pcap` |
| Respuesta a incidentes en Windows | Hayabusa / Chainsaw con reglas Sigma: línea de tiempo | `.evtx` |
| Triage de archivos sospechosos | YARA + capa (capacidades) + hashes | Binario |
| Apps móviles | Análisis estático de APK/IPA (jadx + Semgrep, o MobSF estático) | `.apk` / `.ipa` |
| Firmware | unblob/binwalk para extraer + `trivy`/Syft sobre el filesystem | Imagen de firmware |
| OT/ICS (pasivo) | Parsers ICS de Zeek (Modbus, DNP3, S7) sobre capturas | `.pcap` |
| Ingeniería de detección | Regla Sigma sugerida por hallazgo/técnica ATT&CK | Hallazgos |
| Modelado de amenazas | STRIDE a partir de `inventory` + IaC: flujos y fronteras de confianza, en diagrama | Inventario |

## Fase 5 — Validación ofensiva de sistemas propios

Es el cierre del ciclo, **no el comienzo**. Solo se corre cuando el activo ya pasó por
escaneo de vulnerabilidades (Fases 1–2), está documentado en el `inventory` y sus arreglos de
endurecimiento están aplicados. Así cada prueba confirma que el hardening resiste, en vez de
encontrar lo obvio. Pensada para **nuestra propia infraestructura** (purple team interno):
validar y endurecer, con un bucle escanear → documentar → arreglar → validar → re-endurecer.

Reglas duras de esta fase, sin excepción:
- **Solo activos propios** dentro del alcance registrado en `dast_scope`; el objetivo se valida
  contra el alcance antes de cada acción.
- **Tier 1 (advisory) por defecto**: el servidor entrega el comando exacto y tú lo corres; Tier 2
  (ejecución) pide aprobación por comando y queda registrado en la corrida.
- Sin tocar producción en horario productivo salvo ventana acordada; nada destructivo.
- Credenciales y artefactos de prueba sintéticos, nunca datos reales de clientes.

| Capacidad | Qué valida del hardening | Motor previsto | Inspiración |
|---|---|---|---|
| **Postura de contraseñas y spraying seguro** | Que la política y el bloqueo de cuentas aguanten; detecta credenciales débiles/reutilizadas sin bloquear cuentas | Pruebas con límite de intentos contra el propio directorio, cruzadas con brechas conocidas | `password-auditor`, `credential-tester` |
| **Rutas de escalada de privilegios** | Que el endurecimiento de hosts cerró SUID, sudoers, tareas y servicios abusables | Encadenar los hallazgos de `scan_host` en una ruta demostrable (advisory) | `privesc-advisor`, `exploit-chainer` |
| **Exposición de Directorio Activo** | Que delegaciones, ACL y Kerberos quedaron bien tras el hardening | Pruebas de solo lectura y, en Tier 2, validación controlada (Kerberoasting sobre cuentas propias) | `ad-attacker` |
| **Validación de defensas (purple team)** | Que el EDR/SIEM detecta y alerta lo que debe | Atomic Red Team / Caldera contra hosts propios, cruzado con las reglas Sigma de la Fase 4 | `evasion-specialist` + `detection-engineer` |
| **Prueba de concepto de un hallazgo** | Que una vulnerabilidad reportada es real y explotable en tu entorno, para priorizar el arreglo | Validación acotada por hallazgo, no automática | `poc-validator`, `exploit-chainer` |
| **Segmentación y movimiento lateral** | Que la segmentación de red contiene el alcance de un equipo comprometido | Mapa de alcanzabilidad entre segmentos propios (advisory) | `lateral-movement`, `network-attacker` |

Queda **fuera incluso de esta fase**: infraestructura de phishing e ingeniería social contra
personas, C2 real, exfiltración de datos reales, anonimato del operador y persistencia duradera.
Son técnicas de un compromiso contratado con terceros, no de endurecer lo propio.

---

## No objetivos

- Ningún servicio externo obligatorio ni telemetría.
- Nada de DoS, escaneo masivo, ni evasión de detección para uso malicioso.
- No reemplaza a un pentester ni al monitoreo de producción en tiempo real.
- **Nada contra sistemas de terceros.** Toda capacidad ofensiva (Fase 5) es solo para
  infraestructura propia, dentro del alcance registrado y con aprobación por comando.
- **Fuera incluso de la Fase 5**: phishing e ingeniería social contra personas, C2 real,
  exfiltración de datos reales, anonimato del operador y persistencia duradera.
- Pruebas que requieren hardware dedicado (inalámbricas, UART/JTAG) y CTF.
