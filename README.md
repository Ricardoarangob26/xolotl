<div align="center">

# 🐕‍🔥 Xolotl

**Un guardián que baja al inframundo de tu código.**

Servidor MCP + plugin de Claude Code que une siete escáneres de seguridad open source en una sola herramienta y pone a un agente de IA a hacer lo que los escáneres no hacen: leer el código, descartar falsos positivos con criterio, priorizar y verificar que cada arreglo funcione.

`SAST` · `SCA` · `Secretos` · `Contenedores` · `IaC` · `Servidores` · `DAST` · `Triage con IA`

</div>

> En la mitología mexica, **Xolotl** es el dios con forma de perro que guía y protege a las almas en su viaje por el Mictlán, el inframundo. Esta herramienta hace ese viaje por las capas que nadie mira: el historial de git, las dependencias transitivas, los Dockerfiles y las rutas de la API.

---

## Qué hace

| Análisis | Qué detecta | Motor | Herramienta MCP |
|---|---|---|---|
| **SAST** | Inyecciones, `eval`, deserialización insegura, criptografía débil, path traversal… | Semgrep, Bandit, CodeQL | `scan_static`, `scan_codeql` |
| **SCA** | Dependencias con CVE y la versión que las corrige | OSV-Scanner, Trivy | `scan_static` |
| **Secretos** | Tokens, claves y contraseñas, **también en todo el historial de git** | Gitleaks, Trivy | `scan_static` |
| **Contenedores** | Paquetes vulnerables y secretos dentro de imágenes | Trivy | `scan_container_image` |
| **IaC** | Dockerfile, compose, Kubernetes, Helm, Terraform, CloudFormation mal configurados | Trivy | `scan_iac`, `scan_static` |
| **Servidores Linux** | Paquetes del sistema con CVE (entendiendo los parches retroportados de RHEL/Debian) y endurecimiento: SSH, cuentas, sudo, firewall, SELinux/AppArmor, kernel, servicios expuestos, SUID, reinicio pendiente | Trivy + reglas propias | `scan_host`, `host_collector` |
| **DAST** | Malas configuraciones, exposiciones y CVE en apps, APIs y servicios en ejecución | Nuclei | `scan_dast` |
| **IA para AppSec** | Triage, explicación, priorización, parche y verificación | El agente (Claude u otro cliente MCP) | skills, prompts, `finding_triage`, `runs_diff` |

Los resultados de todas las herramientas se normalizan a un mismo formato y **se deduplican**: si Trivy y OSV reportan la misma CVE, o Gitleaks y Trivy el mismo secreto, queda un solo hallazgo con ambas fuentes.

## Qué tiene de nuevo

Los escáneres de seguridad existen hace años. El problema nunca fue encontrar hallazgos: es que un reporte de 300 líneas, la mitad falsos positivos, termina ignorado. Xolotl cambia el modelo de uso en cinco puntos:

1. **El agente cierra el ciclo completo.** Escanear → leer el código de cada hallazgo → decidir si es explotable → parchear → re-escanear → comparar corridas. Lo que antes eran cinco herramientas y una tarde de un analista, pasa en una conversación.
2. **El triage tiene memoria.** Cada decisión (`false_positive`, `accepted_risk`, `fixed`) se guarda con su justificación y una huella estable del hallazgo. El siguiente escaneo ya llega filtrado, y si algo marcado como corregido reaparece, se reabre solo como **regresión**.
3. **Los límites de seguridad están en el servidor, no en el prompt.** El DAST solo corre contra objetivos registrados con quién autorizó y con qué evidencia. Los secretos se guardan redactados. Ningún proceso se lanza con shell. Ningún binario se instala si su SHA-256 no coincide. Un agente confundido no puede saltarse estas reglas.
4. **Verificación de parches por diferencia.** `runs_diff` responde lo que importa en una revisión: qué se resolvió, qué es nuevo y qué persiste. Un arreglo que solo esquiva la regla, o que introduce otro problema, se ve de inmediato.
5. **Cero infraestructura.** Sin Docker, sin servidor, sin cuentas. `xolotl_install` baja los binarios oficiales a una carpeta propia. Funciona igual en Claude Code, Claude Desktop o cualquier cliente MCP.

## Alcances

**Cubre**
- Código fuente en cualquier lenguaje que soporte Semgrep (30+), con análisis profundo de flujo de datos en los lenguajes de CodeQL (JS/TS, Python, Java, C#, Go, Ruby, C/C++, Swift, Rust, GitHub Actions).
- Dependencias de npm, pip/poetry/uv, Maven/Gradle, Go, Cargo, Composer, NuGet, RubyGems y más (todo lo que leen OSV-Scanner y Trivy).
- Historial completo de git para secretos.
- Imágenes de contenedor desde un registro, el daemon local o un `.tar`.
- Servidores Linux on-premise, máquinas virtuales e instancias (Debian, Ubuntu, RHEL, CentOS, Rocky, AlmaLinux, Oracle, Amazon Linux, Fedora, Alpine): por SSH con llave, o con un recolector de solo lectura que se ejecuta a mano cuando no hay acceso directo (MobaXterm, consola, bastión, Ansible).
- Aplicaciones y servicios en ejecución con las plantillas de la comunidad de Nuclei (miles de CVE, paneles expuestos, malas configuraciones, TLS).
- Informes en Markdown, HTML autocontenido, **SARIF 2.1.0** (GitHub/GitLab code scanning, VS Code) y JSON.

**No cubre (y no pretende)**
- **Lógica de negocio y control de acceso:** IDOR, permisos mal aplicados, flujos de pago. Ningún escáner por patrones los encuentra bien. El agente puede revisarlos a mano siguiendo las rutas de la API, pero eso es revisión manual asistida, no detección automática.
- **Pruebas de penetración completas:** Nuclei detecta lo conocido por plantillas; no reemplaza a un pentester.
- **Seguridad en tiempo de ejecución:** no monitorea producción ni detecta intrusiones activas.
- **Windows Server, hipervisores (ESXi/vCenter) y nube (plano de control):** todavía no. Ver la hoja de ruta abajo.
- **Semgrep Assistant** (la IA de Semgrep) es comercial y no está incluida; ese papel lo cumple el agente.

## Formas de usarlo

| Modo | Cómo |
|---|---|
| **Auditor en pareja** | En el editor: *"audita la seguridad de este repo"*. El agente escanea, hace el triage, explica y propone parches. |
| **Compuerta antes del PR** | *"revisa la seguridad de mis cambios"*: escaneo, `runs_diff` contra la corrida de `main` y veredicto (prompt `review_patch`). |
| **Remediación guiada** | *"corrige F-012"*: parche mínimo, re-escaneo con la misma herramienta y verificación por diferencia (skill `appsec-fix`). |
| **Escaneo programado** | Una rutina de Claude Code (`/schedule`) o `claude -p` en CI corre `scan_static` cada noche y sube el SARIF a GitHub code scanning. El triage acumulado evita repetir el ruido. |
| **DAST después del despliegue** | Tras desplegar en staging: `scan_dast` con perfil `baseline`, luego dirigido según la tecnología detectada (skill `appsec-dast`). |
| **Respuesta a un secreto filtrado** | Gitleaks lo ubica en el historial; la skill guía revocar, rotar, limpiar y revisar el uso indebido, en ese orden. |

## Servidores: cómo se revisa uno

```text
recolector (solo lectura)  →  paquetes + configuración  →  SBOM con distribución y paquete fuente  →  Trivy (avisos de la distro)
                                                      ↘  reglas de endurecimiento  →  hallazgos "config"
```

- **Por qué no por la red:** RHEL y Debian corrigen vulnerabilidades sin cambiar la versión del paquete. Un escáner que mira el banner ("OpenSSH 8.0") reporta CVE ya corregidos y omite otros. Leyendo el paquete instalado y su paquete fuente, Trivy usa los avisos oficiales de la distribución.
- **Sin credenciales en la herramienta:** si no hay SSH directo, `host_collector` entrega el script, se ejecuta en el servidor con `sudo sh xolotl-collect.sh > salida.txt` y `scan_host` analiza el archivo.
- **Lo que no copia:** llaves, hashes de `/etc/shadow` (solo nombres de cuentas sin contraseña), historiales ni variables de entorno.

### Hoja de ruta

| Próximo | Motor previsto |
|---|---|
| Red sin credenciales (`scan_network`) | Nmap + Nuclei red/SSL + testssl.sh + ssh-audit, limitado al alcance |
| Discos de VM sin encenderlas | `trivy vm` (VMDK, AMI, snapshots EBS) |
| Nube: plano de control | Prowler con rol de solo lectura |
| Benchmarks CIS/STIG formales | OpenSCAP (RHEL), Lynis |
| Windows Server | Inventario por WinRM + HardeningKitty |
| Monitoreo continuo | Leer vulnerabilidades y evaluaciones CIS desde la API de Wazuh |

## Instalación

Requiere **Node.js 20+**. Opcional: [`uv`](https://docs.astral.sh/uv/) para instalar o ejecutar Semgrep y Bandit al vuelo.

```bash
git clone https://github.com/Ricardoarangob26/xolotl.git
cd xolotl
npm install && npm run build
```

### Como plugin de Claude Code (MCP + skills)

```bash
claude plugin marketplace add ./xolotl
claude plugin install xolotl@xolotl
```

### Solo el servidor MCP (Claude Code, Claude Desktop, otro cliente)

```bash
claude mcp add xolotl --scope user -- node /ruta/a/xolotl/dist/index.js
```

```json
{ "mcpServers": { "xolotl": { "command": "node", "args": ["/ruta/a/xolotl/dist/index.js"] } } }
```

Luego, en el chat:

> revisa qué escáneres faltan e instálalos

> audita la seguridad de /ruta/al/proyecto

## Herramientas del MCP

| Tool | Para qué |
|---|---|
| `xolotl_doctor` | Qué escáneres hay, versión y de dónde se ejecutan |
| `xolotl_install` | Instala o actualiza escáneres (releases oficiales de GitHub con SHA-256; Semgrep/Bandit con `uv`) |
| `scan_static` | SAST + SCA + secretos + IaC sobre una carpeta, deduplicado |
| `scan_codeql` | Análisis de flujo de datos con la suite `security-extended` |
| `scan_container_image` | Trivy sobre una imagen |
| `scan_iac` | Trivy config sobre infraestructura como código |
| `scan_host` | Servidor Linux por SSH con llave (en el alcance autorizado) o desde la salida del recolector |
| `host_collector` | Escribe el recolector de solo lectura para ejecutarlo en servidores sin SSH directo |
| `dast_scope` | Alcance autorizado para DAST: quién autorizó y con qué evidencia |
| `scan_dast` | Nuclei por perfiles (`baseline`, `automatic`, `full`, `custom`); rechaza objetivos fuera de alcance |
| `runs_list` · `findings_query` · `finding_get` | Navegar corridas y hallazgos, con el código alrededor de la línea |
| `finding_triage` | `confirmed` / `false_positive` / `accepted_risk` / `fixed`, con nota; se recuerda entre corridas |
| `runs_diff` | Resueltos, nuevos y persistentes entre dos corridas |
| `report_generate` | Informe Markdown, HTML, SARIF o JSON |

**Prompts MCP:** `triage_run`, `fix_finding`, `review_patch`.
**Skills:** `appsec-audit`, `appsec-triage`, `appsec-dast`, `appsec-fix`, `appsec-hosts`.

## Modelo de seguridad de la propia herramienta

- Procesos sin shell, con argumentos en arreglo: nada de inyección por comillas en rutas o parámetros.
- Gitleaks corre con `--redact`; Trivy enmascara; las cabeceras de autenticación del DAST se redactan antes de guardar.
- DAST solo contra `localhost` y los objetivos de `scope.json`. Se rechazan alcances como `*`, comodines de TLD o rangos mayores a `/16`. Plantillas intrusivas (dos, fuzz, fuerza bruta, default-login, rce) y detección fuera de banda (interactsh) desactivadas salvo que se pidan explícitamente.
- Instalación solo desde releases oficiales; si el SHA-256 publicado no coincide, se aborta.
- Descartar un hallazgo exige una justificación escrita.

## Herramientas que lo complementan

Todas open source. Varias encajan como un escáner más (cualquier herramienta con salida SARIF ya se puede leer con `parseSarif`).

| Necesidad | Herramienta | Qué agrega |
|---|---|---|
| DAST más profundo | **OWASP ZAP** | Rastreo autenticado, escaneo activo, APIs desde OpenAPI. Complementa a Nuclei, que va por plantillas. |
| Fuzzing de APIs | **Schemathesis**, **RESTler** | Genera casos desde el esquema OpenAPI/GraphQL y encuentra errores 500, fugas y validaciones rotas. |
| Reconocimiento autorizado | **httpx**, **katana**, **subfinder**, **naabu** (ProjectDiscovery) | Descubren hosts, rutas y puertos para alimentar a Nuclei. |
| SBOM y cartera de dependencias | **Syft** + **Grype**, **OWASP Dependency-Track** | Inventario de componentes (CycloneDX/SPDX) y seguimiento de CVE en el tiempo por proyecto. |
| Gestión de vulnerabilidades | **DefectDojo** | Centraliza hallazgos de varios equipos y proyectos; importa SARIF y JSON. |
| Verificar secretos vivos | **TruffleHog** | Comprueba contra el proveedor si una credencial filtrada sigue activa. |
| IaC adicional | **Checkov**, **KICS**, **Hadolint**, **kube-linter** | Más reglas para Terraform/K8s y buenas prácticas de Dockerfile. |
| Cadena de suministro | **OpenSSF Scorecard**, **zizmor** | Postura del repositorio y seguridad de los workflows de GitHub Actions. |
| Confirmar inyecciones SQL | **sqlmap** | Prueba la explotabilidad real (solo en objetivos autorizados). |
| Apps móviles | **MobSF** | Análisis estático y dinámico de APK/IPA. |
| Apps con LLM | **garak**, **promptfoo** | Red teaming de inyección de prompts, fugas y jailbreaks. |
| Calidad + seguridad continua | **SonarQube Community** | Paneles por proyecto y deuda técnica. |
| Tiempo de ejecución | **Falco** | Detección de comportamiento anómalo en contenedores en producción. |

## Datos y configuración

Todo vive en `~/.xolotl` (cámbialo con `XOLOTL_HOME`):

```
~/.xolotl/
├── tools/        binarios gestionados (tienen prioridad sobre los del PATH)
├── runs/<id>/    salida cruda de cada escáner, findings.json, meta.json e informes
├── scope.json    alcance DAST autorizado
└── triage.json   decisiones de triage por huella
```

`GITHUB_TOKEN` (opcional) evita el límite de la API de GitHub al instalar escáneres.

## Desarrollo

```bash
npm run build                          # typecheck + bundle en dist/index.js (sin dependencias en tiempo de ejecución)
node scripts/selftest.mjs              # levanta el MCP y escanea un proyecto vulnerable generado al vuelo
node scripts/selftest.mjs --install    # instala antes los escáneres que falten
node scripts/validate-host.mjs         # scan_host contra trivy image en debian:12 y rockylinux:9 (CVE idénticos + 15 fallas sembradas)
node scripts/call.mjs scan_static '{"path":"/ruta"}'   # llama cualquier tool desde la terminal
```

Estructura: `src/scanners.ts` lanza cada herramienta, `src/parsers.ts` traduce su salida al formato común, `src/findings.ts` normaliza y deduplica, `src/store.ts` guarda corridas y triage, `src/scope.ts` aplica el alcance DAST, `src/report.ts` genera los informes. Agregar un escáner es una función en cada uno de los dos primeros.

`scan_host` está validado contra `trivy image` en Debian 12, Ubuntu 24.04, Rocky 9 y AlmaLinux 9: mismos paquetes, CVE y versiones corregidas.

Probado en Windows 11 con Semgrep 1.181, Bandit 1.9, OSV-Scanner 2.7, Trivy 0.76, Gitleaks 8.30 y Nuclei 3.11. Linux y macOS están contemplados (instalador y rutas), pero aún sin probar. CodeQL está integrado pero todavía no se ha probado de punta a punta.

## Licencia

MIT
