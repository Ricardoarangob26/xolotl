---
name: appsec-hosts
description: Revisión de seguridad de servidores Linux (on-premise, máquinas virtuales e instancias en la nube) con el MCP Xolotl — vulnerabilidades de los paquetes del sistema y endurecimiento (SSH, cuentas, sudo, firewall, SELinux/AppArmor, kernel, servicios expuestos). Úsala cuando pidan auditar, escanear o endurecer un servidor, una VM o una instancia, revisar parches pendientes o comparar un servidor con buenas prácticas tipo CIS.
---

# Servidores Linux

`scan_host` revisa un servidor en solo lectura y produce dos categorías de hallazgos:

- **host** — paquetes del sistema con CVE. Trivy los cruza con los avisos de la propia distribución, así que entiende los parches retroportados de RHEL, Rocky, Alma y Debian (un escaneo de red por versión de banner se equivoca justo ahí).
- **config** — endurecimiento: SSH, cuentas con UID 0 o sin contraseña, sudo sin contraseña, grupo docker, firewall, SELinux/AppArmor, ASLR y otros parámetros del kernel, bases de datos escuchando en todas las interfaces, servicios sin cifrado, SUID fuera del sistema, archivos de /etc modificables por todos, reinicio pendiente, actualizaciones automáticas, auditd, NTP.

Distribuciones con vulnerabilidades: Debian, Ubuntu, RHEL, CentOS, Rocky, AlmaLinux, Oracle Linux, Amazon Linux, Fedora, Alpine. En otras igual corre el endurecimiento.

## 1. Autorización y modo

Revisar un servidor ajeno sin permiso es un incidente, aunque sea en solo lectura. Antes de empezar, confirma con el usuario que el servidor es suyo o que tiene autorización.

| Situación | Modo |
|---|---|
| Hay SSH con llave desde esta máquina | `scan_host` con `target: "usuario@host"`. El host tiene que estar en `dast_scope` (agrégalo con quién autorizó y la evidencia). Usa `sudo: true` si el usuario tiene sudo sin contraseña; si no, `sudo: false` (cobertura parcial). |
| Solo se entra por MobaXterm, consola, bastión o Ansible | `host_collector` escribe el script; el usuario lo ejecuta en el servidor (`sudo sh xolotl-collect.sh > xolotl-host.txt`), descarga el resultado y tú corres `scan_host` con `collected_file`. Ninguna credencial pasa por aquí. |
| Muchos servidores | El mismo recolector distribuido por Ansible/SSH en lote, y un `scan_host` por archivo. |

El recolector no instala ni cambia nada y no copia secretos (ni llaves, ni hashes de /etc/shadow, ni historiales). Puedes mostrárselo al usuario antes de que lo ejecute: está en `src/collector.sh`.

## 2. Triage específico de servidores

Usa la skill **appsec-triage** con estos criterios adicionales:

- **Con parche vs. sin parche.** Lo accionable hoy es lo que tiene `fixedVersion`: es el atraso de parcheo. Lo que no tiene parche publicado se gestiona con mitigaciones o se acepta con nota (`ignore_unfixed: true` para ver solo lo accionable).
- **Agrupa por paquete fuente.** Diez CVE en `util-linux` (libblkid, libmount, mount…) se resuelven con una sola actualización. Entrega el plan como "actualizar X", no como lista de CVE.
- **Expuesto vs. instalado.** Sube la prioridad de lo que escucha en la red (sshd, nginx, la base de datos, OpenSSL que estos usan) y de los servicios que aparecen en `XOL-NET-002`. Baja la de librerías que ningún servicio carga.
- **Reinicio pendiente (`XOL-PAT-001`).** Si existe, los CVE del kernel y de glibc/openssl siguen activos aunque el paquete aparezca actualizado: el reinicio va primero en el plan.
- **Hallazgos críticos de cuentas** (`XOL-ACC-001` UID 0 extra, `XOL-ACC-002` sin contraseña, SUID raros en `XOL-FS-003`) pueden ser señales de una intrusión previa, no solo malas prácticas. Sugiere revisar cuándo aparecieron (`ls -l --time-style=full-iso`, `last`, registros de auditoría) antes de "arreglarlos" y perder la evidencia.
- **El contexto manda.** `ip_forward` en un host de contenedores es normal; un firewall "inactivo" puede ser intencional si hay uno perimetral (anótalo como `accepted_risk` con esa justificación).

## 3. Remediación y verificación

- RHEL/Rocky/Alma: `dnf upgrade --security` (o el paquete puntual), luego reiniciar si hubo kernel o glibc.
- Debian/Ubuntu: `apt-get update && apt-get install --only-upgrade <paquetes>` o `unattended-upgrade`; reiniciar si `/var/run/reboot-required`.
- Cambios de configuración: proponer el cambio exacto (archivo y línea) y advertir los que pueden cortar el acceso (SSH, firewall) — siempre con una sesión abierta de respaldo.
- Volver a recolectar y `runs_diff` contra la corrida anterior: lo parchado sale en **Resueltos**.

## Límites

- No ve software instalado fuera del gestor de paquetes (binarios en /opt, aplicaciones Java/Node empaquetadas): para eso, `scan_static` sobre esas carpetas o `scan_container_image`.
- No detecta intrusiones activas: para eso hace falta análisis forense (Velociraptor) o un EDR.
- Windows no está cubierto todavía.
