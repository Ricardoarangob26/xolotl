---
name: appsec-network
description: Reconocimiento de red sin credenciales con el MCP Xolotl — descubrir puertos y servicios abiertos, revisar la postura TLS y marcar servicios de riesgo expuestos (bases de datos, Redis, Docker, RDP/VNC, SMB, SNMP, paneles) y la configuración SSH. Úsala cuando pidan ver qué expone un host, VM o rango a la red, revisar certificados/TLS, o la superficie de ataque externa de un sistema del que solo se tiene la dirección. Nivel de acceso: sin acceso (caja negra). Ejecución: Tier 2 (execute) o Tier 1 (advisory).
---

# Reconocimiento de red (sin acceso)

`scan_network` mira un objetivo **desde fuera**, sin ninguna credencial. Es el primer paso
cuando solo tienes una dirección: qué está escuchando, qué expone y cómo está el TLS.

- **Nivel de acceso:** 🌑 sin acceso. Solo necesita que el objetivo esté autorizado.
- **Motor:** TCP connect + TLS nativos (no requiere nmap) + `ssh-audit`.
- **Categorías de hallazgo:** `network` (puertos/servicios/TLS) y un hallazgo `info` de inventario con todos los puertos abiertos.

## 1. Autorización — primero, siempre

Escanear un host ajeno sin permiso es un incidente. Antes de nada, confirma con el usuario
que el objetivo es suyo o que tiene autorización escrita, y regístralo:

```
dast_scope action=add target=<host o CIDR> authorized_by=<quién> evidence=<ticket/contrato/propietario>
```

En modo `execute` el servidor **rechaza** cualquier objetivo fuera del alcance. Acepta hosts,
`host:puerto` y CIDR IPv4 (/22 o menor).

## 2. Nivel de ejecución (Tier 1 / Tier 2)

| Situación | Modo |
|---|---|
| Esta máquina puede alcanzar el objetivo y está autorizado | `mode: "execute"` (por defecto). Xolotl sondea y te entrega hallazgos. |
| Red aislada, cumplimiento, o el host ya nos bloqueó (fail2ban) | `mode: "advisory"`. Xolotl **no se conecta**: te da el `nmap`/`ssh-audit` exacto para correr desde un host autorizado; pegas la salida y la interpreto. |

Si `XOLOTL_MODE=advisory` está fijado en el servidor, todo cae a Tier 1 salvo que pidas `execute`.

## 3. Qué miran los hallazgos

- **Servicios de riesgo expuestos.** Bases de datos (MySQL, PostgreSQL, Mongo, MSSQL, Redis, Elastic), Docker/Kubelet, Telnet/FTP, RDP/VNC, SMB, SNMP, IPMI y paneles. Que escuchen en una interfaz pública casi siempre es el hallazgo más grave.
- **Postura TLS.** Protocolo obsoleto (SSLv3/TLS 1.0/1.1), cifrado débil, certificado vencido, autofirmado o con clave corta (RSA <2048, EC <224 — ECDSA P-256 es fuerte, no lo marques).
- **SSH.** `ssh-audit` revisa algoritmos y configuración. Si el host nos bloquea o no responde, se reporta como `error`, no como "limpio".

## 4. Límite importante: red ≠ CVE confirmado

Un banner ("OpenSSH 8.0", "nginx 1.20.1") **no** dice si la distro ya parcheó por retroporte.
Desde la red no afirmes que una versión es vulnerable. Para confirmar CVE con certeza, sube de
nivel: **appsec-hosts** (`scan_host`) lee el paquete instalado y usa los avisos de la distro.

## 5. Después del escaneo

1. Prioriza los servicios de riesgo expuestos y los problemas de TLS reales.
2. Clasifica con **appsec-triage**; un firewall perimetral puede justificar un `accepted_risk` con nota.
3. Para apps/APIs vivas, encadena con **appsec-dast** (Nuclei).
4. Para CVE de sistema con certeza, encadena con **appsec-hosts**.
5. Todo queda en el **inventario** (skill *appsec-inventory*): la próxima corrida dirá qué puertos son nuevos y cuáles desaparecieron.
