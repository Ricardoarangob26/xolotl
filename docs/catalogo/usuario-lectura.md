# 🌓 Usuario de lectura

Lo que se ve con una **cuenta sin privilegios**, un **rol de solo lectura** o la salida de un
**recolector ejecutado sin `sudo`**. Salta el muro de la caja negra: ya se lee el sistema por
dentro, pero no todo.

> **Skill:** `appsec-hosts` (recolector sin `sudo`).

> Este es el nivel natural de tu flujo de MobaXterm cuando `operacion` no tiene `sudo`: el
> recolector corre en modo lectura y tú pegas la salida.

---

## inventario-de-servidor-linux (lectura)
- **Nivel de acceso:** usuario de lectura
- **Ejecución:** Tier 1 (advisory) — tú corres el recolector y pegas la salida
- **Tool MCP:** `host_collector` → `scan_host`
- **Motores:** recolector de solo lectura + Trivy (avisos de la distro) + reglas propias
- **Estado:** ✅ (subconjunto sin `sudo`)
- **Qué encuentra:** paquetes instalados con CVE entendiendo los parches retroportados (Debian, Ubuntu, RHEL, CentOS, Rocky, Alma, Oracle, Amazon, Fedora, Alpine), servicios expuestos, configuración visible al usuario.
- **Qué NO ve a este nivel:** lo que exige `sudo` — `/etc/shadow`, reglas de firewall completas, SUID en rutas restringidas, parámetros de kernel protegidos → ver [credenciales](credenciales.md).
- **Lo que nunca copia:** llaves, hashes de contraseña, historiales ni variables de entorno.

---

## 🧭 En la hoja de ruta a este nivel

| Capacidad | Motor | Nota |
|---|---|---|
| Benchmarks CIS/STIG | Lynis, OpenSCAP | Postura de endurecimiento con cuenta normal |
| Nube: plano de control | Prowler (rol read-only) | Malas configuraciones de AWS/Azure/GCP sin tocar recursos |
| Monitoreo continuo | API de Wazuh | Leer vulnerabilidades y evaluaciones CIS ya recogidas por el agente |
