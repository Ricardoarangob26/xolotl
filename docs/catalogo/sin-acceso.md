# 🌑 Sin acceso

Lo que se ve de un objetivo **desde fuera**, sin ninguna credencial. Requiere solo que el
objetivo esté registrado en el alcance autorizado (`dast_scope`), con quién lo autorizó y
con qué evidencia. Es la caja negra.

> ⚠️ Nada aquí corre contra un objetivo que no esté en el alcance. El servidor rechaza
> comodines de TLD, `*` y rangos mayores a `/16`.

---

## descubrimiento-de-red
- **Nivel de acceso:** sin acceso
- **Ejecución:** Tier 2 (execution)
- **Tool MCP:** `scan_network`
- **Motores:** TCP connect nativo + TLS nativo (Node `net`/`tls`) + `ssh-audit`
- **Estado:** ✅
- **Qué encuentra:** puertos y servicios abiertos, banners, servicios de riesgo expuestos (BD, Redis, Docker, Telnet/FTP, RDP/VNC, SMB, SNMP, IPMI, paneles), postura TLS (protocolo/cifrado débil, certificado vencido/autofirmado/clave corta distinguiendo RSA de EC), auditoría de configuración SSH.
- **Qué NO ve a este nivel:** versiones exactas de paquetes ni si un CVE está parcheado por retroporte. Un banner "OpenSSH 8.0" no dice si la distro ya lo corrigió → eso es [usuario de lectura](usuario-lectura.md) o más.

## dast-por-plantillas
- **Nivel de acceso:** sin acceso
- **Ejecución:** Tier 2 (execution)
- **Tool MCP:** `scan_dast` · `dast_scope`
- **Motores:** Nuclei (plantillas de la comunidad)
- **Estado:** ✅
- **Qué encuentra:** CVE conocidos, paneles expuestos, malas configuraciones, exposiciones y problemas de TLS en apps, APIs y servicios en ejecución. Perfiles `baseline`, `automatic`, `full`, `custom`.
- **Qué NO ve a este nivel:** lógica de negocio, control de acceso (IDOR), ni vulnerabilidades que exijan autenticación. Plantillas intrusivas (dos, fuzz, fuerza bruta, default-login, rce) y detección fuera de banda desactivadas salvo petición explícita.

---

## 🧭 En la hoja de ruta a este nivel

| Capacidad | Motor | Nota |
|---|---|---|
| Reconocimiento autorizado | httpx, katana, subfinder, naabu | Descubrir hosts/rutas/puertos para alimentar a Nuclei |
| DAST profundo | OWASP ZAP | Escaneo activo desde OpenAPI (requiere autenticación → sube de nivel) |
| Fuzzing de APIs | Schemathesis, RESTler | Desde el esquema OpenAPI/GraphQL |
