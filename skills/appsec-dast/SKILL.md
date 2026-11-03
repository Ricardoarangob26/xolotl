---
name: appsec-dast
description: Pruebas dinámicas (DAST) autorizadas con Nuclei a través del MCP Xolotl contra aplicaciones web, APIs, servicios y configuraciones expuestas. Úsala cuando pidan escanear una URL, un sitio, una API o un servidor en ejecución, buscar malas configuraciones o CVE en un servicio expuesto, o hacer pruebas de penetración automatizadas.
---

# Pruebas dinámicas con Nuclei

Las pruebas dinámicas envían tráfico real a sistemas reales. **Solo se prueban objetivos que el usuario está autorizado a probar.** El servidor lo hace cumplir: `scan_dast` rechaza cualquier objetivo fuera de `dast_scope`.

## 1. Autorización (obligatorio)

1. `dast_scope` con `action: "list"`. `localhost`/`127.0.0.1` ya están permitidos.
2. Si el objetivo no está, **pregúntale al usuario** antes de agregarlo: quién autoriza y con qué base (es el dueño del sistema, ticket o contrato de pentest, ambiente propio de pruebas). No lo infieras ni lo inventes.
3. Con la respuesta, `dast_scope` `action: "add"` con `target`, `authorized_by` y `evidence`. Queda registrado con fecha.
4. Nunca agregues dominios de terceros (proveedores, CDNs, APIs públicas) solo porque la app los consume.
5. Preferir ambientes de pruebas o staging sobre producción. Si es producción, acordar ventana y tasa.

## 2. Escaneo por etapas

1. **Reconocimiento** — `scan_dast` con `profile: "baseline"` (tecnologías, malas configuraciones, exposiciones, CVE, TLS, paneles). Tasa por defecto: 30 req/s; bájala (`rate_limit: 5–10`) para servidores frágiles o producción.
2. **Dirigido** — con las tecnologías detectadas, `profile: "custom"` y `tags` específicos (p. ej. `["nginx","php","wordpress"]`, `["graphql"]`, `["jwt"]`) o `profile: "automatic"`.
3. **Autenticado** — si hay que probar detrás del login, `headers: ["Cookie: …"]` o `["Authorization: Bearer …"]` con una cuenta de prueba que el usuario proporcione. Se redactan en los resultados guardados. Nunca uses credenciales de usuarios reales.
4. **Intrusivo** (`allow_intrusive: true`: fuzzing, fuerza bruta, DoS, RCE) y **fuera de banda** (`allow_oob: true`: el objetivo contacta servidores de interactsh) solo si el usuario lo autoriza explícitamente para ese objetivo.

## 3. Resultados

- Triage con la skill **appsec-triage**: reproduce con el `curl` de la evidencia antes de confirmar.
- Cruza con el escaneo estático si existe: un CVE de DAST en un componente que también aparece en SCA sube de prioridad.
- `report_generate` para entregar. No compartas cookies ni tokens en la respuesta.

## Qué no es esto

Nuclei detecta problemas conocidos por plantillas; no sustituye una prueba de penetración manual de lógica de negocio (control de acceso, IDOR, flujos de pago). Dilo en el informe cuando aplique.
