---
name: appsec-triage
description: Triage y priorización de hallazgos de seguridad del MCP Xolotl — separar lo explotable de los falsos positivos leyendo el código, explicar el riesgo y ordenar qué corregir primero. Úsala después de cualquier escaneo de appsec, o cuando pidan priorizar, explicar o filtrar vulnerabilidades, revisar falsos positivos o decidir qué arreglar primero.
---

# Triage de hallazgos

El objetivo es pasar de "N hallazgos" a "estos K son reales, en este orden, y así se arreglan". Cada decisión queda registrada con `finding_triage` y se recuerda en escaneos futuros (por huella), así que justifica bien.

## Proceso

1. `findings_query` con `min_severity: "high"`; luego `medium`. Agrupa por regla: diez hallazgos de la misma regla suelen tener la misma respuesta.
2. Por cada hallazgo (o grupo), `finding_get` y **lee el código**. Abre el archivo completo si hace falta seguir el flujo.
3. Decide con los criterios de abajo y registra con `finding_triage`:
   - `confirmed` — explotable o muy probable.
   - `false_positive` — la nota dice exactamente por qué (p. ej. "el valor viene de una constante, no de la petición").
   - `accepted_risk` — real pero mitigado o fuera de alcance; la nota dice el control compensatorio y quién lo aceptó.
4. Entrega una tabla priorizada (ver formato al final).

## Criterios por categoría

**SAST (semgrep, bandit, codeql)**
- ¿La fuente la controla un atacante? (parámetros, cuerpo, cabeceras, archivos subidos, datos de terceros). Constantes y configuración del despliegue no cuentan.
- ¿Llega al sumidero sin validación/escape efectivo? Revisa sanitizadores propios: muchos están mal.
- ¿Es código alcanzable en producción? Tests, scripts de desarrollo, ejemplos y código muerto bajan a `accepted_risk` o `false_positive` según el caso.
- `confidence: low` de Semgrep o `precision: low/medium` de CodeQL exige leer con más cuidado, no descartar a ciegas.

**SCA (osv-scanner, trivy)**
- ¿El paquete es de producción o solo de desarrollo/build? Dev-only baja de prioridad pero no desaparece (cadena de suministro en CI).
- ¿El proyecto usa la función o el vector vulnerable? Busca en el código (`Grep`) el uso del API afectado.
- ¿Hay versión corregida (`fixedVersion`)? Si es un salto menor, se corrige ya; si es mayor, estima el esfuerzo.
- Dependencias transitivas: identifica qué dependencia directa la trae.

**Secretos (gitleaks, trivy)**
- Nunca imprimas el valor. Los resultados vienen redactados; no los reconstruyas leyendo el archivo en voz alta.
- Falso positivo solo si es claramente un valor de ejemplo, un hash público o un placeholder. Ante la duda, `confirmed`.
- Un secreto en el historial (`commit` en la ubicación) es real aunque ya no esté en el código: hay que **revocarlo y rotarlo**.

**IaC / contenedores (trivy)**
- Contenedor como root, imagen `latest`, puertos y capacidades de más, secretos en variables de entorno, buckets públicos, cifrado desactivado.
- El contexto importa: un Dockerfile de desarrollo local pesa menos que el de producción.

**DAST (nuclei)**
- Reproduce con el `curl` de la evidencia (solo contra objetivos en alcance) antes de confirmar.
- Hallazgos `info` de tecnología son contexto para priorizar CVE, no vulnerabilidades por sí mismos.

## Riesgo real (para ordenar)

Prioridad = severidad del escáner ajustada por **exposición** (¿internet o red interna?), **explotabilidad** (¿requiere autenticación? ¿hay exploit público / está en CISA KEV?) e **impacto** (datos personales, credenciales, ejecución remota). Sube o baja la severidad del escáner y dilo explícitamente.

## Formato de entrega

| Prioridad | ID | Hallazgo | Riesgo real y por qué | Arreglo | Esfuerzo |
|---|---|---|---|---|---|

Después: resumen de descartados (cuántos y razones comunes) y huecos de cobertura (escáneres que fallaron o no aplicaban).
