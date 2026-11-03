---
name: appsec-fix
description: Corregir vulnerabilidades encontradas por el MCP Xolotl y verificar el arreglo re-escaneando y comparando corridas; también revisión de seguridad de parches. Úsala cuando pidan arreglar, remediar o parchear un hallazgo de seguridad, actualizar dependencias vulnerables, responder a un secreto filtrado o revisar si un cambio corrige una vulnerabilidad.
---

# Remediación verificada

Un arreglo no está terminado hasta que el escáner que lo encontró deja de reportarlo y no aparecen hallazgos nuevos.

## Flujo

1. Anota la corrida base (`runs_list`) y el ID del hallazgo.
2. `finding_get` → entiende la causa raíz, no solo la línea marcada. Busca otras ocurrencias del mismo patrón en el repo.
3. Aplica el cambio mínimo que elimina la causa (tabla abajo). Respeta el estilo del proyecto y sus flujos de ramas.
4. Re-escanea con la misma herramienta y alcance (p. ej. `scan_static` con `tools: ["semgrep"]` y los mismos `semgrep_configs`).
5. `runs_diff` con `base_run_id` = corrida base: el hallazgo debe salir en **Resueltos** y **Nuevos** debe estar vacío o revisado.
6. `finding_triage` con `status: "fixed"` y nota del cambio (commit o archivo). Si reaparece en el futuro, el servidor lo reabre solo.
7. Corre los tests del proyecto: un arreglo que rompe la app no es un arreglo.

## Arreglos de referencia

| Problema | Arreglo correcto | Evitar |
|---|---|---|
| Inyección SQL | Consultas parametrizadas / ORM con parámetros | Escapar a mano, listas negras |
| Inyección de comandos | API sin shell con argumentos en arreglo (`execFile`, `subprocess.run([...])`), lista blanca de valores | `shell=True`, concatenar strings |
| XSS | Escape por contexto del framework, evitar `dangerouslySetInnerHTML`/`innerHTML`; si hace falta HTML, sanitizador (DOMPurify) | Regex sobre HTML |
| `eval` / deserialización | Parser seguro (`JSON.parse`, `yaml.safe_load`), nunca `pickle`/`eval` sobre datos externos | Envolver en try/catch |
| SSRF | Lista blanca de destinos, bloquear IP internas y metadata cloud tras resolver DNS | Validar solo el string de la URL |
| Path traversal | Normalizar y comprobar que la ruta queda dentro de la base | Quitar `../` con replace |
| Criptografía débil | bcrypt/argon2 para contraseñas, SHA-256+ para integridad, AES-GCM | MD5/SHA1 para seguridad |
| Dependencia con CVE | Subir a `fixedVersion` (o la mínima mayor); si es transitiva, actualizar la directa o `overrides`/`resolutions` | Ignorar sin analizar uso |
| Contenedor | Usuario no root, imagen con versión fija y mínima (distroless/alpine/slim), multi-stage | `latest`, secretos en `ENV` |

## Secretos filtrados (orden importa)

1. **Revocar/rotar primero** en el proveedor (GitHub, AWS, base de datos…). Borrar del código no basta: el historial y los clones lo conservan.
2. Mover el valor a variable de entorno o gestor de secretos; agregar el archivo a `.gitignore` si aplica.
3. Revisar logs del proveedor por uso indebido durante el tiempo expuesto.
4. Reescribir el historial (`git filter-repo`) solo si el usuario lo decide: es destructivo y afecta a todo el equipo.

## Revisión de un parche ajeno

Usa el prompt `review_patch` del MCP o este flujo: `runs_diff` entre antes y después + leer el diff de git. Verifica que el arreglo cubra todas las rutas de entrada, que no solo evada el patrón de la regla, y que no introduzca hallazgos nuevos. Veredicto explícito: aprobar o cambios requeridos.
