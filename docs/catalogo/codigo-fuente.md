# 📄 Código fuente

Un eje aparte: aquí no se accede a un sistema en ejecución, sino al **repositorio**. Es la
caja blanca del código. No necesita credenciales del objetivo, sino el código mismo.

---

## analisis-estatico
- **Nivel de acceso:** código fuente
- **Ejecución:** Tier 2 (execution) — corre en local sobre una carpeta
- **Tool MCP:** `scan_static`
- **Motores:** Semgrep, Bandit (SAST) · OSV-Scanner, Trivy (SCA) · Gitleaks, Trivy (secretos)
- **Estado:** ✅
- **Qué encuentra:** inyecciones, `eval`, deserialización insegura, criptografía débil, path traversal; dependencias con CVE y la versión que las corrige; secretos **en todo el historial de git**; IaC mal configurada. Todo deduplicado por huella.
- **Qué NO ve:** comportamiento en ejecución ni lógica de negocio.

## analisis-de-flujo-profundo
- **Nivel de acceso:** código fuente
- **Ejecución:** Tier 2 (execution)
- **Tool MCP:** `scan_codeql`
- **Motores:** CodeQL, suite `security-extended`
- **Estado:** ✅
- **Qué encuentra:** flujo de datos de fuente a sumidero en JS/TS, Python, Java, C#, Go, Ruby, C/C++, Swift, Rust y GitHub Actions.
- **Qué NO ve:** lo que no esté modelado como fuente/sumidero; sigue sin cubrir control de acceso.

## imagenes-de-contenedor
- **Nivel de acceso:** código fuente / artefacto
- **Ejecución:** Tier 2 (execution)
- **Tool MCP:** `scan_container_image`
- **Motores:** Trivy
- **Estado:** ✅
- **Qué encuentra:** paquetes vulnerables y secretos dentro de una imagen (registro, daemon local o `.tar`).

## infraestructura-como-codigo
- **Nivel de acceso:** código fuente
- **Ejecución:** Tier 2 (execution)
- **Tool MCP:** `scan_iac`
- **Motores:** Trivy config
- **Estado:** ✅
- **Qué encuentra:** Dockerfile, compose, Kubernetes, Helm, Terraform, CloudFormation mal configurados.

---

## Triage y reporte (transversal)

No es un nivel de acceso: es lo que el agente hace con los hallazgos de cualquier nivel.

| Capacidad | Tool / skill | Estado |
|---|---|---|
| Triage con memoria | `finding_triage`, skill `appsec-triage` | ✅ |
| Inventario acumulado (ecosistema) | `inventory` (SQLite local) | ✅ |
| Comparar corridas | `runs_diff` | ✅ |
| Remediación guiada | prompt `fix_finding`, skill `appsec-fix` | ✅ |
| Informe | `report_generate` (MD/HTML/SARIF/JSON) | ✅ |
