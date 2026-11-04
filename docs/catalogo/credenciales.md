# 🌕 Credenciales privilegiadas

Lo que se ve con **root/sudo**, **admin de Windows**, acceso al **disco** o al **plano de
control**. Es la visión completa del sistema: endurecimiento, superficie oculta y CVE con
certeza de parche.

> **Skill:** `appsec-hosts` (SSH con llave o recolector con `sudo`).

---

## servidor-linux-completo
- **Nivel de acceso:** credenciales (sudo)
- **Ejecución:** Tier 1 (advisory, recolector con `sudo`) o Tier 2 (SSH con llave en el alcance)
- **Tool MCP:** `scan_host` · `host_collector`
- **Motores:** recolector con `sudo` + Trivy + reglas de endurecimiento propias
- **Estado:** ✅
- **Qué encuentra:** todo lo del nivel lectura **más** endurecimiento completo — SSH (`XOL-SSH-*`), cuentas y sudo (`XOL-ACC-*`), firewall y red (`XOL-NET-*`), SELinux/AppArmor (`XOL-MAC-*`), kernel (`XOL-KRN-*`), servicios (`XOL-SVC-*`), SUID, logging, sistema de archivos, reinicio pendiente por parche.
- **Qué NO ve a este nivel:** nada del propio host; es la visión máxima. Sigue sin cubrir lógica de aplicación.

---

## 🧭 En la hoja de ruta a este nivel

| Capacidad | Motor | Nota |
|---|---|---|
| Discos de VM sin encender | `trivy vm` | VMDK, AMI, snapshots EBS — análisis offline con acceso al disco |
| Windows Server | WinRM + HardeningKitty | Inventario y endurecimiento con cuenta de administrador |
| STIG formal | OpenSCAP con perfil STIG | Cumplimiento con privilegios |
