# Catálogo de capacidades

Las capacidades de Xolotl ordenadas por **cuánto acceso al objetivo hace falta**. Es el eje
que importa en la práctica: no es lo mismo lo que ves desde fuera que lo que ves con root.

| Nivel | Qué tienes | Qué alcanzas | Archivo |
|---|---|---|---|
| 🌑 **Sin acceso** | Nada. Solo que el objetivo esté en el alcance autorizado. | Puertos, servicios, TLS, CVE conocidos por banner/plantilla. | [sin-acceso.md](sin-acceso.md) |
| 🌓 **Usuario de lectura** | Una cuenta sin privilegios, un rol read-only o la salida de un recolector sin `sudo`. | Inventario de paquetes, configuración visible, postura CIS parcial. | [usuario-lectura.md](usuario-lectura.md) |
| 🌕 **Credenciales privilegiadas** | root/sudo, admin de Windows, acceso al disco o al plano de control. | Endurecimiento completo, SUID, kernel, CVE con parches retroportados. | [credenciales.md](credenciales.md) |
| 📄 **Código fuente** | El repositorio (no acceso al sistema en ejecución). | SAST, dependencias, secretos en el historial, IaC, imágenes. | [codigo-fuente.md](codigo-fuente.md) |

## Niveles de ejecución

Cada capacidad que toca un sistema vivo corre en uno de dos modos, al estilo de un
compromiso de pentest. Se elige con el parámetro `mode` de la herramienta o con la variable
`XOLOTL_MODE` (modo por defecto del servidor); `xolotl_doctor` muestra cuál está activo.

- **Tier 1 · `advisory`** — el servidor **no se conecta** al objetivo: entrega el comando exacto para que lo corras tú (tu flujo de MobaXterm: Ricardo ejecuta y pega la salida) y te dice cómo traer el resultado. Para redes aisladas, cumplimiento, o un host que ya nos bloqueó.
- **Tier 2 · `execute`** — el servidor valida el objetivo contra el alcance autorizado y ejecuta el escaneo. El cliente MCP pide tu aprobación antes de correr la herramienta.

Aplica a `scan_network`, `scan_dast` y `scan_host` (por SSH). El análisis de código fuente
corre siempre en local, así que no distingue niveles.

## Leyenda de estado

`✅ disponible` · `🧭 en la hoja de ruta` — ver [ROADMAP.md](../../ROADMAP.md).

## Plantilla de una capacidad

Cada entrada del catálogo sigue este encabezado para que sea comparable de un vistazo:

```md
## nombre-capacidad
- **Nivel de acceso:** sin acceso | usuario de lectura | credenciales | código fuente
- **Ejecución:** Tier 1 (advisory) | Tier 2 (execution)
- **Tool MCP / skill:** `scan_...`
- **Motores:** herramienta(s) open source
- **Estado:** ✅ | 🧭
- **Qué encuentra:** ...
- **Qué NO ve a este nivel:** ...
```
