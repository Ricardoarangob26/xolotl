---
name: appsec-plan
description: Armar el plan de evaluación de un sistema o de todo el ecosistema con el MCP Xolotl, usando los tools eval_plan e inventory view=next. Úsala cuando pidan "qué pruebas le puedo hacer a esto", "por dónde empiezo", "un plan de auditoría", "qué me falta evaluar", o cuando haya que ordenar y encadenar los escaneos por activo respetando el nivel de acceso y los niveles de ejecución (Tier 1/Tier 2). Decide el orden; no ejecuta. Nivel de acceso: transversal (lee el inventario y recomienda).
model: haiku
---

<!-- model: asesoría ligera (orquesta y ordena los pasos que ya calcula el motor; no razona sobre
     código). Un modelo barato o local basta. Ver "Modelo por skill" en docs/catalogo/README.md. -->

# Plan de evaluación por activo

Dos tools responden "¿qué tanto le puedo evaluar a cada sistema y en qué orden?", sin tocar nada:

- **`inventory view=next`** — por activo, la **matriz de cobertura**: qué pruebas aplican a su
  tipo, cuáles ya corrieron (✅/⬜) y el siguiente paso de cada hueco. Es el diagnóstico.
- **`eval_plan`** — el **guion ordenado**: encadena los huecos de todos los activos (o de uno)
  en fases, con el Tier por defecto y el acceso que pide cada paso. Es el plan a seguir.

Ninguna escanea. Leen la memoria del `inventory`, así que un activo solo aparece si ya tuvo al
menos una corrida. Para descubrir uno nuevo, primero córrele algo (red, código o host) y el
inventario lo recoge solo.

## Cuándo usar cada una

- "¿Qué le falta a *este* activo?" → `inventory view=next` (o `eval_plan asset=<fragmento>`).
- "Dame el plan de auditoría de todo" → `eval_plan`.
- "¿Qué puedo correr ya con lo que tengo?" → `eval_plan access=[...]` (separa *ahora* de *después*).

## Las fases del plan

`eval_plan` ordena los pasos de menos a más acceso e intrusión, el mismo orden de un compromiso:

| Fase | Qué | Tool | Nivel de acceso |
|---|---|---|---|
| 1 · Superficie expuesta | Puertos, servicios, TLS sin credenciales | `scan_network` | 🌑 red |
| 2 · Código / artefactos | SAST, SCA, secretos, IaC, imágenes | `scan_static`, `scan_codeql`, `scan_iac`, `scan_container_image` | 📄 código / imagen |
| 3 · Configuración interna | Paquetes y endurecimiento del host | `scan_host` | 🌓 SSH / recolector |
| 4 · Aplicación autorizada | DAST contra la app en ejecución | `scan_dast` | alcance en `dast_scope` |

Cada paso trae su **nivel** (código/app/máquina), su **Tier** por defecto y el **acceso** que
necesita. La criticidad del activo (`asset_criticality`) sube los activos importantes dentro de
cada fase.

## El acceso que declaras

`eval_plan access=["red","codigo","imagen","ssh","alcance"]` filtra el plan en dos bloques:

- **Ahora** — lo que puedes correr con el acceso que marcaste.
- **Cuando tengas acceso** — lo que espera una credencial, una llave o el alcance autorizado.

Así el plan es realista: no te manda a correr `scan_host` si todavía no tienes la llave SSH.

## Respeta los niveles de ejecución

El plan **recomienda**, no ejecuta. Al correr cada paso decides el modo (ver *Niveles de
ejecución* en [el catálogo](../../docs/catalogo/README.md)):

- **Tier 1 (advisory)** — Xolotl entrega el comando/recolector y tú lo corres (flujo MobaXterm).
- **Tier 2 (execute)** — Xolotl valida el objetivo contra `dast_scope` y ejecuta, con tu aprobación.

`scan_dast` y `scan_host` por SSH **exigen** que el objetivo esté en `dast_scope`. El plan te lo
recuerda en el acceso de cada paso; regístralo con `dast_scope action=add` antes de ejecutar.

## El bucle

1. Escanea lo que puedas de un sistema nuevo (empieza por la Fase 1, sin acceso).
2. `eval_plan` te dice qué sigue y qué acceso conseguir.
3. Documenta y arregla (skills *appsec-triage*, *appsec-fix*).
4. Reescanea: el hueco se cierra en la matriz y el plan avanza solo a la siguiente fase.

La validación ofensiva (Fase 5 del ROADMAP) es el cierre, no el comienzo: solo sobre activos ya
escaneados, documentados y endurecidos.

## Límites

- Solo planifica lo inventariado. Un activo que nunca escaneaste no está en el plan.
- No inventa pruebas fuera del catálogo de Xolotl; es un orquestador de sus propias tools.
- La inferencia de tipo de activo (host/web/código/imagen) y de puertos sale del inventario; si
  un servicio no se escaneó por red, el plan no sabe que su puerto está abierto.
