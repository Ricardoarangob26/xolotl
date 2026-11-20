---
name: appsec-engagement
description: Definir y consultar el plan de compromiso (reglas de enfrentamiento) de la vía roja de Xolotl con el tool engagement. Úsala cuando vayan a validar ofensivamente infraestructura PROPIA y haya que fijar antes la autorización, el alcance, las ventanas y las reglas; cuando pidan "reglas de enfrentamiento", "ROE", "autorización para pentest", "plan de compromiso" o un documento firmable de alcance; o para comprobar si la autorización está vigente antes de actuar. Materializa el candado de la vía roja. No ejecuta nada. Nivel de acceso: gobernanza (transversal a la vía roja).
model: haiku
---

<!-- model: asesoría ligera (rellena y consulta una plantilla de gobernanza; no razona sobre
     código). Un modelo barato o local basta. Ver "Modelo por skill" en docs/catalogo/README.md. -->

# Plan de compromiso (reglas de enfrentamiento)

El tool `engagement` es el **candado de la vía roja** hecho dato: antes de cualquier prueba
ofensiva sobre infraestructura **propia**, registra quién autoriza, con qué referencia, hasta
cuándo, en qué ventanas y bajo qué reglas. No ejecuta nada; es el documento de gobernanza que toda
capacidad roja debe respetar. El alcance concreto vive en `dast_scope`; aquí va el marco.

## Cuándo usarla

- "Vamos a validar el hardening de nuestros servidores" → primero `engagement action=set`.
- "¿Puedo ya correr la prueba?" → `engagement action=status` (comprueba vigencia y datos).
- "Necesito el documento de alcance para firmarlo" → `engagement action=export`.
- "¿Qué quedó registrado?" → `engagement action=show`.

## Las acciones

| action | Qué hace |
|---|---|
| `set` | Crea o actualiza el plan (merge de campos). El primer registro necesita al menos `name`. |
| `status` | Evalúa si la autorización está **vigente**: plan presente, con `authorized_by` y `authorization_ref`, y dentro de la vigencia (`authorized_from`/`authorized_until`). |
| `show` | Resumen del plan registrado. |
| `export` | Escribe el documento de **reglas de enfrentamiento** en Markdown (plantilla firmable) con autorización + alcance (de `dast_scope`) + exclusiones + ventanas + las reglas duras. |
| `clear` | Borra el plan. |

Campos de `set`: `name`, `org`, `authorized_by`, `authorization_ref`, `authorized_from`,
`authorized_until` (ambas `YYYY-MM-DD`), `windows[]`, `exclusions[]`, `rules[]`,
`emergency_contact`, `default_tier` (`advisory`/`execute`).

## El candado (reglas duras, no negociables)

Siempre aparecen en el documento, no se editan:

1. **Solo activos propios** dentro del alcance registrado en `dast_scope`; se valida antes de cada acción.
2. **Tier 1 (advisory) por defecto**; Tier 2 pide aprobación por comando y registra quién aprobó.
3. **Nada destructivo**; nada en producción fuera de la ventana acordada.
4. **Credenciales y datos de prueba sintéticos**, nunca datos reales de clientes.
5. **Nada contra terceros.** Fuera incluso de la vía roja: phishing e ingeniería social, C2 real,
   exfiltración de datos reales, persistencia duradera y anonimato del operador.

Las `rules` que añadas se suman a estas; nunca las reemplazan.

## El flujo correcto de la vía roja

1. El activo ya pasó por la vía azul (escaneado, documentado, endurecido).
2. `dast_scope action=add` registra el objetivo con quién autoriza y la evidencia.
3. `engagement action=set` fija el marco (autorización, vigencia, ventanas, exclusiones).
4. `engagement action=status` confirma **VIGENTE** antes de actuar.
5. `engagement action=export` para firmar el ROE si procede.
6. Recién entonces se corre la capacidad roja, en Tier 1 por defecto.

## Relación con el resto

- **`dast_scope`** guarda el alcance objeto por objeto; `engagement` guarda el marco. El documento
  exportado une los dos.
- **`handoff`** incluye el plan: al traspasar el compromiso a otra máquina viaja la autorización.
- El plan **no autoriza por sí solo**: refleja la autorización que ya existe fuera de la herramienta.

## Límites

- `status` comprueba la **vigencia por fecha**, no la ventana horaria fina (esa es texto para que
  la juzgue la persona).
- No hay capacidades rojas todavía (Fase 5 del ROADMAP): este plan es el requisito previo que las
  habilitará, blindadas desde el principio.
