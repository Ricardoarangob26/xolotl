---
name: appsec-inventory
description: Explorar sistemas y construir un inventario de seguridad vivo con el MCP Xolotl, usando el tool inventory. Úsala cuando pidan un panorama del ecosistema, saber qué activos y hallazgos hay acumulados, qué cambió entre escaneos (nuevo, persistente o desaparecido), rastrear un hallazgo en el tiempo, o ir mapeando varios sistemas en varias sesiones. La memoria larga de Xolotl, aparte del triage. Nivel de acceso: transversal (lee lo ya escaneado).
---

# Inventario y ecosistema

El tool `inventory` es la **memoria larga** de Xolotl: una base local (SQLite en
`~/.xolotl/xolotl.db`, o JSON de respaldo) que **crece sola con cada corrida**. No escanea
nada; lee lo acumulado. Es la base para explorar varios sistemas a lo largo del tiempo e ir
armando un inventario/ecosistema, en vez de mirar una corrida aislada.

## Cuándo usarla

- "¿Qué tenemos escaneado?", "dame el panorama del ecosistema" → `view: "summary"`.
- "¿Qué activos hay y cuáles tienen más hallazgos?" → `view: "assets"`.
- "¿Qué apareció nuevo desde el último escaneo?" → `view: "findings", seen: "new"`.
- "¿Qué ya no aparece (posiblemente corregido o apagado)?" → `view: "findings", seen: "gone"`.
- "¿Desde cuándo existe este hallazgo y en qué corridas salió?" → `view: "history", fingerprint: <huella>`.

## Las cuatro vistas

| view | Devuelve |
|---|---|
| `summary` | Motor, nº de corridas, activos, hallazgos activos/históricos, por severidad y categoría, última corrida. |
| `assets` | Cada activo (host, URL o ruta) con su conteo de hallazgos por severidad y las categorías que lo tocan. |
| `findings` | Hallazgos acumulados de **todas** las corridas, deduplicados por huella, con filtros. |
| `history` | Un hallazgo (por su huella) a través del tiempo: en qué corridas apareció y con qué estado. |

Filtros de `findings`: `severity`, `category`, `asset` (coincide por fragmento), `status`,
`include_suppressed`, `limit`, y `seen`:

- `latest` — visto en la corrida más reciente.
- `new` — apareció **por primera vez** en la corrida más reciente (exposición nueva o regresión).
- `gone` — ya no apareció en la última corrida (corregido, host apagado o fuera de alcance).
- `all` — todo el histórico (por defecto).

## El bucle de exploración

Para ir mapeando un ecosistema a lo largo de varias sesiones:

1. **Explora** un sistema nuevo con la skill del nivel que corresponda (*appsec-network* sin acceso, *appsec-hosts* con recolector, *appsec-audit* para código).
2. Cada corrida alimenta el inventario sola (al guardarse).
3. **Revisa** con `inventory view=summary` cómo creció el ecosistema y con `assets` qué activos concentran riesgo.
4. **Compara** en el tiempo con `seen=new` (lo que apareció) y `seen=gone` (lo que se fue). Para dos corridas concretas del mismo activo, `runs_diff` es más fino.
5. **Rastrea** un hallazgo tenaz con `view=history` para ver si reaparece pese a haberse marcado corregido (regresión).

## Relación con el triage

El triage (`finding_triage`, skill *appsec-triage*) guarda la **decisión** sobre un hallazgo
(falso positivo, riesgo aceptado, corregido) y se recuerda por huella. El inventario guarda la
**historia observable**: cuándo y en qué corridas se vio, con qué herramienta. Por defecto el
inventario oculta los descartados; usa `include_suppressed: true` para auditarlos.

## Límites

- No escanea: solo refleja lo que ya se corrió. Un activo que nunca escaneaste no está.
- Los datos viven en `~/.xolotl`, en esta máquina. Es local por diseño; no se sincroniza entre equipos.
- `seen=new`/`gone` se miden contra la **última corrida registrada**, sea del activo que sea; para comparar dos corridas específicas usa `runs_diff`.
