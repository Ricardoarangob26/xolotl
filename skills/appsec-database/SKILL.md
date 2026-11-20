---
name: appsec-database
description: Auditar la configuración de seguridad de una base de datos con el MCP Xolotl, usando el tool scan_db y una cuenta de SOLO LECTURA. Úsala cuando pidan revisar o endurecer una base de datos, auditar su configuración, cifrado, autenticación, roles/privilegios o exposición de red, o comparar su configuración con buenas prácticas. Sin conexión propia: entrega consultas de solo lectura para correrlas a mano y parsea la salida. Motores: PostgreSQL, MySQL/MariaDB y SQL Server. Nivel de acceso: usuario de lectura.
---

# Auditoría de configuración de bases de datos

`scan_db` revisa cómo está **configurada** una base de datos (no sus datos): cifrado en tránsito,
autenticación, exposición de red, superusuarios y auditoría. No se conecta ni instala nada —fiel al
principio "depende de ti"—: entrega un script SQL de **solo lectura** para que lo corras con una
cuenta de lectura, y parsea la salida a hallazgos de configuración.

## Motores

- **PostgreSQL** — disponible.
- **MySQL / MariaDB** — disponible.
- **SQL Server** — disponible.

## El flujo (Tier 1, tu MobaXterm)

1. `scan_db engine=postgresql` (sin más) devuelve el script `pg-collect.sql` y el comando:
   `psql -X -A -t -h <host> -U <usuario_lectura> -d <base> -f pg-collect.sql > pg-audit.txt`.
   Basta un rol con `pg_read_all_settings` (o el propietario); ninguna consulta cambia datos.
2. Corres el script y traes `pg-audit.txt`.
3. `scan_db engine=postgresql collected_file=<ruta> target=<nombre>` lo parsea a hallazgos.

## Qué comprueba (PostgreSQL)

| Área | Hallazgos |
|---|---|
| Cifrado en tránsito | `ssl=off` (alto); `ssl_min_protocol_version` TLS 1.0/1.1 (medio) |
| Autenticación | pg_hba `trust` (crítico), `password` en claro (alto); hashing MD5 (medio) |
| Exposición de red | `listen_addresses='*'` (medio); reglas pg_hba con origen `0.0.0.0/0` (alto) |
| Privilegios | superusuarios además de `postgres` (medio) |
| Auditoría | sin `log_connections`/`log_disconnections` (bajo); sin pgaudit y `log_statement` limitado (bajo) |

## Qué comprueba (MySQL / MariaDB)

| Área | Hallazgos |
|---|---|
| Cifrado en tránsito | `require_secure_transport=OFF` (alto); `tls_version` con TLS 1.0/1.1 (medio) |
| Autenticación | cuentas sin contraseña (**crítico**), anónimas (alto); plugin por defecto `mysql_native_password` (medio); cuentas con hash débil (bajo) |
| Archivos | `local_infile=ON` (medio); `secure_file_priv` vacío (alto) |
| Exposición de red | cuentas con `Host='%'` (medio) |
| Privilegios | cuentas con `SUPER`/`GRANT` fuera de las de sistema (medio) |
| Auditoría | sin `validate_password` (bajo); `general_log=ON` (bajo) |

En MariaDB, cambia `performance_schema.global_variables` por `information_schema.global_variables`
en el script (lo indica el modo advisory).

## Relación con el resto

- Los hallazgos son de categoría **config**: heredan el mapeo a cumplimiento (CIS/NIST/ISO), la
  prioridad de riesgo, el inventario, la revalidación y los informes como cualquier otro.
- Complementa a `scan_host` (sistema operativo) y `scan_network` (puerto expuesto): juntos cubren
  el host, la red y el motor de base de datos.

## Límites

- Audita **configuración**, no busca inyección SQL en aplicaciones (eso es `scan_static`/`scan_dast`).
- La sección pg_hba necesita un rol con lectura de configuración; sin él, el resto igual se audita.
- No lee ni exporta datos de las tablas; solo parámetros, roles y reglas de acceso.
