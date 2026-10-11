# Informe JSON v1

El formato portable vincula resultados con alcance y evidencia. La validación de estructura no autentica el origen ni demuestra que se ejecutaron las pruebas.

| Campo | Tipo | Interpretación |
|---|---|---|
| schema_version | string, `1.0` | Versión del contrato |
| scanner_version | string | Implementación que declara haber generado el informe |
| created_at | string ISO 8601 | Fecha declarada, no sellada por tercero |
| target | string | Repo o ruta local; revisar antes de compartir |
| revision | string SHA Git de 40 caracteres, opcional | Commit exacto del Hub; no usar branch mutable como identidad final |
| status | enum | En el MVP siempre `insufficient_evidence` |
| files | array | Ruta, tamaño opcional/desconocido, hash calculado o declarado distinguibles |
| findings | array | Regla, severidad, archivo, mensaje y futura evidencia |
| coverage | object de booleanos | Inventario, contenido integral, comportamiento y pesos |
| limitations | array de strings | Omisiones y límites particulares |

`sha256` es calculado localmente. `declared_lfs_sha256` se obtuvo de metadatos y NO se verificó sobre bytes. Tamaño null significa desconocido. La presencia de `revision` no demuestra que un directorio local corresponda al commit; eso requiere mapear y verificar artefactos.

Reglas actuales: MG001 formato posiblemente ejecutable; MG002 código/nativo presente; MG003 enlace omitido; MG004 auto_map presente; MG005 configuración inválida. Todas tienen severidad `review`. La web usa `extension-review` y tiene menor alcance. No mezclar sus resultados como si fueran scans idénticos.

Un fallo de acceso aborta la CLI con exit 2 y no produce un informe completo. Una futura versión deberá representar completitud por fase y errores individuales explícitamente. En 0.1, status expresa la conclusión sobre seguridad, no completitud operativa.

Para futuras pruebas conductuales, añadir artefactos identificados por hash: corpus, plantilla, parámetros, seeds, runtime, modelo base, transcripciones y evaluador. Evitar secretos y datos personales; no incluir razonamientos privados de proveedores. Mantener compatibilidad mediante nueva versión cuando cambie la semántica.
