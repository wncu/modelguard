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
| findings | array | Regla, severidad (`review` o `high`), archivo, mensaje |
| coverage | object de booleanos | Inventario, chequeos estáticos de formato, contenido integral, comportamiento y pesos |
| summary | object, opcional | Archivos, bytes, conteo de hallazgos por severidad y segundos de análisis |
| limitations | array de strings | Omisiones y límites particulares |

`sha256` es calculado localmente. `symlink_target` indica que el archivo se leyó a través de un enlace (caché de Hugging Face o `--follow-symlinks`); `same_as` marca bytes idénticos (mismo inodo) ya inspeccionados bajo otro nombre. `declared_lfs_sha256` se obtuvo de metadatos y NO se verificó sobre bytes. Tamaño null significa desconocido. La presencia de `revision` no demuestra que un directorio local corresponda al commit; eso requiere mapear y verificar artefactos.

## Reglas

| Regla | Severidad | Significado |
|---|---|---|
| MG001 | review | Extensión de serialización potencialmente ejecutable (pickle, PyTorch, joblib, npy/npz, Keras/HDF5) |
| MG002 | review | Código o binario nativo presente; nunca se ejecuta |
| MG003 | review | Symlink no seguido (o roto/en bucle) |
| MG004 | review | `auto_map` o `custom_pipelines` en archivos de configuración: código remoto con `trust_remote_code` |
| MG005 | review | Configuración inválida o mayor de 2 MiB |
| MG006 | high / review | Global importado por un pickle. `high`: módulo peligroso (`os`, `subprocess`, `builtins.eval`, red, `torch.hub`…), atributo dunder o operandos no resolubles. `review`: fuera de la lista permitida, agrupado por paquete |
| MG007 | review | Pickle malformado, límite de análisis alcanzado, miembro de zip no inspeccionable o archivo ilegible |
| MG008 | review | Estructura safetensors inconsistente (cabecera, claves duplicadas, tamaños, huecos, solapes) |
| MG009 | review | Estructura GGUF inconsistente (tamaños por tipo de cuantización, solapes, datos tras los tensores) |
| MG010 | high / review | La extensión no coincide con la firma del contenido (`high` si el contenido es pickle o zip) |
| MG011 | high | SHA-256 o tamaño distinto del declarado (Hub en `verify`, o nombre del blob en la caché de HF) |
| MG012 | review | Archivo presente solo localmente o solo en el Hub (`verify`) |
| MG013 | high / review | El código Python usa ejecución de procesos, red, `eval`/`exec`, cargas codificadas…; `high` para `exec(decode(...))` o proceso + red |
| MG014 | review | Archivo TorchScript con código serializado |
| MG015 | high / review | Plantilla de chat con patrones de inyección Jinja (dunders, guiones bajos escapados, globals usados como gadget) |
| MG016 | review | Formato de archivo comprimido no inspeccionado (7z, tar, gz…) |

`coverage.static_formats` indica que se corrieron los chequeos estáticos; `coverage.content` sigue en false porque no hay inspección integral. La web usa `extension-review` y tiene menor alcance. No mezclar sus resultados como si fueran scans idénticos.

Un archivo ilegible se reporta como MG007 y el escaneo continúa; solo un objetivo inexistente, un fallo del Hub o de escritura del informe aborta con exit 2. `status` expresa la conclusión sobre seguridad, no completitud operativa.

Para futuras pruebas conductuales, añadir artefactos identificados por hash: corpus, plantilla, parámetros, seeds, runtime, modelo base, transcripciones y evaluador. Evitar secretos y datos personales; no incluir razonamientos privados de proveedores. Mantener compatibilidad mediante nueva versión cuando cambie la semántica.
