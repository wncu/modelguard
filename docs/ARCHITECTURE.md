# Arquitectura sin backend propio

| Componente | Dónde corre | Qué guarda/contacta |
|---|---|---|
| HTML/CSS/JS estático | Navegador del visitante | Último informe pequeño en localStorage; exportación a disco |
| Consulta Hub | Navegador o CLI del visitante | HTTPS directamente a Hugging Face, metadatos públicos |
| Inspección y hashes | Python en PC del visitante | Archivos de su disco; JSON local |
| Inferencia futura | Runtime elegido por visitante | Pesos y cómputo locales; integración pendiente |

No subir un archivo para analizarlo: el selector entrega referencias locales. El MVP web solo examina nombres/tamaños. No usar localStorage para pesos: almacenamiento pequeño, síncrono y con cuotas variables. Para futuras lecturas grandes: streams y workers, permisos explícitos de acceso a disco; IndexedDB/OPFS solo si hay una necesidad justificada, cuotas comprobadas y limpieza. No duplicar 500 GB por defecto.

No cuentas, base de datos, Redis, Celery, GPU central, API de ModelGuard ni facturación por análisis. El hosting estático puede ser gratuito dentro de los límites del proveedor; no prometer ancho de banda ilimitado. Hugging Face puede imponer límites y CORS. Sin proxy de fallback: la CLI resuelve el caso en el equipo del usuario.

CSP restringe scripts a recursos propios y conexiones a Hugging Face. Renderizar informes con textContent evita interpretar HTML. Límites: 2 MiB de metadatos/importación; 1 MiB de historial; hashing CLI de 1 MiB por bloque. Inventario y JSON crecen con la cantidad de archivos, no con el volumen de pesos. La web no calcula hashes todavía.

La CLI no es una sandbox: no abrir repositorios que se modifican concurrentemente. Omite symlinks encontrados pero no ofrece protección contra carreras de enlaces ni directorios padre enlazados. Un futuro modo endurecido usará apertura sin seguimiento de enlaces y límites de número de archivos. El MVP consulta HTTPS al dominio fijo; urllib sigue redirecciones del servicio sin credenciales.

## Presupuesto de recursos

El CLI está pensado para correr en segundo plano sin molestar el equipo.

- **GPU: nunca.** No carga tensores ni runtimes de inferencia.
- **Memoria plana (~25 MB de pico medido).** Solo lee cabeceras y opcodes. Los pickles se analizan en streaming con límites de lectura (32 MB por argumento, 256 MB por flujo, 512 MB por zip); safetensors lee una cabecera de hasta 16 MB; en GGUF los arrays se saltan con `seek` en vez de leerse. El hash usa un único búfer de 1 MiB.
- **CPU mínima.** El proceso baja su prioridad con `nice 15`, el análisis de pickle tiene tope de 10 s y 5 M opcodes por archivo, y un archivo que supera un límite se reporta como incompleto (MG007) en lugar de agotar recursos.
- **E/S discreta.** Solo se lee el archivo completo con `--hash`; ahí se pide al kernel descartar la caché de páginas para no desplazar otros datos.
- **Medido** (Python 3.13, equipo local): GGUF Qwen2.5-0.5B Q4 (372 MB) con `--hash`: 1.7 s, 23 MB; YOLOv8n `.pt`: 0.08 s; pickle de 3 M enteros: ~6 s (tope de opcodes); mutaciones aleatorias de 5 modelos reales: sin fallos ni cuelgues.
