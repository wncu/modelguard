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
- **Memoria plana.** Los archivos se abren con `mmap` de solo lectura y los parsers saltan por offset los datos grandes (bytes de tensores, strings largos) sin tocarlos, así que el tamaño del modelo no influye. El analizador de pickle guarda los strings del memo como referencias empaquetadas en un `array` (8 bytes por entrada) y solo decodifica los que usa un `STACK_GLOBAL`. Miembros comprimidos de zip: máximo 64 MB descomprimidos. Cabecera safetensors: máximo 16 MB. Hash: un búfer de 1 MiB. Pico medido en el peor caso sintético: 34 MB, de los cuales 18 son Python.
- **CPU mínima.** El proceso se pone en `nice 19`, y en Linux eso también deja la E/S en la prioridad más baja. El análisis de pickle tiene tope de 10 s y 5 M opcodes por archivo; un archivo que supera un límite se reporta como incompleto (MG007) en lugar de agotar recursos. El hash es secuencial por defecto; `--jobs N` lo paraleliza.
- **E/S discreta.** Solo `--hash` lee archivos completos, y descarta la caché de páginas cada 64 MB para no desplazar otros datos. Los archivos con el mismo inodo (enlaces de la caché de HF, hardlinks) se leen una vez.
- **Arranque rápido.** `urllib` solo se importa para `hub` y `verify`: el CLI arranca en ~30 ms.

Cifras detalladas en [VALIDATION.md](VALIDATION.md).
