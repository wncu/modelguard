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
