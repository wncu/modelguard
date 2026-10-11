# Modelo de amenazas

## Activos y adversarios

Proteger disco/credenciales del visitante, integridad del informe y afirmaciones públicas del proyecto. Un atacante puede controlar nombres, archivos, código, pesos, README, configuración, respuestas del modelo y un informe importado. No puede autorizar acciones por medio del contenido de esos archivos.

| Entrada | Amenaza | Control actual | Pendiente |
|---|---|---|---|
| Nombres/extensiones | Manipulación visual, formatos disfrazados | Renderizado textContent; identificación por firma de contenido (MG010) también dentro de zips | Normalización Unicode para revisión |
| JSON importado | XSS, memoria, informe falso | Límite 2 MiB y renderizado como texto | Validación completa con schema y firma opcional |
| Repo Hub | Código remoto o pesos maliciosos | Consulta solo metadatos, dominio fijo, sin token, redirecciones solo a huggingface.co, validación de tipos de la respuesta | Firmas de autor |
| Disco local | Symlinks, carreras, archivos cambiantes | Enlaces omitidos salvo dentro de la caché de HF o con `--follow-symlinks`; FIFOs y dispositivos nunca se abren; `.git` omitido; lectura sin ejecución | Apertura no-follow, snapshot inmutable |
| Parsers (pickle, zip, npy, safetensors, GGUF, JSON, AST) | Deserialización ejecutable y DoS | Nada se deserializa ni ejecuta; límites de bytes, opcodes, tiempo, pila, memo y miembros; fuzzing y pruebas diferenciales | Procesos aislados con límites del sistema operativo |
| Plantillas de chat | SSTI en Jinja al renderizar (p. ej. CVE-2024-34359) | Se analizan como texto, nunca se renderizan (MG015) | Parser Jinja propio |
| Inferencia futura | Acceso a red/disco, llamadas no autorizadas | No integrada | Aislamiento OS, tools ficticias, cero secretos reales |
| Historial local | Otra persona o XSS en el mismo origen lee datos | Informe pequeño, borrado, sin tokens | Advertencias sobre rutas privadas, política de origen dedicada |

No usar eval/exec, pickle.load, torch.load ni trust_remote_code para inspección. No ejecutar sugerencias del modelo. No pasar un nombre de archivo o salida de modelo a un shell. La CLI lee el disco con los permisos del usuario: no es aislamiento. Un hash no es una firma del autor.

Fuera del alcance actual: host ya comprometido, runtime de inferencia, modelos con backdoors desconocidos, ataques de hardware, archivos mutables durante lectura y rutas padre enlazadas. Documentar estos límites en los resultados, no ocultarlos con un score.
