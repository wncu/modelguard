# Validación y mediciones

Resultados de la versión 0.2.0 (2026-10-11, Python 3.14, Intel i5-9500 sin extensiones SHA). Ninguno de estos resultados certifica seguridad: miden si las reglas encuentran lo que deben y cuánto cuestan.

## Detección

| Prueba | Resultado |
|---|---|
| Corpus de pruebas de [picklescan](https://github.com/mmaitre314/picklescan/tree/main/tests/data) (46 archivos) | Los 37 maliciosos inspeccionables salen `high` (`os.system`, `eval`, `runpy`, `bdb`, `pip.main`, `torch._inductor`, `pydoc.pipepager`, `venv.create`, red, override de `sys.modules`, zip con flag de cifrado falso, pickle bajo `data.txt`, bypass de magic de PyTorch). Benignos: ningún `high`. El `.7z` se marca MG016 (no inspeccionable). |
| Diferencial contra `pickle.Unpickler.find_class` | 9 000 pickles aleatorios (protocolos 0-5, memo compartido, strings largos): el conjunto de globals encontrados coincide exactamente con los que resuelve el unpickler real. |
| Evasiones del analizador anterior | `POP`/`DUP` entre operandos de `STACK_GLOBAL`, operandos memorizados, operandos no-string, payload clásico de protocolo 0 que empieza con `cos\nsystem`, payload en el segundo pickle encadenado, nombres con puntos y dunders (`X.__init__.__globals__`), prefijos (`numpy.testing._private.utils.runstring`): todos cubiertos por tests. |
| Plantillas de chat | Payloads SSTI conocidos (`__class__.__mro__`, `cycler.__init__.__globals__.os`, `attr('\x5f\x5f…')`, `lipsum.__globals__`, `_TemplateReference__context`) salen `high`; la plantilla real de Qwen2.5 sale limpia. |

## Formatos reales

| Modelo | Resultado |
|---|---|
| GGUF: 19 archivos reales en 18 formatos (F32, BF16, Q4_0, Q4_1, Q2_K, Q3_K_L, Q4_K_M, Q5_K_M, Q8_K_XL, IQ1_S, IQ1_M, IQ2_XXS, IQ2_M, IQ3_XXS, IQ3_XS, IQ3_M, IQ4_NL, IQ4_XS, MXFP4 de gpt-oss-20b) | El tamaño calculado de cada tensor cubre el archivo byte a byte: sin huecos, solapes ni datos sobrantes. 3 archivos completos; 16 validados descargando solo la cabecera por HTTP Range sobre un archivo disperso del tamaño real. |
| safetensors (tiny-random-gpt2), PyTorch legacy (tiny-gpt2), PyTorch zip (tiny-random-gpt2, YOLOv8n) | Sin falsos `high`. YOLOv8n: un único `review` agrupado (8 clases de `ultralytics`). |
| Caché real de Hugging Face (8 datasets, 1 390 archivos, almacenamiento xet) | Enlaces seguidos dentro de la caché, cada blob verificado contra su nombre SHA-256, sin MG003 ni MG011 falsos. |
| `verify` contra el Hub | Coincidencia en archivos íntegros; un byte añadido produce MG011 (`verify`) y MG008 (estructura). |

## Paridad CLI ↔ web

El motor del navegador (`web/engine.mjs`) se ejecuta en Node contra el motor Python y se comparan los hallazgos uno a uno (regla, severidad, archivo y mensaje; en MG007 sobre archivos corruptos solo regla, severidad y archivo):

- Corpus adversarial sintético (evasiones de pickle, zips con nombres falsos, flag de cifrado, ZIP64 al estilo PyTorch, npz, safetensors y GGUF corruptos, plantillas maliciosas) y SHA-256: idénticos.
- Modelos reales (corpus de picklescan, tiny-gpt2, tiny-random-gpt2, YOLOv8n, stories GGUF, Qwen2.5 GGUF de 372 MB con hash): idénticos.
- 22 500 archivos mutados: 1 diferencia, un MG007 adicional en JS sobre un deflate corrupto (la librería del navegador reporta errores que zlib tolera).

La paridad encontró bugs en ambos lados: nombres de tensor GGUF vacíos mal reportados y un `UnicodeDecodeError` que abortaba todo el escaneo en Python; en JS, zips con datos antepuestos, registros ZIP64 de PyTorch, nombres CP437/NUL, cabeceras con UTF-8 inválido y salida parcial de deflate.

La web también se probó en Chromium real (controlado por DevTools Protocol, con archivos reales en el selector): detección, comparación con el Hub (coincidencia y copia manipulada → MG011), sin errores de consola, y diseño en 1100 px y 390 px. SHA-256 en el navegador: nativo hasta 64 MB; por encima, incremental en JS a ~110 MB/s sin cargar el archivo entero.

## MCP

Probado con Claude Code como cliente real (`claude -p --mcp-config`): la herramienta `modelguard_scan` detectó `subprocess.run` en un pickle malicioso y nada `high` en YOLOv8n.

## Robustez

Fuzzing con mutaciones (bits, truncado, cabeceras aleatorias, inserciones) sobre pickles y sobre los modelos reales con extensiones al azar: 70 000 pickles mutados y 7 000 archivos mutados sin excepciones no controladas ni análisis de más de 2 s.

## Recursos

`python scripts/bench.py` (sin red) mide cada caso en un proceso nuevo. Python más los imports de ModelGuard ocupan 18 MB.

| Caso | Tiempo | Memoria pico |
|---|---|---|
| Pickle con un payload de 256 MB | < 1 ms (se salta por offset) | 25 MB |
| Pickle de 2 M enteros | 0.5 s | 34 MB |
| Pickle con 300 k strings únicos | 0.36 s | 33 MB |
| Zip de PyTorch con 2 000 storages | 15 ms | 26 MB |
| GGUF de 1 GiB con vocabulario de 300 k tokens | 44 ms | 29 MB |
| GGUF real de 372 MB con `--hash` | 1.0 s (límite de SHA-256 de la CPU: ~505 MB/s) | 32 MB |
| GGUF disperso de 12 GB (gpt-oss-20b) sin hash | 0.18 s | 38 MB |

Respecto a 0.1: el análisis de pickle es de 4 a 6.6 veces más rápido, un pickle con 200 k strings bajó de 122 MB a 42 MB, y el arranque del CLI bajó de 54 ms a 29 ms.
