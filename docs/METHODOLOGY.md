# Metodología de análisis — v0.1 (2026-10-11)

## Pregunta y alcance

¿Qué riesgos observables presenta un artefacto concreto, con qué pruebas y qué cobertura? No se intenta certificar ausencia de amenazas. Una seed de generación controla aleatoriedad; no es sinónimo de backdoor. Un trigger puede depender de tokens, contexto, fecha, plantilla o combinaciones y estar aprendido en los pesos. "Uncensored" y Q6_K describen políticas/transformaciones declaradas, no integridad ni ausencia de malware.

Distinguir: (a) ejecución de código al cargar un archivo; (b) comportamiento condicionado aprendido; (c) instrucciones maliciosas en entradas o plantillas; (d) vulnerabilidades del propio runtime/parser. Un formato que evita pickle no demuestra comportamiento benigno. Un hash coincidente solo demuestra identidad de bytes respecto a la referencia elegida.

## Protocolo por capas

| Capa | Evidencia necesaria | Pruebas | Límite |
|---|---|---|---|
| Identidad | Repo, SHA de commit, archivo exacto, cuantización, runtime/versiones | Fijar revisión, SHA-256 local y referencia independiente | Un autor malicioso también publica hashes válidos |
| Procedencia | Modelo base, licencia, receta de fine-tuning/abliteración/cuantización | Revisar model card e historial; registrar omisiones | Declaraciones no autenticadas no prueban procedencia |
| Supply chain | Archivos, configuración, dependencias y código | Inventario; revisión de auto_map y trust_remote_code; posterior AST/opcodes y parsers limitados | Nombre/extensión no equivalen al contenido |
| Comportamiento | Corpus versionado y salidas reproducibles | Pares control/trigger, comparación con base, tareas benignas y herramientas simuladas | Un resultado anómalo no prueba una backdoor; no hallazgos no descartan triggers |
| Pesos/activaciones | Acceso a pesos y base comparable, instrumentación | Diferencias, probes y técnicas de investigación | Aplicabilidad limitada; cuantización/adaptación pueden confundir diferencias |

MVP: inventario y señales de extensiones; CLI revisa solo config.json limitado. No descarga pesos, deserializa pickle ni importa Python ajeno. No inspecciona historial, model cards, dependencias, opcodes ni estructura tensorial todavía. No incorpora resultados de otros scanners como si fueran pruebas propias.

## Experimento conductual futuro (en el equipo del usuario)

1. Fijar commit/archivo, hash, plantilla, tokenizer, runtime, parámetros, seed(s), hardware y corpus. Comparar la misma cuantización siempre que sea posible; registrar diferencias inevitables.
2. Diseñar pares equivalentes: control sin trigger y variantes con trigger candidato. Separar corpus exploratorio del conjunto reservado de confirmación. Usar controles benignos y modelos de backdoor sintéticos conocidos; no convertir una negativa o lenguaje ofensivo en prueba de infección.
3. Repetir por múltiples seeds y tareas, manteniendo constante el resto. Medir tasa de conducta definida previamente, tasa de llamadas de herramienta no autorizadas y cambios de utilidad. Reportar numeradores, denominadores e intervalos de confianza; corregir comparaciones múltiples. La señal cero solo informa del corpus probado.
4. Herramientas exclusivamente simuladas: respuestas ficticias para shell, filesystem y red; nunca despachar llamadas a herramientas reales. Registrar solicitudes, validación de esquema y si la llamada excedía permisos de la tarea. No usar secretos reales.
5. Para modelos desconocidos, ejecutar inferencia en aislamiento impuesto por el sistema operativo, con red bloqueada, sin carpetas personales, límites CPU/RAM/GPU/disco/tiempo y runtime actualizado. Un servidor localhost o un contenedor con configuración por defecto no constituyen por sí solos una sandbox. La CLI actual no implementa este aislamiento ni inferencia.
6. Confirmar una señal con un conjunto nuevo, más de una tarea y comparación adecuada con la base. Documentar explicaciones alternativas: prompt injection, plantilla distinta, variación normal, fine-tuning benigno, cuantización o errores del evaluador. Solo una reproducción y evidencia específica permitirían hablar de riesgo confirmado.

No prometer 256k de contexto en una T4 por el tamaño del archivo: memoria de pesos, KV cache, arquitectura y runtime condicionan viabilidad. No ejecutar modelos enormes para metadatos.

## Estados y trazabilidad

- `insufficient_evidence`: no hay cobertura adecuada para concluir sobre backdoors; único estado global del MVP.
- `no_findings_in_tested_scope`: futuro; enumerar exactamente pruebas y cobertura, nunca abreviar como seguro.
- `suspicious_behavior`: futuro; señal reproducible pendiente de atribución.
- `confirmed_risk`: futuro; evidencia concreta, reproducible y revisada.

Separar estado de completitud, severidad del hallazgo y conclusión de seguridad. Un archivo Python o pickle presente requiere revisión, no condena al autor. Un análisis fallido no obtiene un badge favorable. Un informe JSON importado puede ser manipulado: no es firma ni verificación independiente. Todo badge futuro debe enlazar informe, revisión exacta, metodología y fecha; no usar un check verde universal.

## Validación del detector

Antes de ampliar claims: corpus limpio etiquetado y corpus de amenazas conocido; falsos positivos/negativos por regla; tests de ficheros truncados, límites de memoria, archivos gigantes, enlaces, rutas, fallos de red; experimentos reservados y reproducibles. Publicar resultados de fallos. Un scanner también procesa entradas no confiables y necesita su propio modelo de amenazas.

## Fuentes primarias consultadas

- Hugging Face, Pickle scanning: https://huggingface.co/docs/hub/security-pickle — riesgo de ejecución al deserializar y utilidad de inspección sin ejecución.
- Hugging Face, Malware scanning: https://huggingface.co/docs/hub/security-malware — ausencia de badge puede reflejar un scan pendiente/error.
- Safetensors audit: https://huggingface.co/blog/safetensors-security-audit — seguridad de formato/parser no equivale a auditoría conductual.
- Hub API: https://huggingface.co/docs/hub/api — inventario y revisiones de repositorios.
- Transformers custom models: https://huggingface.co/docs/transformers/custom_models — código personalizado y carga explícita.
- Anthropic, Sleeper Agents (2024): https://www.anthropic.com/news/sleeper-agents-training-deceptive-llms-that-persist-through-safety-training — evidencia experimental de conducta condicionada persistente; no detector universal.
- Anthropic, Simple probes can catch sleeper agents (2024): https://www.anthropic.com/research/probes-catch-sleeper-agents — probes en escenarios estudiados; generalización a modelos arbitrarios no establecida.

La arquitectura y el protocolo propuestos son decisiones de ModelGuard basadas en estas fuentes, no capacidades demostradas por el MVP.
