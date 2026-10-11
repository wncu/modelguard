# Desarrollo y decisiones

## Estructura

- `web/`: archivos estáticos sin build ni dependencia npm.
- `modelguard/`: CLI Python sin dependencias de runtime.
- `tests/`: fixtures sintéticos que no ejecutan código externo.
- `docs/`: diseño y metodología; distinguir capacidades propuestas de implementadas.
- `schemas/`: contrato portable de informe.
- `scripts/`: verificación y preview locales.

## ADR 001: sin backend propio

La inspección corre en el cliente o su CLI. La página puede alojarse de forma estática. Ningún usuario puede cargar pesos a infraestructura del mantenedor. No introducir proxies, cuotas GPU centrales, tokens compartidos ni cuentas como requisito básico.

## ADR 002: sin detector universal

Un resultado negativo depende de cobertura. El MVP conserva `insufficient_evidence` y señales de revisión. No convertir extensiones sospechosas en acusaciones de malware ni llamar seguro a safetensors/GGUF por el formato.

## ADR 003: almacenamiento de informes, no pesos

localStorage para último informe pequeño; exportación JSON para portabilidad. Pesos permanecen en su ubicación elegida por el usuario. No usar localStorage como repositorio de modelos ni duplicar artefactos gigantes.

## Antes de integrar un motor

Documentar inputs, aislamiento, presupuesto máximo, cobertura, falsos positivos, licencias, versiones y corpus de validación. Agregar pruebas de error y amenazas reales de ese motor. Un adaptador de inferencia nunca despacha llamadas de herramienta a shell/red/disco reales.

## Verificación

`python scripts/check.py` ejecuta tests Python y verifica sintaxis JS si Node está disponible. `python scripts/serve.py` abre solo un servidor local en loopback, sin CORS adicional ni upload endpoint. Sin CI con modelos descargados o GPU.

Revisar frontend en escritorio/móvil: teclado, mensajes de error, input inválido, importación excesiva, localStorage inaccesible, borrado/exportación y CORS del Hub. La verificación inicial cubre tests CLI y sintaxis JS; no afirmar QA visual o integración Hub en vivo hasta hacerlas.
