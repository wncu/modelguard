# Contribuir

Empieza por README y docs/METHODOLOGY.md. Propuestas deben explicar problema, evidencia, límites y coste local. Mantén web estática y ejecución local; no añadir backend obligatorio ni tokens del mantenedor.

Para una regla nueva: identificador estable, alcance, ejemplos benignos/sospechosos, tests y explicación de falsos positivos. No descargar modelos grandes en pruebas. No ejecutar artefactos de terceros. Para detectores conductuales: corpus versionado, controles, pruebas reservadas y métricas antes de claims públicos.

Corre `python scripts/check.py`. Presenta cambios acotados y explica qué está implementado vs pendiente. Reporta vulnerabilidades del scanner según SECURITY.md; no publiques secretos ni acusaciones sin evidencia.
