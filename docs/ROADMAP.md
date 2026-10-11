# Roadmap con criterios de aceptación

1. **MVP disponible**: CLI local/metadatos, web estática, exportación y reglas visibles. Ningún claim de detección conductual.
2. **Contenido estático**: parsers aislados y con límites para GGUF y safetensors; pickle con herramientas de análisis sin unpickle; AST Python; revisión de dependencias. Confirmar firmas, no solo extensiones. Corpus y falsos positivos publicados por regla.
3. **Integridad/procedencia**: comparación con referencias independientes, commit exacto, artefactos derivados y historial. Estado incompleto si no se puede recuperar evidencia.
4. **Harness local experimental**: runtime ya instalado por el usuario, red aislada, herramientas simuladas, corpus versionado, confirmación reservada, exportación reproducible. Ningún dispatcher real de herramientas.
5. **Investigación de backdoors**: comparar técnicas con modelos controlados y bases; calibrar probes por arquitectura. No lanzar un score universal de seguridad.
6. **Reportes compartibles**: publicar únicamente por acción explícita del usuario; firmas y verificación antes de badges. No registro central obligatorio.

No CI que descargue modelos grandes. No GPU patrocinada por el mantenedor. No ejecución automática de contenido del Hub. Proyecto aún no publicado como paquete ni desplegado.
