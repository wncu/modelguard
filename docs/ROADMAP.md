# Roadmap con criterios de aceptación

1. **MVP disponible**: CLI local/metadatos, web estática, exportación y reglas visibles. Ningún claim de detección conductual.
2. **Contenido estático** (en gran parte hecho en 0.2): parsers con límites para GGUF y safetensors; pickle sin unpickle; AST Python; plantillas de chat; firmas en vez de extensiones; corpus publicado en [VALIDATION.md](VALIDATION.md). Pendiente: Keras/HDF5 (capas Lambda), ONNX, revisión de dependencias y tasas de falsos positivos por regla sobre un corpus grande de modelos populares.
3. **Integridad/procedencia** (iniciado: `verify` y blobs de la caché de HF): comparación con referencias independientes, commit exacto, artefactos derivados y historial. Estado incompleto si no se puede recuperar evidencia.
4. **Harness local experimental**: runtime ya instalado por el usuario, red aislada, herramientas simuladas, corpus versionado, confirmación reservada, exportación reproducible. Ningún dispatcher real de herramientas.
5. **Investigación de backdoors**: comparar técnicas con modelos controlados y bases; calibrar probes por arquitectura. No lanzar un score universal de seguridad.
6. **Reportes compartibles**: publicar únicamente por acción explícita del usuario; firmas y verificación antes de badges. No registro central obligatorio.

No CI que descargue modelos grandes. No GPU patrocinada por el mantenedor. No ejecución automática de contenido del Hub. Proyecto aún no publicado como paquete ni desplegado.
